use std::any::Any;
use std::fmt::{Debug, Display};
use std::fs::File;
use std::net::SocketAddr;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::thread::available_parallelism;
use std::time::SystemTime;

use bytes::{BufMut, Bytes};
use camino::Utf8Path;
use domain::base::iana::{Class, Rcode};
use domain::base::name::FlattenInto;
use domain::base::{Name, Rtype, Serial};
use domain::net::server::middleware::notify::Notifiable;
use domain::rdata::ZoneRecordData;
use domain::tsig::KeyStore;
use domain::zonefile::inplace::{self, Entry};
use domain::zonetree::error::RecordError;
use domain::zonetree::parsed::Zonefile;
use domain::zonetree::{
    AnswerContent, InMemoryZoneDiff, ReadableZone, StoredName, WritableZone, WritableZoneNode,
    Zone, ZoneBuilder, ZoneStore,
};
use foldhash::HashMap;
use futures::Future;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tracing::{debug, error, info};

use crate::center::{halt_zone, Center, Change};
use crate::common::light_weight_zone::LightWeightZone;
use crate::common::tsig::TsigKeyStore;
use crate::comms::{ApplicationCommand, Terminated};
use crate::payload::Update;
use crate::zone::ZoneLoadSource;
use crate::zonemaintenance::maintainer::{
    Config, ConnectionFactory, DefaultConnFactory, TypedZone, ZoneMaintainer,
};
use crate::zonemaintenance::types::{
    NotifyConfig, TransportStrategy, XfrConfig, XfrStrategy, ZoneConfig, ZoneId, ZoneInfo,
    ZoneReport, ZoneReportDetails,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZoneLoaderReport {
    pub started_at: SystemTime,
    pub finished_at: Option<SystemTime>,
    pub byte_count: usize,
    pub record_count: usize,
}

pub struct ZoneLoader {
    /// The center.
    pub center: Arc<Center>,

    /// The zone maintainer.
    //
    // TODO: Merge 'ZoneMaintainer' into 'ZoneLoader'.
    pub zone_maintainer: Arc<ZoneMaintainer<TsigKeyStore, DefaultConnFactory>>,

    /// A channel to propagate zone update events.
    //
    // TODO: Turn into a simple method on 'self'.
    pub zone_updated_tx: tokio::sync::mpsc::Sender<(StoredName, Serial)>,

    /// The status of zone loading.
    //
    // TODO: Move into 'ZoneState'.
    pub receipt_info: Arc<Mutex<HashMap<StoredName, ZoneLoaderReport>>>,
}

impl ZoneLoader {
    /// Launch the zone loader.
    pub fn launch(center: Arc<Center>) -> Self {
        // TODO: metrics and status reporting
        let receipt_info: Arc<Mutex<HashMap<StoredName, ZoneLoaderReport>>> = Default::default();

        // TODO: Replace this with a method on 'self'.
        let (zone_updated_tx, mut zone_updated_rx) = tokio::sync::mpsc::channel(10);
        tokio::spawn({
            let update_tx = center.update_tx.clone();
            async move {
                while let Some((zone_name, zone_serial)) = zone_updated_rx.recv().await {
                    info!(
                        "[ZL]: Received a new copy of zone '{zone_name}' at serial {zone_serial}",
                    );

                    let _ = update_tx.send(Update::UnsignedZoneUpdatedEvent {
                        zone_name,
                        zone_serial,
                    });
                }
            }
        });

        let maintainer_config =
            Config::<_, DefaultConnFactory>::new(center.old_tsig_key_store.clone());
        let zone_maintainer = Arc::new(
            ZoneMaintainer::new_with_config(center.clone(), maintainer_config)
                .with_zone_tree(center.unsigned_zones.clone()),
        );

        // Load primary zones.
        // Create secondary zones.
        let zones = {
            let state = center.state.lock().unwrap();
            state
                .zones
                .iter()
                .map(|zone| {
                    let state = zone.0.state.lock().unwrap();
                    (zone.0.name.clone(), state.source.clone())
                })
                .collect::<Vec<_>>()
        };

        // TODO: Decide how to really handle this... not use hard-coded max of 3.
        let available_parallelism = available_parallelism().unwrap().get();
        let max_zones_loading_at_once = (available_parallelism - 1).clamp(1, 3);
        info!("[ZL]: Adding at most {max_zones_loading_at_once} zones at once.");
        let max_zones_loading_at_once = Arc::new(Semaphore::new(max_zones_loading_at_once));

        for (name, source) in zones {
            let zone_maintainer_clone = zone_maintainer.clone();
            let max_zones_loading_at_once = max_zones_loading_at_once.clone();
            let zone_updated_tx = zone_updated_tx.clone();
            let receipt_info = receipt_info.clone();
            let center = center.clone();
            tokio::spawn(async move {
                info!("[ZL]: Waiting to add zone '{name}' with source '{source:?}'");
                let _permit = max_zones_loading_at_once.acquire().await.unwrap();

                info!("[ZL]: Adding zone '{name}' with source '{source:?}'");
                let zone = match source {
                    ZoneLoadSource::None => {
                        // Nothing to do.
                        return;
                    }

                    ZoneLoadSource::Zonefile { path } => {
                        match Self::register_primary_zone(
                            center.clone(),
                            name.clone(),
                            &path,
                            &zone_updated_tx,
                            receipt_info.clone(),
                        )
                        .await
                        {
                            Ok((zone, ri)) => {
                                receipt_info.lock().unwrap().insert(name.clone(), ri);
                                zone
                            }

                            Err(Terminated) => {
                                // Self::register_primary_zone() will have
                                // already logged the error so nothing to
                                // do but quit this task.
                                return;
                            }
                        }
                    }

                    ZoneLoadSource::Server { addr, tsig_key: _ } => {
                        Self::register_secondary_zone(name.clone(), addr, zone_updated_tx.clone())
                    }
                };

                if let Err(err) = zone_maintainer_clone.insert_zone(zone).await {
                    error!("[ZL]: Failed to insert zone '{name}': {err}")
                }
            });
        }

        tokio::spawn({
            let zone_maintainer = zone_maintainer.clone();
            async move { zone_maintainer.run().await }
        });

        Self {
            center,
            zone_maintainer,
            zone_updated_tx,
            receipt_info,
        }
    }

    /// React to an application command.
    pub async fn on_command(&self, cmd: ApplicationCommand) -> Result<(), Terminated> {
        debug!("[ZL] Received command: {cmd:?}",);

        match cmd {
            ApplicationCommand::Terminate => {
                return Err(Terminated);
            }

            ApplicationCommand::Changed(Change::ZoneSourceChanged(name, source)) => {
                // Just remove and re-insert the zone.
                let id = ZoneId {
                    name: name.clone(),
                    class: Class::IN,
                };
                self.zone_maintainer.remove_zone(id).await;
                let zone_maintainer = self.zone_maintainer.clone();
                let center = self.center.clone();
                let zone_updated_tx = self.zone_updated_tx.clone();
                let receipt_info = self.receipt_info.clone();

                tokio::spawn(async move {
                    let zone = match source {
                        ZoneLoadSource::None => {
                            // Nothing to do
                            return;
                        }

                        ZoneLoadSource::Zonefile { path } => {
                            match Self::register_primary_zone(
                                center,
                                name.clone(),
                                &path,
                                &zone_updated_tx,
                                receipt_info.clone(),
                            )
                            .await
                            {
                                Ok((zone, ri)) => {
                                    receipt_info.lock().unwrap().insert(name.clone(), ri);
                                    zone
                                }

                                Err(Terminated) => {
                                    // Self::register_primary_zone() will have
                                    // already logged the error so nothing to
                                    // do but quit this task.
                                    return;
                                }
                            }
                        }

                        ZoneLoadSource::Server { addr, tsig_key: _ } => {
                            Self::register_secondary_zone(name.clone(), addr, zone_updated_tx)
                        }
                    };

                    // TODO: Handle (or iron out) potential errors here.
                    let _ = zone_maintainer.insert_zone(zone).await;
                });
            }

            ApplicationCommand::Changed(Change::ZoneRemoved(name)) => {
                // Remove the zone if it was tracked.
                let id = ZoneId {
                    name: name.clone(),
                    class: Class::IN,
                };
                self.zone_maintainer.remove_zone(id).await;
            }

            ApplicationCommand::RefreshZone {
                zone_name,
                serial,
                source,
            } => {
                if let Some(source) = source {
                    let _ = self
                        .zone_maintainer
                        .notify_zone_changed(Class::IN, &zone_name, serial, source)
                        .await;
                } else {
                    // TODO: Should we check the serial number here?
                    let _ = serial;

                    self.zone_maintainer
                        .force_zone_refresh(&zone_name, Class::IN)
                        .await;
                }
            }

            ApplicationCommand::GetZoneReport {
                zone_name,
                report_tx,
            } => {
                if let Ok(report) = self
                    .zone_maintainer
                    .zone_status(&zone_name, Class::IN)
                    .await
                {
                    let zone_loader_report =
                        self.receipt_info.lock().unwrap().get(&zone_name).cloned();
                    report_tx.send((report, zone_loader_report)).unwrap();
                } else {
                    let report = ZoneReport::new(
                        ZoneId::new(zone_name.clone(), Class::IN),
                        ZoneReportDetails::Primary,
                        vec![],
                        ZoneInfo::default(),
                    );
                    let zone_loader_report =
                        self.receipt_info.lock().unwrap().get(&zone_name).cloned();
                    report_tx.send((report, zone_loader_report)).unwrap();
                }
            }

            ApplicationCommand::ReloadZone { zone_name, source } => match source {
                ZoneLoadSource::None => return Ok(()),
                ZoneLoadSource::Zonefile { path } => {
                    Self::remove_and_add(
                        self.center.clone(),
                        zone_name,
                        path,
                        self.zone_maintainer.clone(),
                        &self.zone_updated_tx,
                        self.receipt_info.clone(),
                    )
                    .await
                }
                ZoneLoadSource::Server { .. } => {
                    self.zone_maintainer
                        .force_zone_refresh(&zone_name, Class::IN)
                        .await
                }
            },

            _ => {
                // TODO
            }
        }

        Ok(())
    }

    async fn remove_and_add<KS, CF>(
        center: Arc<Center>,
        name: StoredName,
        path: Box<Utf8Path>,
        zone_maintainer: Arc<ZoneMaintainer<KS, CF>>,
        zone_updated_tx: &Sender<(StoredName, Serial)>,
        receipt_info: Arc<Mutex<HashMap<StoredName, ZoneLoaderReport>>>,
    ) where
        KS: Deref + Send + Sync + 'static,
        KS::Target: KeyStore,
        <KS::Target as KeyStore>::Key: Clone + Debug + Display + Sync + Send + 'static,
        CF: ConnectionFactory + Send + Sync + 'static,
    {
        // Just remove and re-insert the zone (like with zone source changed).
        let id = ZoneId {
            name: name.clone(),
            class: Class::IN,
        };
        zone_maintainer.remove_zone(id).await;

        let Ok((zone, _)) =
            Self::register_primary_zone(center, name.clone(), &path, zone_updated_tx, receipt_info)
                .await
        else {
            return;
        };

        // TODO: Handle (or iron out) potential errors here.
        let _ = zone_maintainer.insert_zone(zone).await;
    }

    async fn register_primary_zone(
        center: Arc<Center>,
        zone_name: StoredName,
        zone_path: &Utf8Path,
        zone_updated_tx: &Sender<(Name<Bytes>, Serial)>,
        receipt_info: Arc<Mutex<HashMap<StoredName, ZoneLoaderReport>>>,
    ) -> Result<(TypedZone, ZoneLoaderReport), Terminated> {
        let (zone, _byte_count) = {
            let cloned_zone_name = zone_name.clone();
            let cloned_zone_path: Box<Utf8Path> = zone_path.into();
            let cloned_receipt_info = receipt_info.clone();
            tokio::task::spawn_blocking(move || {
                load_file_into_zone(&cloned_zone_name, &cloned_zone_path, cloned_receipt_info)
            })
            .await
            .map_err(|_| Terminated)?
            .inspect_err(|err| {
                halt_zone(&center, &zone_name, false, err);
                error!("[ZL]: {err}");
            })
            .map_err(|_| Terminated)?
        };
        let Some(serial) = get_zone_serial(zone_name.clone(), &zone).await else {
            error!("[ZL]: Zone file '{zone_path}' lacks a SOA record. Skipping zone.");
            return Err(Terminated);
        };

        let zone_cfg = ZoneConfig::new();
        zone_updated_tx
            .send((zone.apex_name().clone(), serial))
            .await
            .unwrap();
        let zone = Zone::new(NotifyOnWriteZone::new(zone, zone_updated_tx.clone()));
        let report = receipt_info
            .lock()
            .unwrap()
            .get(&zone_name)
            .cloned()
            .unwrap();
        Ok((TypedZone::new(zone, zone_cfg), report))
    }

    fn register_secondary_zone(
        zone_name: Name<Bytes>,
        source: SocketAddr,
        zone_updated_tx: Sender<(Name<Bytes>, Serial)>,
    ) -> TypedZone {
        let zone_cfg = Self::determine_secondary_zone_cfg(&zone_name, source);
        let zone = Zone::new(LightWeightZone::new(zone_name, true));
        let zone = Zone::new(NotifyOnWriteZone::new(zone, zone_updated_tx));
        TypedZone::new(zone, zone_cfg)
    }

    fn determine_secondary_zone_cfg(zone_name: &StoredName, source: SocketAddr) -> ZoneConfig {
        let mut zone_cfg = ZoneConfig::new();

        let notify_cfg = NotifyConfig::default();

        let xfr_cfg = XfrConfig {
            strategy: XfrStrategy::IxfrWithAxfrFallback,
            ixfr_transport: TransportStrategy::Tcp,
            compatibility_mode: Default::default(),
            tsig_key: None,
        };

        info!(
            "[ZL]: Allowing NOTIFY from {} for zone '{zone_name}'",
            source.ip()
        );

        zone_cfg
            .allow_notify_from
            .add_src(source.ip(), notify_cfg.clone());

        info!("[ZL]: Adding XFR primary {source} for zone '{zone_name}'",);
        zone_cfg.request_xfr_from.add_dst(source, xfr_cfg.clone());

        zone_cfg
    }
}

async fn get_zone_serial(apex_name: Name<Bytes>, zone: &Zone) -> Option<Serial> {
    if let Ok(answer) = zone.read().query(apex_name, Rtype::SOA) {
        if let AnswerContent::Data(rrset) = answer.content() {
            if let Some(rr) = rrset.first() {
                if let ZoneRecordData::Soa(soa) = rr.data() {
                    return Some(soa.serial());
                }
            }
        }
    }
    None
}

fn load_file_into_zone(
    zone_name: &StoredName,
    zone_path: &Utf8Path,
    receipt_info: Arc<Mutex<HashMap<StoredName, ZoneLoaderReport>>>,
) -> Result<(Zone, usize), String> {
    let before = Instant::now();
    info!("[ZL]: Loading primary zone '{zone_name}' from '{zone_path}'..");
    let mut zone_file = File::open(zone_path)
        .map_err(|err| format!("Failed to open zone file '{zone_path}': {err}"))?;
    let zone_file_len = zone_file
        .metadata()
        .map_err(|err| format!("Failed to read metadata for file '{zone_path}': {err}"))?
        .len();

    let report = ZoneLoaderReport {
        started_at: SystemTime::now(),
        finished_at: None,
        byte_count: zone_file_len.try_into().unwrap_or_default(),
        record_count: 0,
    };
    let _ = receipt_info
        .lock()
        .unwrap()
        .insert(zone_name.clone(), report);

    debug!("[ZL]: Allocating {zone_file_len} bytes to read zone '{zone_name}' from '{zone_path}");
    let mut buf = inplace::Zonefile::with_capacity(zone_file_len as usize).writer();

    debug!("[ZL]: Reading {zone_file_len} bytes for zone '{zone_name}' from '{zone_path}");
    std::io::copy(&mut zone_file, &mut buf)
        .map_err(|err| format!("Failed to read data from file '{zone_path}': {err}"))?;
    let mut reader = buf.into_inner();
    reader.set_origin(zone_name.clone());
    reader.set_default_class(Class::IN);

    debug!("[ZL]: Parsing stage 1 {zone_file_len} bytes of zone '{zone_name}' data");
    let mut parsed_zone_file = Zonefile::default();
    let mut rr_count = 0;
    let mut loading_error = None;

    for res in reader {
        match res.map_err(RecordError::MalformedRecord) {
            Ok(Entry::Record(r)) => {
                let stored_rec = r.flatten_into();
                // let name = stored_rec.owner().clone();
                if let Err(err) = parsed_zone_file.insert(stored_rec) {
                    error!("Unable to parse record in '{zone_name}': {err}");
                    loading_error = Some(err.to_string());
                    break;
                }

                rr_count += 1;
                if rr_count % 1000 == 0 {
                    if let Some(ri) = receipt_info.lock().unwrap().get_mut(zone_name) {
                        ri.record_count = rr_count;
                    }
                }
            }

            Ok(Entry::Include { .. }) => {
                // Not supported at this time.
                error!("[ZL] Zone file $INCLUDE directive in zone '{zone_name}' is not supported");
                loading_error =
                    Some("Zone file contains unsupported $INCLUDE directive".to_string());
                break;
            }

            Err(err) => {
                // The inplace::Zonefile parser is not capable of
                // continuing after an error, so we immediately return for
                // now.
                error!("[ZL]: Fatal error while parsing zone '{zone_name}': {err}");
                loading_error = Some(err.to_string());
                break;
            }
        }
    }

    if let Some(err) = loading_error {
        return Err(format!(
            "Encountered an error while loading the zone: {err}"
        ));
    }

    debug!("[ZL]: Parsing stage 2 of zone '{zone_name}' data");
    let res = ZoneBuilder::try_from(parsed_zone_file).map(Zone::from);
    let Ok(zone) = res else {
        let err = format!("{}", res.unwrap_err());
        error!("[ZL]: Failed to build a zone tree for '{zone_name}': {err}");
        return Err(format!(
            "Encountered an error while loading the zone: {err}"
        ));
    };
    info!(
        "Loaded {zone_file_len} bytes from '{zone_path}' in {} secs",
        before.elapsed().as_secs()
    );

    if let Some(ri) = receipt_info.lock().unwrap().get_mut(zone_name) {
        ri.record_count = rr_count;
        ri.finished_at = Some(SystemTime::now());
    }

    Ok((zone, zone_file_len as usize))
}

//------------- NotifyOnWriteZone --------------------------------------------

#[derive(Debug)]
pub struct NotifyOnWriteZone {
    store: Arc<dyn ZoneStore>,
    sender: Sender<(StoredName, Serial)>,
}

impl NotifyOnWriteZone {
    pub fn new(zone: Zone, sender: Sender<(StoredName, Serial)>) -> Self {
        Self {
            store: zone.into_inner(),
            sender,
        }
    }
}

impl ZoneStore for NotifyOnWriteZone {
    fn class(&self) -> Class {
        self.store.class()
    }

    fn apex_name(&self) -> &StoredName {
        self.store.apex_name()
    }

    fn read(self: Arc<Self>) -> Box<dyn ReadableZone> {
        self.store.clone().read()
    }

    fn write(
        self: Arc<Self>,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WritableZone>> + Send + Sync>> {
        let fut = self.store.clone().write();
        Box::pin(async move {
            let writable_zone = fut.await;
            let writable_zone = NotifyOnCommitZone {
                writable_zone,
                store: self.store.clone(),
                sender: self.sender.clone(),
            };
            Box::new(writable_zone) as Box<dyn WritableZone>
        })
    }

    fn as_any(&self) -> &dyn Any {
        self as &dyn Any
    }
}

struct NotifyOnCommitZone {
    writable_zone: Box<dyn WritableZone>,
    store: Arc<dyn ZoneStore>,
    sender: Sender<(StoredName, Serial)>,
}

impl WritableZone for NotifyOnCommitZone {
    fn open(
        &self,
        create_diff: bool,
    ) -> Pin<
        Box<dyn Future<Output = Result<Box<dyn WritableZoneNode>, std::io::Error>> + Send + Sync>,
    > {
        self.writable_zone.open(create_diff)
    }

    fn commit(
        &mut self,
        bump_soa_serial: bool,
    ) -> Pin<Box<dyn Future<Output = Result<Option<InMemoryZoneDiff>, std::io::Error>> + Send + Sync>>
    {
        let fut = self.writable_zone.commit(bump_soa_serial);
        let store = self.store.clone();
        let sender = self.sender.clone();

        Box::pin(async move {
            let res = fut.await;
            let zone_name = store.apex_name().clone();
            match store
                .read()
                .query_async(zone_name.clone(), Rtype::SOA)
                .await
            {
                Ok(answer) if answer.rcode() == Rcode::NOERROR => {
                    let soa_data = answer.content().first().map(|(_ttl, data)| data);
                    if let Some(ZoneRecordData::Soa(soa)) = soa_data {
                        let zone_serial = soa.serial();
                        debug!("Notifying that zone '{zone_name}' has been committed at serial {zone_serial}");
                        sender.send((zone_name.clone(), zone_serial)).await.unwrap();
                    } else {
                        error!("Failed to query SOA of zone {zone_name} after commit: invalid SOA found");
                    }
                }
                Ok(answer) => error!(
                    "Failed to query SOA of zone {zone_name} after commit: rcode {}",
                    answer.rcode()
                ),
                Err(_) => {
                    error!("Failed to query SOA of zone {zone_name} after commit: out of zone.")
                }
            }
            res
        })
    }
}
