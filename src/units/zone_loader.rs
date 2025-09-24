use std::any::Any;
use std::fmt::{Debug, Display};
use std::fs::File;
use std::net::SocketAddr;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;

use bytes::{BufMut, Bytes};
use camino::Utf8Path;
use domain::base::iana::{Class, Rcode};
use domain::base::{Name, Rtype, Serial};
use domain::net::server::middleware::notify::Notifiable;
use domain::rdata::ZoneRecordData;
use domain::tsig::KeyStore;
use domain::zonefile::inplace;
use domain::zonetree::{
    AnswerContent, InMemoryZoneDiff, ReadableZone, StoredName, WritableZone, WritableZoneNode,
    Zone, ZoneStore,
};
use futures::Future;
use log::{debug, error, info};
use tokio::sync::mpsc::{self, Sender};
use tokio::sync::oneshot;
use tokio::time::Instant;

#[cfg(feature = "tls")]
use tokio_rustls::rustls::ServerConfig;

use crate::center::{Center, Change};
use crate::common::light_weight_zone::LightWeightZone;
use crate::comms::{ApplicationCommand, Terminated};
use crate::payload::Update;
use crate::zone::ZoneLoadSource;
use crate::zonemaintenance::maintainer::{
    Config, ConnectionFactory, DefaultConnFactory, TypedZone, ZoneMaintainer,
};
use crate::zonemaintenance::types::{
    NotifyConfig, TransportStrategy, XfrConfig, XfrStrategy, ZoneConfig, ZoneId,
};

#[derive(Debug)]
pub struct ZoneLoader {
    /// The center.
    pub center: Arc<Center>,
}

impl ZoneLoader {
    pub async fn run(
        self,
        mut cmd_rx: mpsc::UnboundedReceiver<ApplicationCommand>,
        ready_tx: oneshot::Sender<bool>,
    ) -> Result<(), Terminated> {
        // TODO: metrics and status reporting

        let (zone_updated_tx, mut zone_updated_rx) = tokio::sync::mpsc::channel(10);

        let maintainer_config =
            Config::<_, DefaultConnFactory>::new(self.center.old_tsig_key_store.clone());
        let zone_maintainer = Arc::new(
            ZoneMaintainer::new_with_config(maintainer_config)
                .with_zone_tree(self.center.unsigned_zones.clone()),
        );

        // Load primary zones.
        // Create secondary zones.
        let zones = {
            let state = self.center.state.lock().unwrap();
            state
                .zones
                .iter()
                .map(|zone| {
                    let state = zone.0.state.lock().unwrap();
                    (zone.0.name.clone(), state.source.clone())
                })
                .collect::<Vec<_>>()
        };
        for (name, source) in zones {
            info!("[ZL]: Adding zone '{name}' with source '{source:?}'",);
            let zone = match source {
                ZoneLoadSource::None => continue,

                ZoneLoadSource::Zonefile { path } => {
                    Self::register_primary_zone(name.clone(), &path, &zone_updated_tx).await?
                }

                ZoneLoadSource::Server { addr, tsig_key: _ } => {
                    Self::register_secondary_zone(name.clone(), addr, zone_updated_tx.clone())?
                }
            };

            if let Err(err) = zone_maintainer.insert_zone(zone).await {
                error!("[ZL]: Error: Failed to insert zone '{name}': {err}")
            }
        }

        let zone_maintainer_clone = zone_maintainer.clone();
        tokio::spawn(async move { zone_maintainer_clone.run().await });

        // Notify the manager that we are ready.
        ready_tx.send(true).map_err(|_| Terminated)?;

        loop {
            tokio::select! {
                zone_updated = zone_updated_rx.recv() => {
                    self.on_zone_updated(zone_updated);
                }

                cmd = cmd_rx.recv() => {
                    self.on_command(cmd, &zone_maintainer, zone_updated_tx.clone()).await?;
                }
            }
        }
    }

    fn on_zone_updated(&self, zone_updated: Option<(StoredName, Serial)>) {
        let (zone_name, zone_serial) = zone_updated.unwrap();

        info!("[ZL]: Received a new copy of zone '{zone_name}' at serial {zone_serial}",);

        self.center
            .update_tx
            .send(Update::UnsignedZoneUpdatedEvent {
                zone_name,
                zone_serial,
            })
            .unwrap();
    }

    async fn on_command<KS, CF>(
        &self,
        cmd: Option<ApplicationCommand>,
        zone_maintainer: &ZoneMaintainer<KS, CF>,
        zone_updated_tx: Sender<(StoredName, Serial)>,
    ) -> Result<(), Terminated>
    where
        KS: Deref + Send + Sync + 'static,
        KS::Target: KeyStore,
        <KS::Target as KeyStore>::Key: Clone + Debug + Display + Sync + Send + 'static,
        CF: ConnectionFactory + Send + Sync + 'static,
    {
        info!("[ZL] Received command: {cmd:?}",);

        match cmd {
            Some(ApplicationCommand::Terminate) | None => {
                return Err(Terminated);
            }

            Some(ApplicationCommand::Changed(Change::ZoneSourceChanged(name, source))) => {
                // Just remove and re-insert the zone.
                let id = ZoneId {
                    name: name.clone(),
                    class: Class::IN,
                };
                zone_maintainer.remove_zone(id).await;

                let zone = match source {
                    ZoneLoadSource::None => return Ok(()),

                    ZoneLoadSource::Zonefile { path } => {
                        Self::register_primary_zone(name.clone(), &path, &zone_updated_tx).await?
                    }

                    ZoneLoadSource::Server { addr, tsig_key: _ } => {
                        Self::register_secondary_zone(name.clone(), addr, zone_updated_tx)?
                    }
                };

                // TODO: Handle (or iron out) potential errors here.
                let _ = zone_maintainer.insert_zone(zone).await;
            }

            Some(ApplicationCommand::Changed(Change::ZoneRemoved(name))) => {
                // Remove the zone if it was tracked.
                let id = ZoneId {
                    name: name.clone(),
                    class: Class::IN,
                };
                zone_maintainer.remove_zone(id).await;
            }

            Some(ApplicationCommand::RefreshZone {
                zone_name,
                serial,
                source,
            }) => {
                if let Some(source) = source {
                    let _ = zone_maintainer
                        .notify_zone_changed(Class::IN, &zone_name, serial, source)
                        .await;
                } else {
                    // TODO: Should we check the serial number here?
                    let _ = serial;

                    zone_maintainer
                        .force_zone_refresh(&zone_name, Class::IN)
                        .await;
                }
            }

            Some(ApplicationCommand::ReloadZone {
                zone_name: name,
                source,
            }) => {
                // Just remove and re-insert the zone (like with zone source changed).
                let id = ZoneId {
                    name: name.clone(),
                    class: Class::IN,
                };
                zone_maintainer.remove_zone(id).await;

                let zone = match source {
                    ZoneLoadSource::None => return Ok(()),

                    ZoneLoadSource::Zonefile { path } => {
                        Self::register_primary_zone(name.clone(), &path, &zone_updated_tx).await?
                    }

                    ZoneLoadSource::Server { addr, tsig_key: _ } => {
                        Self::register_secondary_zone(name.clone(), addr, zone_updated_tx)?
                    }
                };

                // TODO: Handle (or iron out) potential errors here.
                let _ = zone_maintainer.insert_zone(zone).await;
            }

            Some(_) => {
                // TODO
            }
        }

        Ok(())
    }

    async fn register_primary_zone(
        zone_name: StoredName,
        zone_path: &Utf8Path,
        zone_updated_tx: &Sender<(Name<Bytes>, Serial)>,
    ) -> Result<TypedZone, Terminated> {
        let zone = load_file_into_zone(&zone_name, zone_path).await?;
        let Some(serial) = get_zone_serial(zone_name.clone(), &zone).await else {
            error!("[ZL]: Error: Zone file '{zone_path}' lacks a SOA record. Skipping zone.");
            return Err(Terminated);
        };

        let zone_cfg = ZoneConfig::new();
        zone_updated_tx
            .send((zone.apex_name().clone(), serial))
            .await
            .unwrap();
        let zone = Zone::new(NotifyOnWriteZone::new(zone, zone_updated_tx.clone()));
        Ok(TypedZone::new(zone, zone_cfg))
    }

    fn register_secondary_zone(
        zone_name: Name<Bytes>,
        source: SocketAddr,
        zone_updated_tx: Sender<(Name<Bytes>, Serial)>,
    ) -> Result<TypedZone, Terminated> {
        let zone_cfg = Self::determine_secondary_zone_cfg(&zone_name, source)?;
        let zone = Zone::new(LightWeightZone::new(zone_name, true));
        let zone = Zone::new(NotifyOnWriteZone::new(zone, zone_updated_tx));
        Ok(TypedZone::new(zone, zone_cfg))
    }

    fn determine_secondary_zone_cfg(
        zone_name: &StoredName,
        source: SocketAddr,
    ) -> Result<ZoneConfig, Terminated> {
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

        Ok(zone_cfg)
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

async fn load_file_into_zone(
    zone_name: &StoredName,
    zone_path: &Utf8Path,
) -> Result<Zone, Terminated> {
    let before = Instant::now();
    info!("[ZL]: Loading primary zone '{zone_name}' from '{zone_path}'..",);
    let mut zone_file = File::open(zone_path)
        .inspect_err(|err| error!("[ZL]: Error: Failed to open zone file '{zone_path}': {err}",))
        .map_err(|_| Terminated)?;
    let zone_file_len = zone_file
        .metadata()
        .inspect_err(|err| {
            error!("[ZL]: Error: Failed to read metadata for file '{zone_path}': {err}",)
        })
        .map_err(|_| Terminated)?
        .len();
    let mut buf = inplace::Zonefile::with_capacity(zone_file_len as usize).writer();
    std::io::copy(&mut zone_file, &mut buf)
        .inspect_err(|err| {
            error!("[ZL]: Error: Failed to read data from file '{zone_path}': {err}",)
        })
        .map_err(|_| Terminated)?;
    let reader = buf.into_inner();
    let res = Zone::try_from(reader);
    let Ok(zone) = res else {
        let errors = res.unwrap_err();
        let mut msg = format!("Failed to parse zone: {} errors", errors.len());
        for (name, err) in errors.into_iter() {
            msg.push_str(&format!("  {name}: {err}\n"));
        }
        error!("[ZL]: Error parsing zone '{zone_name}': {msg}");
        return Err(Terminated);
    };
    info!(
        "Loaded {zone_file_len} bytes from '{zone_path}' in {} secs",
        before.elapsed().as_secs()
    );
    Ok(zone)
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
