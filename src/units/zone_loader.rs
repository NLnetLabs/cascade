use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::fs::File;
use std::net::SocketAddr;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;

use bytes::{BufMut, Bytes};
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
use tokio::time::Instant;

#[cfg(feature = "tls")]
use tokio_rustls::rustls::ServerConfig;

use crate::api::ZoneSource;
use crate::center::Center;
use crate::common::light_weight_zone::LightWeightZone;
use crate::common::tsig::{parse_key_strings, TsigKeyStore};
use crate::common::xfr::parse_xfr_acl;
use crate::comms::{ApplicationCommand, Terminated};
use crate::payload::Update;
use crate::zonemaintenance::maintainer::{
    Config, ConnectionFactory, DefaultConnFactory, TypedZone, ZoneMaintainer,
};
use crate::zonemaintenance::types::{
    NotifyConfig, TransportStrategy, XfrConfig, XfrStrategy, ZoneConfig,
};

#[derive(Debug)]
pub struct ZoneLoader {
    /// The center.
    pub center: Arc<Center>,

    /// The zone names and (if primary) corresponding zone file paths to load.
    pub zones: Arc<HashMap<StoredName, String>>,

    /// XFR in per secondary zone: Allow NOTIFY from, and when with a port also request XFR from.
    pub xfr_in: Arc<HashMap<StoredName, String>>,

    /// XFR out per primary zone: Allow XFR from, and when with a port also send NOTIFY to.
    pub xfr_out: Arc<HashMap<StoredName, String>>,

    /// TSIG keys.
    pub tsig_keys: HashMap<String, String>,
}

impl ZoneLoader {
    pub async fn run(
        self,
        mut cmd_rx: mpsc::UnboundedReceiver<ApplicationCommand>,
    ) -> Result<(), Terminated> {
        // TODO: metrics and status reporting

        let (zone_updated_tx, mut zone_updated_rx) = tokio::sync::mpsc::channel(10);

        for (key_name, opt_alg_and_hex_bytes) in self.tsig_keys.iter() {
            let key = parse_key_strings(key_name, opt_alg_and_hex_bytes).map_err(|err| {
                error!("[ZL]: Failed to parse TSIG key '{key_name}': {err}",);
                Terminated
            })?;
            self.center.old_tsig_key_store.insert(key);
        }

        let maintainer_config =
            Config::<_, DefaultConnFactory>::new(self.center.old_tsig_key_store.clone());
        let zone_maintainer = Arc::new(
            ZoneMaintainer::new_with_config(maintainer_config)
                .with_zone_tree(self.center.unsigned_zones.clone()),
        );

        // We used to load zones from config, but not any longer. This should begin empty.
        assert!(self.zones.is_empty());

        // // Load primary zones.
        // // Create secondary zones.
        // for (zone_name, zone_path) in self.zones.iter() {
        //     let zone = if !zone_path.is_empty() {
        //         Self::register_primary_zone(
        //             zone_name.clone(),
        //             zone_path,
        //             &self.center.old_tsig_key_store,
        //             None,
        //             &self.xfr_out,
        //             &zone_updated_tx,
        //         )
        //         .await?
        //     } else {
        //         info!("[ZL]: Adding secondary zone '{zone_name}'",);
        //         Self::register_secondary_zone(
        //             zone_name.clone(),
        //             &self.center.old_tsig_key_store,
        //             None,
        //             &self.xfr_in,
        //             zone_updated_tx.clone(),
        //         )?
        //     };

        //     if let Err(err) = zone_maintainer.insert_zone(zone).await {
        //         error!("[ZL]: Error: Failed to insert zone '{zone_name}': {err}")
        //     }
        // }

        let zone_maintainer_clone = zone_maintainer.clone();
        tokio::spawn(async move { zone_maintainer_clone.run().await });

        loop {
            tokio::select! {
                zone_updated = zone_updated_rx.recv() => {
                    self.on_zone_updated(zone_updated);
                }

                cmd = cmd_rx.recv() => {
                    self.on_command(cmd, &self.center.old_tsig_key_store, &zone_maintainer, zone_updated_tx.clone()).await?;
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
        tsig_key_store: &TsigKeyStore,
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

            Some(ApplicationCommand::RegisterZone { register }) => {
                let res = match register.source {
                    ZoneSource::Zonefile {
                        path, /* Lacks XFR out settings */
                    } => {
                        Self::register_primary_zone(
                            register.name.clone(),
                            &path.to_string(),
                            tsig_key_store,
                            None,
                            &self.xfr_out,
                            &zone_updated_tx,
                        )
                        .await
                    }
                    ZoneSource::Server {
                        addr, /* Lacks TSIG key name */
                    } => {
                        // Use any existing XFR inbound ACL that has been
                        // defined for this zone from this source.
                        Self::register_secondary_zone(
                            register.name.clone(),
                            tsig_key_store,
                            Some(addr),
                            &self.xfr_in,
                            zone_updated_tx.clone(),
                        )
                    }
                };

                match res {
                    Err(_) => {
                        error!("[ZL]: Error: Failed to register zone '{}'", register.name);
                    }

                    Ok(zone) => {
                        if let Err(err) = zone_maintainer.insert_zone(zone).await {
                            error!(
                                "[ZL]: Error: Failed to insert zone '{}': {err}",
                                register.name
                            );
                        }
                    }
                }
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

            Some(_) => {
                // TODO
            }
        }

        Ok(())
    }

    async fn register_primary_zone(
        zone_name: StoredName,
        zone_path: &str,
        tsig_key_store: &TsigKeyStore,
        dest: Option<SocketAddr>,
        xfr_out: &HashMap<StoredName, String>,
        zone_updated_tx: &Sender<(Name<Bytes>, Serial)>,
    ) -> Result<TypedZone, Terminated> {
        let zone = load_file_into_zone(&zone_name, zone_path).await?;
        let Some(serial) = get_zone_serial(zone_name.clone(), &zone).await else {
            error!("[ZL]: Error: Zone file '{zone_path}' lacks a SOA record. Skipping zone.");
            return Err(Terminated);
        };

        let zone_cfg = Self::determine_primary_zone_cfg(&zone_name, xfr_out, dest, tsig_key_store)?;
        zone_updated_tx
            .send((zone.apex_name().clone(), serial))
            .await
            .unwrap();
        let zone = Zone::new(NotifyOnWriteZone::new(zone, zone_updated_tx.clone()));
        Ok(TypedZone::new(zone, zone_cfg))
    }

    fn determine_primary_zone_cfg(
        zone_name: &StoredName,
        xfr_out: &HashMap<StoredName, String>,
        dest: Option<SocketAddr>,
        tsig_key_store: &TsigKeyStore,
    ) -> Result<ZoneConfig, Terminated> {
        let mut zone_cfg = ZoneConfig::new();

        if let Some(xfr_out) = xfr_out.get(zone_name) {
            let mut notify_cfg = NotifyConfig::default();

            let mut xfr_cfg = XfrConfig {
                strategy: XfrStrategy::IxfrWithAxfrFallback,
                ixfr_transport: TransportStrategy::Tcp,
                ..Default::default()
            };

            let dst = parse_xfr_acl(xfr_out, &mut xfr_cfg, &mut notify_cfg, tsig_key_store)
                .map_err(|_| {
                    error!("[ZL]: Error parsing XFR ACL");
                    Terminated
                })?;

            info!("[ZL]: Adding XFR secondary {dst} for zone '{zone_name}'",);

            if Some(dst) != dest {
                // Don't use any settings we found for this zone, they were
                // for a different source. Instead use default settings for
                // NOTIFY and XFR, i.e. send NOTIFY and request XFR, but
                // don't use TSIG and no special restrictions over the XFR
                // transport/protocol to use.
                notify_cfg = NotifyConfig::default();
                xfr_cfg = XfrConfig::default();
            }

            zone_cfg.provide_xfr_to.add_src(dst.ip(), xfr_cfg.clone());

            if dst.port() != 0 {
                info!(
                    "[ZL]: Allowing NOTIFY to {} for zone '{zone_name}'",
                    dst.ip()
                );
                zone_cfg.send_notify_to.add_dst(dst, notify_cfg.clone());
            }
        } else {
            // Local primary zone that has no known secondary, so no
            // nameserver to permit XFR from or send NOTIFY to.
        }

        Ok(zone_cfg)
    }

    fn register_secondary_zone(
        zone_name: Name<Bytes>,
        tsig_key_store: &TsigKeyStore,
        source: Option<SocketAddr>,
        xfr_in: &HashMap<StoredName, String>,
        zone_updated_tx: Sender<(Name<Bytes>, Serial)>,
    ) -> Result<TypedZone, Terminated> {
        let zone_cfg =
            Self::determine_secondary_zone_cfg(&zone_name, source, xfr_in, tsig_key_store)?;
        let zone = Zone::new(LightWeightZone::new(zone_name, true));
        let zone = Zone::new(NotifyOnWriteZone::new(zone, zone_updated_tx));
        Ok(TypedZone::new(zone, zone_cfg))
    }

    fn determine_secondary_zone_cfg(
        zone_name: &StoredName,
        source: Option<SocketAddr>,
        xfr_in: &HashMap<StoredName, String>,
        tsig_key_store: &TsigKeyStore,
    ) -> Result<ZoneConfig, Terminated> {
        let mut zone_cfg = ZoneConfig::new();

        if let Some(xfr_in) = xfr_in.get(zone_name) {
            let mut notify_cfg = NotifyConfig::default();

            let mut xfr_cfg = XfrConfig {
                strategy: XfrStrategy::IxfrWithAxfrFallback,
                ixfr_transport: TransportStrategy::Tcp,
                ..Default::default()
            };

            let src = parse_xfr_acl(xfr_in, &mut xfr_cfg, &mut notify_cfg, tsig_key_store)
                .map_err(|_| {
                    error!("[ZL]: Error parsing XFR ACL");
                    Terminated
                })?;

            info!(
                "[ZL]: Allowing NOTIFY from {} for zone '{zone_name}'",
                src.ip()
            );

            if Some(src) != source {
                // Don't use any settings we found for this zone, they were
                // for a different source. Instead use default settings for
                // NOTIFY and XFR, i.e. send NOTIFY and request XFR, but
                // don't use TSIG and no special restrictions over the XFR
                // transport/protocol to use.
                notify_cfg = NotifyConfig::default();
                xfr_cfg = XfrConfig::default();
            }

            zone_cfg
                .allow_notify_from
                .add_src(src.ip(), notify_cfg.clone());

            if src.port() != 0 {
                info!("[ZL]: Adding XFR primary {src} for zone '{zone_name}'",);
                zone_cfg.request_xfr_from.add_dst(src, xfr_cfg.clone());
            }
        }

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

async fn load_file_into_zone(zone_name: &StoredName, zone_path: &str) -> Result<Zone, Terminated> {
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
