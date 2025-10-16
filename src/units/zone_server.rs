use core::future::ready;

use std::marker::Sync;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use arc_swap::ArcSwap;
use bytes::Bytes;
use domain::base::iana::{Class, Rcode};
use domain::base::Name;
use domain::base::{Serial, ToName};
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::{self, DgramServer};
use domain::net::server::message::Request;
use domain::net::server::middleware::cookies::CookiesMiddlewareSvc;
use domain::net::server::middleware::edns::EdnsMiddlewareSvc;
use domain::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use domain::net::server::middleware::notify::{Notifiable, NotifyError, NotifyMiddlewareSvc};
use domain::net::server::middleware::tsig::TsigMiddlewareSvc;
use domain::net::server::middleware::xfr::XfrMiddlewareSvc;
use domain::net::server::middleware::xfr::{XfrData, XfrDataProvider, XfrDataProviderError};
use domain::net::server::service::{CallResult, Service, ServiceResult};
use domain::net::server::stream::{self, StreamServer};
use domain::net::server::util::mk_builder_for_target;
use domain::net::server::util::service_fn;
use domain::net::server::ConnectionConfig;
use domain::tsig::KeyStore;
use domain::tsig::{Algorithm, Key};
use domain::zonetree::types::EmptyZoneDiff;
use domain::zonetree::Answer;
use domain::zonetree::{StoredName, ZoneTree};
use futures::Future;
use log::{debug, error, info, warn};
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot, RwLock};

use crate::api::{
    ZoneReviewDecision, ZoneReviewError, ZoneReviewOutput, ZoneReviewResult, ZoneReviewStage,
    ZoneReviewStatus,
};
use crate::center::{get_zone, Center};
use crate::common::tsig::TsigKeyStore;
use crate::comms::ApplicationCommand;
use crate::comms::Terminated;
use crate::config::SocketConfig;
use crate::daemon::SocketProvider;
use crate::payload::Update;
use crate::targets::central_command::record_zone_event;
use crate::zone::HistoricalEvent;
use crate::zonemaintenance::maintainer::{Config, DefaultConnFactory, ZoneMaintainer};

#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq)]
pub enum Mode {
    #[serde(alias = "prepublish")]
    #[serde(alias = "prepub")]
    Prepublish,

    #[serde(alias = "publish")]
    #[serde(alias = "pub")]
    Publish,
}

#[allow(clippy::enum_variant_names)]
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq)]
pub enum Source {
    #[serde(alias = "unsigned")]
    UnsignedZones,

    #[serde(alias = "signed")]
    SignedZones,

    #[serde(alias = "published")]
    PublishedZones,
}

#[derive(Debug)]
pub struct ZoneServerUnit {
    pub center: Arc<Center>,

    pub mode: Mode,

    pub source: Source,
}

impl ZoneServerUnit {
    pub async fn run(
        self,
        cmd_rx: mpsc::UnboundedReceiver<ApplicationCommand>,
        ready_tx: oneshot::Sender<bool>,
        socket_provider: Arc<Mutex<SocketProvider>>,
    ) -> Result<(), Terminated> {
        let unit_name = match (self.mode, self.source) {
            (Mode::Prepublish, Source::UnsignedZones) => "RS",
            (Mode::Prepublish, Source::SignedZones) => "RS2",
            (Mode::Publish, Source::PublishedZones) => "PS",
            _ => unreachable!(),
        };

        // TODO: metrics and status reporting

        // TODO: This will just choose all current zones to be served. For signed and published
        // zones this doesn't matter so much as they only exist while being and once approved.
        // But for unsigned zones the zone could be updated whilst being reviewed and we only
        // serve the latest version of the zone, not the specific serial being reviewed!
        let zones = match self.source {
            Source::UnsignedZones => self.center.unsigned_zones.clone(),
            Source::SignedZones => self.center.signed_zones.clone(),
            Source::PublishedZones => self.center.published_zones.clone(),
        };

        let max_concurrency = std::thread::available_parallelism().unwrap().get() / 2;

        // TODO: Pass xfr_out to XfrDataProvidingZonesWrapper for enforcement.
        let zones = XfrDataProvidingZonesWrapper {
            zones,
            key_store: self.center.old_tsig_key_store.clone(),
        };

        // Propagate NOTIFY messages if this is the publication server.
        let notifier = LoaderNotifier {
            enabled: self.source == Source::PublishedZones,
            update_tx: self.center.update_tx.clone(),
        };

        // let svc = ZoneServerService::new(zones.clone());
        let svc = service_fn(zone_server_service, zones.clone());
        let svc = XfrMiddlewareSvc::new(svc, zones.clone(), max_concurrency);
        let svc = NotifyMiddlewareSvc::new(svc, notifier);
        let svc = TsigMiddlewareSvc::new(svc, self.center.old_tsig_key_store.clone());
        let svc = CookiesMiddlewareSvc::with_random_secret(svc);
        let svc = EdnsMiddlewareSvc::new(svc);
        let svc = MandatoryMiddlewareSvc::<_, _, ()>::new(svc);
        let svc = Arc::new(svc);

        // TODO: Should this reload when the config changes?
        let servers = {
            let state = self.center.state.lock().unwrap();
            let config = &state.config;
            let servers = match self.source {
                Source::UnsignedZones => &config.loader.review.servers,
                Source::SignedZones => &config.signer.review.servers,
                Source::PublishedZones => &config.server.servers,
            };
            servers.clone()
        };

        let _addrs = spawn_servers(socket_provider, unit_name, svc, servers)
            .inspect_err(|err| error!("[{unit_name}]: Spawning nameservers failed: {err}"))
            .map_err(|_| Terminated)?;

        // Notify the manager that we are ready.
        ready_tx.send(true).map_err(|_| Terminated)?;

        let update_tx = self.center.update_tx.clone();
        ZoneServer::new(self.center, self.source)
            .run(unit_name, update_tx, cmd_rx)
            .await?;

        Ok(())
    }
}

fn spawn_servers<Svc>(
    socket_provider: Arc<Mutex<SocketProvider>>,
    unit_name: &'static str,
    svc: Svc,
    servers: Vec<SocketConfig>,
) -> Result<Vec<String>, String>
where
    Svc: Service<Vec<u8>, ()> + Clone,
{
    let mut addrs = Vec::new();
    let mut socket_provider = socket_provider.lock().unwrap();
    for sock_cfg in servers {
        if let SocketConfig::UDP { addr } | SocketConfig::TCPUDP { addr } = sock_cfg {
            info!("[{unit_name}]: Obtaining UDP socket for address {addr}");
            let sock = socket_provider
                .take_udp(&addr)
                .ok_or(format!("No socket available for UDP {addr}"))?;
            tokio::spawn(serve_on_udp(svc.clone(), VecBufSource, sock));
            addrs.push(addr.to_string());
        }

        if let SocketConfig::TCP { addr } | SocketConfig::TCPUDP { addr } = sock_cfg {
            info!("[{unit_name}]: Obtaining TCP listener for address {addr}");
            let sock = socket_provider
                .take_tcp(&addr)
                .ok_or(format!("No socket available for TCP {addr}"))?;
            tokio::spawn(serve_on_tcp(svc.clone(), VecBufSource, sock));
            addrs.push(addr.to_string());
        }
    }

    if unit_name == "PS" {
        // Also listen on any remaining UDP and TCP sockets provided by
        // the O/S.
        while let Some(sock) = socket_provider.pop_udp() {
            let addr = sock
                .local_addr()
                .map_err(|err| format!("Provided UDP socket lacks address: {err}"))?;
            info!("[{unit_name}]: Receieved additional UDP socket {addr}");
            tokio::spawn(serve_on_udp(svc.clone(), VecBufSource, sock));
            addrs.push(addr.to_string());
        }
        while let Some(sock) = socket_provider.pop_tcp() {
            let addr = sock
                .local_addr()
                .map_err(|err| format!("Provided TCP listener lacks address: {err}"))?;
            info!("[{unit_name}]: Receieved additional TCP listener {addr}");
            tokio::spawn(serve_on_tcp(svc.clone(), VecBufSource, sock));
            addrs.push(addr.to_string());
        }
    }

    Ok(addrs)
}

async fn serve_on_udp<Svc>(svc: Svc, buf: VecBufSource, sock: tokio::net::UdpSocket)
where
    Svc: Service<Vec<u8>, ()> + Clone,
{
    let config = dgram::Config::new();
    let srv = DgramServer::<_, _, _>::with_config(sock, buf, svc, config);
    let srv = Arc::new(srv);
    srv.run().await;
}

async fn serve_on_tcp<Svc>(svc: Svc, buf: VecBufSource, sock: tokio::net::TcpListener)
where
    Svc: Service<Vec<u8>, ()> + Clone,
{
    let mut conn_config = ConnectionConfig::new();
    conn_config.set_max_queued_responses(10000);
    let mut config = stream::Config::new();
    config.set_connection_config(conn_config);
    let srv = StreamServer::with_config(sock, buf, svc, config);
    let srv = Arc::new(srv);
    srv.run().await;
}

//------------ ZoneServer ----------------------------------------------------

struct ZoneServer {
    zone_review_api: Option<ZoneReviewApi>,
    center: Arc<Center>,
    source: Source,
    #[allow(clippy::type_complexity)]
    pending_approvals: Arc<RwLock<foldhash::HashSet<(Name<Bytes>, Serial)>>>,
    #[allow(clippy::type_complexity)]
    last_approvals: Arc<RwLock<foldhash::HashMap<(Name<Bytes>, Serial), Instant>>>,
}

impl ZoneServer {
    #[allow(clippy::too_many_arguments)]
    fn new(center: Arc<Center>, source: Source) -> Self {
        Self {
            zone_review_api: Default::default(),
            center,
            source,
            pending_approvals: Default::default(),
            last_approvals: Default::default(),
        }
    }

    async fn run(
        mut self,
        unit_name: &'static str,
        update_tx: mpsc::UnboundedSender<Update>,
        mut cmd_rx: mpsc::UnboundedReceiver<ApplicationCommand>,
    ) -> Result<(), crate::comms::Terminated> {
        // let status_reporter = self.status_reporter.clone();

        // Setup approval API endpoint
        self.zone_review_api = Some(ZoneReviewApi::new(
            self.center.clone(),
            update_tx.clone(),
            self.pending_approvals.clone(),
            self.last_approvals.clone(),
            self.source,
        ));

        // status_reporter.listener_listening(&listen_addr.to_string());

        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    let Some(cmd) = cmd else {
                        // arc_self.status_reporter.terminated();
                        return Err(Terminated);
                    };

                    self.handle_command(cmd, unit_name, update_tx.clone()).await?;
                }
            }
        }
    }

    async fn handle_command(
        &self,
        cmd: ApplicationCommand,
        unit_name: &'static str,
        update_tx: mpsc::UnboundedSender<Update>,
    ) -> Result<(), Terminated> {
        debug!("[{unit_name}] Received command: {cmd:?}",);
        match cmd {
            ApplicationCommand::Terminate => {
                // arc_self.status_reporter.terminated();
                return Err(Terminated);
            }

            ApplicationCommand::ReviewZone {
                name,
                serial,
                decision,
                tx,
            } => {
                self.on_zone_review_api_cmd(
                    unit_name,
                    name,
                    serial,
                    matches!(decision, ZoneReviewDecision::Approve),
                    tx,
                )
                .await;
            }

            ApplicationCommand::SeekApprovalForUnsignedZone { .. }
            | ApplicationCommand::SeekApprovalForSignedZone { .. } => {
                self.on_seek_approval_for_zone_cmd(cmd, unit_name, update_tx)
                    .await;
            }

            ApplicationCommand::PublishSignedZone {
                zone_name,
                zone_serial,
            } => {
                self.on_publish_signed_zone_cmd(unit_name, zone_name, zone_serial)
                    .await;
            }

            _ => { /* Not for us */ }
        }

        Ok(())
    }

    async fn on_publish_signed_zone_cmd(
        &self,
        unit_name: &str,
        zone_name: Name<Bytes>,
        zone_serial: Serial,
    ) {
        info!("[{unit_name}]: Publishing signed zone '{zone_name}' at serial {zone_serial}.");

        // Move next_min_expiration to min_expiration, and determine policy.
        let policy = {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone = get_zone(&self.center, &zone_name).unwrap();
            let mut zone_state = zone.state.lock().unwrap();

            // Save as next_min_expiration. After the signed zone is approved
            // this value should be move to min_expiration.
            zone_state.min_expiration = zone_state.next_min_expiration;
            zone_state.next_min_expiration = None;
            zone.mark_dirty(&mut zone_state, &self.center);

            zone_state.policy.clone()
        };

        // Move the zone from the signed collection to the published collection.
        // TODO: Bump the zone serial?
        let signed_zones = self.center.signed_zones.load();
        if let Some(zone) = signed_zones.get_zone(&zone_name, Class::IN) {
            let published_zones = self.center.published_zones.load();

            // Create a deep copy of the set of
            // published zones. We will add the
            // new zone to that copied set and
            // then replace the original set with
            // the new set.
            info!("[{unit_name}]: Adding '{zone_name}' to the set of published zones.");
            let mut new_published_zones = Arc::unwrap_or_clone(published_zones.clone());
            let _ = new_published_zones.remove_zone(zone.apex_name(), zone.class());
            new_published_zones.insert_zone(zone.clone()).unwrap();
            self.center
                .published_zones
                .store(Arc::new(new_published_zones));

            // Create a deep copy of the set of
            // signed zones. We will remove the
            // zone from the copied set and then
            // replace the original set with the
            // new set.
            let mut new_signed_zones = Arc::unwrap_or_clone(signed_zones.clone());
            new_signed_zones.remove_zone(&zone_name, Class::IN).unwrap();
            self.center.signed_zones.store(Arc::new(new_signed_zones));
        }

        // Send NOTIFY if configured to do so.
        if let Some(policy) = policy {
            info!(
                "[{unit_name}]: Found {} NOTIFY targets",
                policy.server.outbound.send_notify_to.len()
            );
            if !policy.server.outbound.send_notify_to.is_empty() {
                let addrs = policy
                    .server
                    .outbound
                    .send_notify_to
                    .iter()
                    .filter_map(|s| {
                        if s.addr.port() != 0 {
                            Some(&s.addr)
                        } else {
                            None
                        }
                    });

                let maintainer_config =
                    Config::<_, DefaultConnFactory>::new(self.center.old_tsig_key_store.clone());
                let maintainer_config = Arc::new(ArcSwap::from_pointee(maintainer_config));
                ZoneMaintainer::send_notify_to_addrs(zone_name.clone(), addrs, maintainer_config)
                    .await;
            }
        }
    }

    async fn on_seek_approval_for_zone_cmd(
        &self,
        cmd: ApplicationCommand,
        unit_name: &'static str,
        update_tx: mpsc::UnboundedSender<Update>,
    ) -> Option<Result<(), Terminated>> {
        let (zone_name, zone_serial, zone_type) = match cmd {
            ApplicationCommand::SeekApprovalForUnsignedZone {
                zone_name,
                zone_serial,
            } => (zone_name, zone_serial, "unsigned"),
            ApplicationCommand::SeekApprovalForSignedZone {
                zone_name,
                zone_serial,
            } => (zone_name, zone_serial, "signed"),
            _ => unreachable!(),
        };

        // Remove any prior approval for this zone as we have been asked to
        // (re-)approve it.
        let _ = self
            .last_approvals
            .write()
            .await
            .remove(&(zone_name.clone(), zone_serial));

        let review = {
            let zone = get_zone(&self.center, &zone_name).unwrap();
            let zone_state = zone.state.lock().unwrap();
            let policy = zone_state.policy.as_ref().unwrap();
            match self.source {
                Source::UnsignedZones => policy.loader.review.clone(),
                Source::SignedZones => policy.signer.review.clone(),
                Source::PublishedZones => unreachable!(),
            }
        };

        let (review_server, pending_event) = {
            let state = self.center.state.lock().unwrap();
            let status = ZoneReviewStatus::Pending;
            match self.source {
                Source::UnsignedZones => (
                    state.config.loader.review.servers.first().cloned(),
                    HistoricalEvent::UnsignedZoneReview { status },
                ),
                Source::SignedZones => (
                    state.config.signer.review.servers.first().cloned(),
                    HistoricalEvent::SignedZoneReview { status },
                ),
                Source::PublishedZones => unreachable!(),
            }
        };

        if !review.required {
            // Approve immediately.
            match self.source {
                Source::UnsignedZones => {
                    info!("[{unit_name}]: Adding '{zone_name}' to the set of signable zones.");
                    if let Err(err) =
                        ZoneServer::promote_zone_to_signable(self.center.clone(), &zone_name)
                    {
                        error!("[{unit_name}]: Cannot promote unsigned zone '{zone_name}' to the signable set of zones: {err}");
                    } else {
                        update_tx
                            .send(Update::UnsignedZoneApprovedEvent {
                                zone_name: zone_name.clone(),
                                zone_serial,
                            })
                            .unwrap();
                    }
                }
                Source::SignedZones => {
                    update_tx
                        .send(Update::SignedZoneApprovedEvent {
                            zone_name: zone_name.clone(),
                            zone_serial,
                        })
                        .unwrap();
                }
                Source::PublishedZones => unreachable!(),
            }

            return None;
        };

        info!("[{unit_name}]: Seeking approval for {zone_type} zone '{zone_name}' at serial {zone_serial}.");

        self.pending_approvals
            .write()
            .await
            .insert((zone_name.clone(), zone_serial));

        record_zone_event(&self.center, &zone_name, pending_event, Some(zone_serial));

        if review.cmd_hook.is_none() || review_server.is_none() {
            match (review_server, review.cmd_hook) {
                (None, None) => warn!("[{unit_name}] Review required, but neither a review server nor a review hook is set; use the CLI to approve or reject the zone"),
                (None, Some(_)) => warn!("[{unit_name}] Review required, but no review server configured; use the CLI to approve or reject the zone"),
                (Some(_), None) => info!("[{unit_name}] No review hook set; waiting for manual review"),
                (Some(_), Some(_)) => unreachable!(),
            }
            info!("[{unit_name}]: Approve with command: cascade zone approve --{zone_type} {zone_name} {zone_serial}");
            info!("[{unit_name}]: Reject with command: cascade zone reject --{zone_type} {zone_name} {zone_serial}");
            return None;
        }

        let hook = review.cmd_hook.unwrap();
        let review_server = review_server.unwrap();

        // TODO: Windows support?
        // TODO: Set 'CASCADE_UNSIGNED_SERIAL' and 'CASCADE_UNSIGNED_SERVER'.
        match tokio::process::Command::new("sh")
            .args(["-c", &hook])
            .envs([
                ("CASCADE_ZONE", &*zone_name.to_string()),
                ("CASCADE_SERIAL", &*zone_serial.to_string()),
                ("CASCADE_SERVER", &*review_server.addr().to_string()),
                ("CASCADE_SERVER_IP", &*review_server.addr().ip().to_string()),
                (
                    "CASCADE_SERVER_PORT",
                    &*review_server.addr().port().to_string(),
                ),
            ])
            .spawn()
        {
            Ok(mut child) => {
                info!("[{unit_name}]: Executed hook '{hook}' for {zone_type} zone '{zone_name}' at serial {zone_serial}");

                // Wait for the child to complete.
                let update_tx = self.center.update_tx.clone();
                tokio::spawn(async move {
                    let status = match child.wait().await {
                        Ok(status) => status,
                        Err(error) => {
                            error!("[{unit_name}]: Failed to watch hook '{hook}': {error}");
                            return;
                        }
                    };

                    debug!("[{unit_name}]: Hook '{hook}' exited with status {status}");

                    let decision = match status.success() {
                        true => ZoneReviewDecision::Approve,
                        false => ZoneReviewDecision::Reject,
                    };

                    let _ = update_tx.send(Update::ReviewZone {
                        name: zone_name,
                        stage: match zone_type {
                            "unsigned" => ZoneReviewStage::Unsigned,
                            "signed" => ZoneReviewStage::Signed,
                            _ => unreachable!(),
                        },
                        serial: zone_serial,
                        decision,
                    });
                });
            }
            Err(err) => {
                error!("[{unit_name}]: Failed to execute hook '{hook}' for {zone_type} zone '{zone_name}' at serial {zone_serial}: {err}");
                self.pending_approvals
                    .write()
                    .await
                    .remove(&(zone_name.clone(), zone_serial));
            }
        }
        None
    }

    async fn on_zone_review_api_cmd(
        &self,
        unit_name: &str,
        zone_name: Name<Bytes>,
        zone_serial: Serial,
        approve: bool,
        tx: tokio::sync::oneshot::Sender<ZoneReviewResult>,
    ) {
        // This can fail if the caller doesn't care about the result.
        let _ = tx.send(
            self.zone_review_api
                .as_ref()
                .expect("This should have been setup on startup.")
                .process_request(unit_name, zone_name.clone(), zone_serial, approve)
                .await,
        );
    }

    fn promote_zone_to_signable(
        center: Arc<Center>,
        zone_name: &StoredName,
    ) -> Result<(), ZoneReviewError> {
        let unsigned_zones = center.unsigned_zones.load();
        let Some(zone) = unsigned_zones.get_zone(&zone_name, Class::IN) else {
            debug!("Cannot promote zone '{zone_name}' to signable: zone not found'");
            return Err(ZoneReviewError::NoSuchZone);
        };

        // Create a deep copy of the set of signable zones. We will add
        // the new zone to that copied set and then replace the original
        // set with the new set.
        let signable_zones = center.signable_zones.load();
        let mut new_signable_zones = Arc::unwrap_or_clone(signable_zones.clone());
        let _ = new_signable_zones.remove_zone(zone_name, Class::IN);
        new_signable_zones.insert_zone(zone.clone()).unwrap();
        center.signable_zones.store(Arc::new(new_signable_zones));

        Ok(())
    }
}

impl std::fmt::Debug for ZoneServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneLoader").finish()
    }
}

#[derive(Clone, Default)]
struct XfrDataProvidingZonesWrapper {
    zones: Arc<ArcSwap<ZoneTree>>,
    key_store: TsigKeyStore,
}

impl XfrDataProvider<Option<<TsigKeyStore as KeyStore>::Key>> for XfrDataProvidingZonesWrapper {
    type Diff = EmptyZoneDiff;

    fn request<Octs>(
        &self,
        req: &Request<Octs, Option<<TsigKeyStore as KeyStore>::Key>>,
        _diff_from: Option<domain::base::Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        domain::net::server::middleware::xfr::XfrData<Self::Diff>,
                        domain::net::server::middleware::xfr::XfrDataProviderError,
                    >,
                > + Sync
                + Send
                + '_,
        >,
    >
    where
        Octs: octseq::Octets + Send + Sync,
    {
        let res = req
            .message()
            .sole_question()
            .map_err(XfrDataProviderError::ParseError)
            .and_then(|q| {
                if let Some(zone) = self.zones.load().find_zone(q.qname(), q.qclass()) {
                    Ok(XfrData::new(zone.clone(), vec![], false))
                } else {
                    Err(XfrDataProviderError::UnknownZone)
                }
            });

        Box::pin(ready(res))
    }
}

impl KeyStore for XfrDataProvidingZonesWrapper {
    type Key = Key;

    fn get_key<N: ToName>(&self, name: &N, algorithm: Algorithm) -> Option<Self::Key> {
        self.key_store.get_key(name, algorithm)
    }
}

//----------- LoaderNotifier ---------------------------------------------------

/// A forwarder of NOTIFY messages to the zone loader.
#[derive(Clone, Debug)]
pub struct LoaderNotifier {
    /// Whether the forwarder is enabled.
    enabled: bool,

    /// A channel to propagate updates to Cascade.
    update_tx: mpsc::UnboundedSender<Update>,
}

impl Notifiable for LoaderNotifier {
    // TODO: Get the SOA serial in the NOTIFY message.
    fn notify_zone_changed(
        &self,
        class: Class,
        apex_name: &Name<Bytes>,
        serial: Option<Serial>,
        source: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Result<(), NotifyError>> + Sync + Send + '_>> {
        // Don't do anything if the notifier is disabled.
        if self.enabled && class == Class::IN {
            // Propagate a request for the zone refresh.
            let _ = self.update_tx.send(Update::RefreshZone {
                zone_name: apex_name.clone(),
                source: Some(source),
                serial,
            });
        }

        Box::pin(std::future::ready(Ok(())))
    }
}

#[derive(Clone)]
struct ZoneServerService {
    #[allow(dead_code)]
    zones: XfrDataProvidingZonesWrapper,
}

impl ZoneServerService {
    #[allow(dead_code)]
    fn new(zones: XfrDataProvidingZonesWrapper) -> Self {
        Self { zones }
    }
}

fn zone_server_service(
    request: Request<Vec<u8>, Option<<TsigKeyStore as KeyStore>::Key>>,
    zones: XfrDataProvidingZonesWrapper,
) -> ServiceResult<Vec<u8>> {
    let question = request.message().sole_question().unwrap();
    let zone = zones
        .zones
        .load()
        .find_zone(question.qname(), question.qclass())
        .map(|zone| zone.read());
    let answer = match zone {
        Some(zone) => {
            let qname = question.qname().to_bytes();
            let qtype = question.qtype();
            zone.query(qname, qtype).unwrap()
        }
        None => Answer::new(Rcode::NXDOMAIN),
    };

    let builder = mk_builder_for_target();
    let additional = answer.to_message(request.message(), builder);
    Ok(CallResult::new(additional))
}

// TODO: Should we expire old pending approvals, e.g. a hook script failed and
// they never got approved or rejected?
impl ZoneReviewApi {
    async fn process_request(
        &self,
        unit_name: &str,
        zone_name: Name<Bytes>,
        zone_serial: Serial,
        approve: bool,
    ) -> ZoneReviewResult {
        // Was this version of the zone pending review?
        let existed = {
            let mut approvals = self.pending_approvals.write().await;
            approvals.remove(&(zone_name.clone(), zone_serial))
        };

        if !existed {
            // TODO: Check whether the zone exists at all.
            debug!("[{unit_name}] Got a review for {zone_name}/{zone_serial}, but it was not pending review");
            return Err(ZoneReviewError::NotUnderReview);
        }

        if approve {
            let (zone_type, event) = match self.source {
                Source::UnsignedZones => {
                    info!("[{unit_name}]: Adding '{zone_name}' to the set of signable zones.");
                    ZoneServer::promote_zone_to_signable(self.center.clone(), &zone_name)?;

                    (
                        "unsigned",
                        Update::UnsignedZoneApprovedEvent {
                            zone_name: zone_name.clone(),
                            zone_serial,
                        },
                    )
                }
                Source::SignedZones => (
                    "signed",
                    Update::SignedZoneApprovedEvent {
                        zone_name: zone_name.clone(),
                        zone_serial,
                    },
                ),
                Source::PublishedZones => unreachable!(),
            };
            info!("Pending {zone_type} zone '{zone_name}' approved at serial {zone_serial}.");
            let approved_at = Instant::now();
            self.last_approvals
                .write()
                .await
                .entry((zone_name.clone(), zone_serial))
                .and_modify(|instant| *instant = approved_at)
                .or_insert(approved_at);
            self.update_tx.send(event).unwrap();
        } else {
            let (zone_type, event) = match self.source {
                Source::UnsignedZones => (
                    "unsigned",
                    Update::UnsignedZoneRejectedEvent {
                        zone_name: zone_name.clone(),
                        zone_serial,
                    },
                ),
                Source::SignedZones => (
                    "signed",
                    Update::SignedZoneRejectedEvent {
                        zone_name: zone_name.clone(),
                        zone_serial,
                    },
                ),
                Source::PublishedZones => unreachable!(),
            };
            info!("Pending {zone_type} zone '{zone_name}' rejected at serial {zone_serial}.");
            self.update_tx.send(event).unwrap();
        }

        Ok(ZoneReviewOutput {})
    }
}

//------------ ZoneReviewApi -------------------------------------------------

struct ZoneReviewApi {
    center: Arc<Center>,
    update_tx: mpsc::UnboundedSender<Update>,
    #[allow(clippy::type_complexity)]
    pending_approvals: Arc<RwLock<foldhash::HashSet<(Name<Bytes>, Serial)>>>,
    #[allow(clippy::type_complexity)]
    last_approvals: Arc<RwLock<foldhash::HashMap<(Name<Bytes>, Serial), Instant>>>,
    source: Source,
}

impl ZoneReviewApi {
    #[allow(clippy::type_complexity)]
    fn new(
        center: Arc<Center>,
        update_tx: mpsc::UnboundedSender<Update>,
        pending_approvals: Arc<RwLock<foldhash::HashSet<(Name<Bytes>, Serial)>>>,
        last_approvals: Arc<RwLock<foldhash::HashMap<(Name<Bytes>, Serial), Instant>>>,
        source: Source,
    ) -> Self {
        Self {
            center,
            update_tx,
            pending_approvals,
            last_approvals,
            source,
        }
    }
}
