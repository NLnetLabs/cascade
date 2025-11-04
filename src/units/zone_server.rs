use std::future::{ready, Future};
use std::marker::Sync;
use std::net::IpAddr;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
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
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

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

/// The source of a zone server.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// Loaded, unsigned zones that need review.
    Unsigned,

    /// Freshly signed zones that need review.
    Signed,

    /// Approved and published signed zones.
    Published,
}

fn spawn_servers<Svc>(
    unit_name: &'static str,
    socket_provider: &mut SocketProvider,
    source: Source,
    svc: Svc,
    servers: Vec<SocketConfig>,
) -> Result<(), String>
where
    Svc: Service<Vec<u8>, ()> + Clone,
{
    for sock_cfg in servers {
        if let SocketConfig::UDP { addr } | SocketConfig::TCPUDP { addr } = sock_cfg {
            info!("[{unit_name}]: Obtaining UDP socket for address {addr}");
            let sock = socket_provider
                .take_udp(&addr)
                .ok_or(format!("No socket available for UDP {addr}"))?;
            tokio::spawn(serve_on_udp(svc.clone(), VecBufSource, sock));
        }

        if let SocketConfig::TCP { addr } | SocketConfig::TCPUDP { addr } = sock_cfg {
            info!("[{unit_name}]: Obtaining TCP listener for address {addr}");
            let sock = socket_provider
                .take_tcp(&addr)
                .ok_or(format!("No socket available for TCP {addr}"))?;
            tokio::spawn(serve_on_tcp(svc.clone(), VecBufSource, sock));
        }
    }

    if matches!(source, Source::Published) {
        // Also listen on any remaining UDP and TCP sockets provided by
        // the O/S.
        while let Some(sock) = socket_provider.pop_udp() {
            let addr = sock
                .local_addr()
                .map_err(|err| format!("Provided UDP socket lacks address: {err}"))?;
            info!("[{unit_name}]: Receieved additional UDP socket {addr}");
            tokio::spawn(serve_on_udp(svc.clone(), VecBufSource, sock));
        }
        while let Some(sock) = socket_provider.pop_tcp() {
            let addr = sock
                .local_addr()
                .map_err(|err| format!("Provided TCP listener lacks address: {err}"))?;
            info!("[{unit_name}]: Receieved additional TCP listener {addr}");
            tokio::spawn(serve_on_tcp(svc.clone(), VecBufSource, sock));
        }
    }

    Ok(())
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

pub struct ZoneServer {
    center: Arc<Center>,
    zone_review_api: ZoneReviewApi,
    source: Source,
    #[allow(clippy::type_complexity)]
    pending_approvals: Arc<RwLock<foldhash::HashSet<(Name<Bytes>, Serial)>>>,
    #[allow(clippy::type_complexity)]
    last_approvals: Arc<RwLock<foldhash::HashMap<(Name<Bytes>, Serial), Instant>>>,
}

impl ZoneServer {
    /// Launch a zone server.
    pub fn launch(
        center: Arc<Center>,
        source: Source,
        socket_provider: &mut SocketProvider,
    ) -> Result<Self, Terminated> {
        let unit_name = match source {
            Source::Unsigned => "RS",
            Source::Signed => "RS2",
            Source::Published => "PS",
        };

        // TODO: metrics and status reporting

        // TODO: This will just choose all current zones to be served. For signed and published
        // zones this doesn't matter so much as they only exist while being and once approved.
        // But for unsigned zones the zone could be updated whilst being reviewed and we only
        // serve the latest version of the zone, not the specific serial being reviewed!
        let zones = match source {
            Source::Unsigned => center.unsigned_zones.clone(),
            Source::Signed => center.signed_zones.clone(),
            Source::Published => center.published_zones.clone(),
        };

        let max_concurrency = std::thread::available_parallelism()
            .unwrap()
            .get()
            .div_ceil(2);

        // TODO: Pass xfr_out to XfrDataProvidingZonesWrapper for enforcement.
        let zones = XfrDataProvidingZonesWrapper {
            zones,
            key_store: center.old_tsig_key_store.clone(),
        };

        // Propagate NOTIFY messages if this is the publication server.
        let notifier = LoaderNotifier {
            enabled: matches!(source, Source::Published),
            update_tx: center.update_tx.clone(),
        };

        // let svc = ZoneServerService::new(zones.clone());
        let svc = service_fn(zone_server_service, zones.clone());
        let svc = XfrMiddlewareSvc::new(svc, zones.clone(), max_concurrency);
        let svc = NotifyMiddlewareSvc::new(svc, notifier);
        let svc = TsigMiddlewareSvc::new(svc, center.old_tsig_key_store.clone());
        let svc = CookiesMiddlewareSvc::with_random_secret(svc);
        let svc = EdnsMiddlewareSvc::new(svc);
        let svc = MandatoryMiddlewareSvc::<_, _, ()>::new(svc);
        let svc = Arc::new(svc);

        let servers = {
            let state = center.state.lock().unwrap();
            let config = &state.config;
            let servers = match source {
                Source::Unsigned => &config.loader.review.servers,
                Source::Signed => &config.signer.review.servers,
                Source::Published => &config.server.servers,
            };
            servers.clone()
        };

        spawn_servers(unit_name, socket_provider, source, svc, servers)
            .inspect_err(|err| error!("[{unit_name}]: Spawning nameservers failed: {err}"))
            .map_err(|_| Terminated)?;

        let pending_approvals = <Arc<RwLock<_>>>::default();
        let last_approvals = <Arc<RwLock<_>>>::default();

        let zone_review_api = ZoneReviewApi {
            center: center.clone(),
            update_tx: center.update_tx.clone(),
            pending_approvals: pending_approvals.clone(),
            last_approvals: last_approvals.clone(),
            source,
        };

        Ok(Self {
            center,
            zone_review_api,
            source,
            pending_approvals,
            last_approvals,
        })
    }

    /// Respond to an application command.
    pub async fn on_command(&self, cmd: ApplicationCommand) -> Result<(), Terminated> {
        let unit_name = match self.source {
            Source::Unsigned => "RS",
            Source::Signed => "RS2",
            Source::Published => "PS",
        };

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
                self.on_seek_approval_for_zone_cmd(cmd, unit_name, self.center.update_tx.clone())
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
                Source::Unsigned => policy.loader.review.clone(),
                Source::Signed => policy.signer.review.clone(),
                Source::Published => unreachable!(),
            }
        };

        let (review_server, pending_event) = {
            let state = self.center.state.lock().unwrap();
            let status = ZoneReviewStatus::Pending;
            match self.source {
                Source::Unsigned => (
                    state.config.loader.review.servers.first().cloned(),
                    HistoricalEvent::UnsignedZoneReview { status },
                ),
                Source::Signed => (
                    state.config.signer.review.servers.first().cloned(),
                    HistoricalEvent::SignedZoneReview { status },
                ),
                Source::Published => unreachable!(),
            }
        };

        if !review.required {
            // Approve immediately.
            match self.source {
                Source::Unsigned => {
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
                Source::Signed => {
                    update_tx
                        .send(Update::SignedZoneApprovedEvent {
                            zone_name: zone_name.clone(),
                            zone_serial,
                        })
                        .unwrap();
                }
                Source::Published => unreachable!(),
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
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                info!("[{unit_name}]: Executed hook '{hook}' for {zone_type} zone '{zone_name}' at serial {zone_serial}");

                // Wait for the child to complete.
                let update_tx = self.center.update_tx.clone();
                let stdout = child.stdout.take().expect("we use Stdio::piped");
                let stderr = child.stderr.take().expect("we use Stdio::piped");

                tokio::spawn(async move {
                    let _: Result<_, _> = Self::process_output(stdout, false).await;
                });
                tokio::spawn(async move {
                    let _: Result<_, _> = Self::process_output(stderr, true).await;
                });
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

    async fn process_output(
        pipe: impl tokio::io::AsyncRead + Unpin,
        is_warn: bool,
    ) -> Result<(), std::io::Error> {
        use tokio::io::{AsyncBufReadExt, BufReader};

        let pipe = BufReader::new(pipe);
        let mut lines = pipe.lines();
        while let Some(line) = lines.next_line().await? {
            if is_warn {
                warn!("{}", line);
            } else {
                info!("{}", line);
            }
        }
        Ok(())
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
                Source::Unsigned => {
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
                Source::Signed => (
                    "signed",
                    Update::SignedZoneApprovedEvent {
                        zone_name: zone_name.clone(),
                        zone_serial,
                    },
                ),
                Source::Published => unreachable!(),
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
                Source::Unsigned => (
                    "unsigned",
                    Update::UnsignedZoneRejectedEvent {
                        zone_name: zone_name.clone(),
                        zone_serial,
                    },
                ),
                Source::Signed => (
                    "signed",
                    Update::SignedZoneRejectedEvent {
                        zone_name: zone_name.clone(),
                        zone_serial,
                    },
                ),
                Source::Published => unreachable!(),
            };
            info!("Pending {zone_type} zone '{zone_name}' rejected at serial {zone_serial}.");
            self.update_tx.send(event).unwrap();
        }

        Ok(ZoneReviewOutput {})
    }
}
