use std::future::{Future, ready};
use std::marker::Sync;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use domain::base::iana::{Class, Opcode, Rcode};
use domain::base::{MessageBuilder, Name, Rtype, Serial, ToName};
use domain::net::client::dgram::Connection;
use domain::net::client::protocol::UdpConnect;
use domain::net::client::request::{RequestMessage, SendRequest};
use domain::net::server::ConnectionConfig;
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
use domain::tsig::KeyStore;
use domain::tsig::{Algorithm, Key};
use domain::zonetree::Answer;
use domain::zonetree::types::EmptyZoneDiff;
use domain::zonetree::{StoredName, ZoneTree};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::api::{
    ZoneReviewDecision, ZoneReviewError, ZoneReviewOutput, ZoneReviewResult, ZoneReviewStage,
    ZoneReviewStatus,
};
use crate::center::{Center, get_zone};
use crate::common::tsig::TsigKeyStore;
use crate::config::SocketConfig;
use crate::daemon::SocketProvider;
use crate::manager::record_zone_event;
use crate::manager::{ApplicationCommand, Terminated, Update};
use crate::util::AbortOnDrop;
use crate::zone::{
    HistoricalEvent, SignedZoneVersionState, UnsignedZoneVersionState, ZoneVersionReviewState,
};

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
    servers: &[SocketConfig],
) -> Result<Vec<AbortOnDrop>, String>
where
    Svc: Service<Vec<u8>, ()> + Clone,
{
    let mut handles = Vec::new();

    for sock_cfg in servers {
        if let SocketConfig::UDP { addr } | SocketConfig::TCPUDP { addr } = sock_cfg {
            info!("[{unit_name}]: Obtaining UDP socket for address {addr}");
            let sock = socket_provider
                .take_udp(addr)
                .ok_or(format!("No socket available for UDP {addr}"))?;
            handles.push(AbortOnDrop::from(tokio::spawn(serve_on_udp(
                svc.clone(),
                VecBufSource,
                sock,
            ))));
        }

        if let SocketConfig::TCP { addr } | SocketConfig::TCPUDP { addr } = sock_cfg {
            info!("[{unit_name}]: Obtaining TCP listener for address {addr}");
            let sock = socket_provider
                .take_tcp(addr)
                .ok_or(format!("No socket available for TCP {addr}"))?;
            handles.push(AbortOnDrop::from(tokio::spawn(serve_on_tcp(
                svc.clone(),
                VecBufSource,
                sock,
            ))));
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
            handles.push(AbortOnDrop::from(tokio::spawn(serve_on_udp(
                svc.clone(),
                VecBufSource,
                sock,
            ))));
        }
        while let Some(sock) = socket_provider.pop_tcp() {
            let addr = sock
                .local_addr()
                .map_err(|err| format!("Provided TCP listener lacks address: {err}"))?;
            info!("[{unit_name}]: Receieved additional TCP listener {addr}");
            handles.push(AbortOnDrop::from(tokio::spawn(serve_on_tcp(
                svc.clone(),
                VecBufSource,
                sock,
            ))));
        }
    }

    Ok(handles)
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
    source: Source,
}

impl ZoneServer {
    pub fn new(source: Source) -> Self {
        Self { source }
    }

    /// Launch a zone server.
    pub fn run(
        center: Arc<Center>,
        source: Source,
        socket_provider: &mut SocketProvider,
    ) -> Result<Vec<AbortOnDrop>, Terminated> {
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

        let servers = match source {
            Source::Unsigned => &center.config.loader.review.servers,
            Source::Signed => &center.config.signer.review.servers,
            Source::Published => &center.config.server.servers,
        };

        let handles = spawn_servers(unit_name, socket_provider, source, svc, servers)
            .inspect_err(|err| error!("[{unit_name}]: Spawning nameservers failed: {err}"))
            .map_err(|_| Terminated)?;

        Ok(handles)
    }

    /// Respond to an application command.
    pub fn on_command(
        &self,
        center: &Arc<Center>,
        cmd: ApplicationCommand,
    ) -> Result<(), Terminated> {
        let unit_name = match self.source {
            Source::Unsigned => "RS",
            Source::Signed => "RS2",
            Source::Published => "PS",
        };

        debug!("[{unit_name}] Received command: {cmd:?}",);
        match cmd {
            ApplicationCommand::ReviewZone {
                name,
                serial,
                decision,
                tx,
            } => {
                self.on_zone_review_api_cmd(
                    center,
                    unit_name,
                    name,
                    serial,
                    matches!(decision, ZoneReviewDecision::Approve),
                    tx,
                );
            }

            ApplicationCommand::SeekApprovalForUnsignedZone { .. }
            | ApplicationCommand::SeekApprovalForSignedZone { .. } => {
                self.on_seek_approval_for_zone_cmd(
                    center,
                    cmd,
                    unit_name,
                    center.update_tx.clone(),
                );
            }

            ApplicationCommand::PublishSignedZone {
                zone_name,
                zone_serial,
            } => {
                self.on_publish_signed_zone_cmd(center, unit_name, zone_name, zone_serial);
            }

            _ => { /* Not for us */ }
        }

        Ok(())
    }

    fn on_publish_signed_zone_cmd(
        &self,
        center: &Arc<Center>,
        unit_name: &str,
        zone_name: Name<Bytes>,
        zone_serial: Serial,
    ) {
        info!("[{unit_name}]: Publishing signed zone '{zone_name}' at serial {zone_serial}.");

        // Move next_min_expiration to min_expiration, and determine policy.
        let policy = {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone = get_zone(center, &zone_name).unwrap();
            let mut zone_state = zone.state.lock().unwrap();

            // Save as next_min_expiration. After the signed zone is approved
            // this value should be move to min_expiration.
            zone_state.min_expiration = zone_state.next_min_expiration;
            zone_state.next_min_expiration = None;
            zone.mark_dirty(&mut zone_state, center);

            zone_state.policy.clone()
        };

        // Move the zone from the signed collection to the published collection.
        // TODO: Bump the zone serial?
        let signed_zones = center.signed_zones.load();
        if let Some(zone) = signed_zones.get_zone(&zone_name, Class::IN) {
            // Create a deep copy of the set of
            // published zones. We will add the
            // new zone to that copied set and
            // then replace the original set with
            // the new set.
            info!("[{unit_name}]: Adding '{zone_name}' to the set of published zones.");
            center.published_zones.rcu(|zones| {
                let mut new_published_zones = Arc::unwrap_or_clone(zones.clone());
                let _ = new_published_zones.remove_zone(zone.apex_name(), zone.class());
                new_published_zones.insert_zone(zone.clone()).unwrap();
                new_published_zones
            });

            // Create a deep copy of the set of
            // signed zones. We will remove the
            // zone from the copied set and then
            // replace the original set with the
            // new set.
            center.signed_zones.rcu(|zones| {
                let mut new_signed_zones = Arc::unwrap_or_clone(zones.clone());
                new_signed_zones.remove_zone(&zone_name, Class::IN).unwrap();
                new_signed_zones
            });
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
                            Some(s.addr)
                        } else {
                            None
                        }
                    });

                send_notify_to_addrs(zone_name.clone(), addrs, &center.old_tsig_key_store);
            }
        }
    }

    fn on_seek_approval_for_zone_cmd(
        &self,
        center: &Arc<Center>,
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

        let zone = get_zone(center, &zone_name).unwrap();

        let review = {
            let zone_state = zone.state.lock().unwrap();
            let policy = zone_state.policy.as_ref().unwrap();
            match self.source {
                Source::Unsigned => policy.loader.review.clone(),
                Source::Signed => policy.signer.review.clone(),
                Source::Published => unreachable!(),
            }
        };

        let (review_server, pending_event) = {
            let status = ZoneReviewStatus::Pending;
            match self.source {
                Source::Unsigned => (
                    center.config.loader.review.servers.first().cloned(),
                    HistoricalEvent::UnsignedZoneReview { status },
                ),
                Source::Signed => (
                    center.config.signer.review.servers.first().cloned(),
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
                        ZoneServer::promote_zone_to_signable(center.clone(), &zone_name)
                    {
                        error!(
                            "[{unit_name}]: Cannot promote unsigned zone '{zone_name}' to the signable set of zones: {err}"
                        );
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

        info!(
            "[{unit_name}]: Seeking approval for {zone_type} zone '{zone_name}' at serial {zone_serial}."
        );

        // Mark this version of the zone as pending approval.
        //
        // TODO: These entries should have been created a long time ago, but
        // not all components use these fields yet.  For now, they need to be
        // created over here -- hence 'or_insert_with()'.
        {
            let mut zone_state = zone.state.lock().unwrap();
            match self.source {
                Source::Unsigned => {
                    zone_state
                        .unsigned
                        .entry(zone_serial)
                        .or_insert_with(|| UnsignedZoneVersionState {
                            review: Default::default(),
                        })
                        .review = ZoneVersionReviewState::Pending;
                }
                Source::Signed => {
                    zone_state
                        .signed
                        .entry(zone_serial)
                        .or_insert_with(|| SignedZoneVersionState {
                            unsigned_serial: Serial::from(0), // TODO
                            review: Default::default(),
                        })
                        .review = ZoneVersionReviewState::Pending;
                }
                Source::Published => unreachable!(),
            }
        }

        record_zone_event(center, &zone_name, pending_event, Some(zone_serial));

        if review.cmd_hook.is_none() || review_server.is_none() {
            match (review_server, review.cmd_hook) {
                (None, None) => warn!(
                    "[{unit_name}] Review required, but neither a review server nor a review hook is set; use the CLI to approve or reject the zone"
                ),
                (None, Some(_)) => warn!(
                    "[{unit_name}] Review required, but no review server configured; use the CLI to approve or reject the zone"
                ),
                (Some(_), None) => {
                    info!("[{unit_name}] No review hook set; waiting for manual review")
                }
                (Some(_), Some(_)) => unreachable!(),
            }
            info!(
                "[{unit_name}]: Approve with command: cascade zone approve --{zone_type} {zone_name} {zone_serial}"
            );
            info!(
                "[{unit_name}]: Reject with command: cascade zone reject --{zone_type} {zone_name} {zone_serial}"
            );
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
                info!(
                    "[{unit_name}]: Executed hook '{hook}' for {zone_type} zone '{zone_name}' at serial {zone_serial}"
                );

                // Wait for the child to complete.
                let update_tx = center.update_tx.clone();
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
                error!(
                    "[{unit_name}]: Failed to execute hook '{hook}' for {zone_type} zone '{zone_name}' at serial {zone_serial}: {err}"
                );

                {
                    let mut zone_state = zone.state.lock().unwrap();
                    match self.source {
                        Source::Unsigned => {
                            zone_state.unsigned.get_mut(&zone_serial).unwrap().review =
                                ZoneVersionReviewState::Rejected;
                        }
                        Source::Signed => {
                            zone_state.signed.get_mut(&zone_serial).unwrap().review =
                                ZoneVersionReviewState::Rejected;
                        }
                        Source::Published => unreachable!(),
                    }
                }
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

    fn on_zone_review_api_cmd(
        &self,
        center: &Arc<Center>,
        unit_name: &str,
        zone_name: Name<Bytes>,
        zone_serial: Serial,
        approve: bool,
        tx: tokio::sync::oneshot::Sender<ZoneReviewResult>,
    ) {
        // Look up the zone.
        let Some(zone) = get_zone(center, &zone_name) else {
            debug!(
                "[{unit_name}] Got a review for {zone_name}/{zone_serial}, but the zone does not exist"
            );
            let _ = tx.send(Err(ZoneReviewError::NoSuchZone));
            return;
        };

        let new_review_state = if approve {
            ZoneVersionReviewState::Approved
        } else {
            ZoneVersionReviewState::Rejected
        };

        // Look up the version of the zone being reviewed.
        match self.source {
            Source::Unsigned => {
                {
                    let mut zone_state = zone.state.lock().unwrap();
                    let Some(version) = zone_state.unsigned.get_mut(&zone_serial) else {
                        // 'on_seek_approval_for_zone_cmd()' should have created
                        // this.  Since it doesn't exist, the zone is not under
                        // review.

                        debug!(
                            "[{unit_name}] Got a review for {zone_name}/{zone_serial}, but it was not pending review"
                        );
                        let _ = tx.send(Err(ZoneReviewError::NotUnderReview));
                        return;
                    };

                    // Check that the zone was not already approved.
                    if matches!(version.review, ZoneVersionReviewState::Approved) {
                        // This version of the zone is no longer being reviewed.
                        //
                        // TODO: Differentiate this from 'NotUnderReview'?

                        let _ = tx.send(Err(ZoneReviewError::NotUnderReview));
                        return;
                    }

                    version.review = new_review_state;
                }
                if approve {
                    info!(
                        "Unsigned zone '{zone_name}' with serial {zone_serial} has been approved."
                    );
                    match Self::promote_zone_to_signable(center.clone(), &zone_name) {
                        Ok(()) => {
                            let _ = center.update_tx.send(Update::UnsignedZoneApprovedEvent {
                                zone_name,
                                zone_serial,
                            });
                        }
                        Err(err) => {
                            error!(
                                "Ignoring approval for '{zone_name}': zone could not be promoted to signable: {err}"
                            );
                        }
                    }
                } else {
                    error!(
                        "Unsigned zone '{zone_name}' with serial {zone_serial} has been rejected."
                    );
                }
            }

            Source::Signed => {
                {
                    let mut zone_state = zone.state.lock().unwrap();
                    let Some(version) = zone_state.signed.get_mut(&zone_serial) else {
                        // 'on_seek_approval_for_zone_cmd()' should have created
                        // this.  Since it doesn't exist, the zone is not under
                        // review.

                        debug!(
                            "[{unit_name}] Got a review for {zone_name}/{zone_serial}, but it was not pending review"
                        );
                        let _ = tx.send(Err(ZoneReviewError::NotUnderReview));
                        return;
                    };

                    // Check that the zone was not already approved.
                    if matches!(version.review, ZoneVersionReviewState::Approved) {
                        // This version of the zone is no longer being reviewed.
                        //
                        // TODO: Differentiate this from 'NotUnderReview'?

                        let _ = tx.send(Err(ZoneReviewError::NotUnderReview));
                        return;
                    }

                    version.review = new_review_state;
                }
                if approve {
                    info!("Signed zone '{zone_name}' with serial {zone_serial} has been approved.");
                    let _ = center.update_tx.send(Update::SignedZoneApprovedEvent {
                        zone_name,
                        zone_serial,
                    });
                } else {
                    error!(
                        "Signed zone '{zone_name}' with serial {zone_serial} has been rejected."
                    );
                }
            }

            Source::Published => unreachable!(),
        };

        let _ = tx.send(Ok(ZoneReviewOutput {}));
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
        debug!("Promoting '{zone_name}' to signable");
        center.signable_zones.rcu(|zones| {
            let mut new_signable_zones = Arc::unwrap_or_clone(zones.clone());
            let _ = new_signable_zones.remove_zone(zone_name, Class::IN);
            new_signable_zones.insert_zone(zone.clone()).unwrap();
            new_signable_zones
        });

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
        _serial: Option<Serial>,
        _source: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Result<(), NotifyError>> + Sync + Send + '_>> {
        // Don't do anything if the notifier is disabled.
        if self.enabled && class == Class::IN {
            // Propagate a request for the zone refresh.
            // This request ignores the serial and source because we will just
            // do a SOA query to our configured upstreams.
            let _ = self.update_tx.send(Update::RefreshZone {
                zone_name: apex_name.clone(),
            });
        }

        Box::pin(std::future::ready(Ok(())))
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

pub fn send_notify_to_addrs(
    apex_name: StoredName,
    notify_set: impl Iterator<Item = SocketAddr>,
    _key_store: &TsigKeyStore,
) {
    let mut dgram_config = domain::net::client::dgram::Config::new();
    dgram_config.set_max_parallel(1);
    dgram_config.set_read_timeout(Duration::from_millis(1000));
    dgram_config.set_max_retries(1);
    dgram_config.set_udp_payload_size(Some(1400));

    let mut msg = MessageBuilder::new_vec();
    msg.header_mut().set_opcode(Opcode::NOTIFY);
    let mut msg = msg.question();
    msg.push((apex_name, Rtype::SOA)).unwrap();

    for nameserver_addr in notify_set {
        let dgram_config = dgram_config.clone();
        let req = RequestMessage::new(msg.clone()).unwrap();

        // let tsig_key = zone_info
        //     .config
        //     .send_notify_to
        //     .dst(&nameserver_addr)
        //     .and_then(|cfg| cfg.tsig_key.as_ref())
        //     .and_then(|(name, alg)| key_store.get_key(name, *alg));
        //
        // if let Some(key) = tsig_key.as_ref() {
        //     debug!(
        //         "Found TSIG key '{}' (algorith {}) for NOTIFY to {nameserver_addr}",
        //         key.as_ref().name(),
        //         key.as_ref().algorithm()
        //     );
        // }

        tokio::spawn(async move {
            // TODO: Use the connection factory here.
            let udp_connect = UdpConnect::new(nameserver_addr);
            let client = Connection::with_config(udp_connect, dgram_config.clone());

            trace!("Sending NOTIFY to nameserver {nameserver_addr}");
            let span = tracing::trace_span!("auth", addr = %nameserver_addr);
            let _guard = span.enter();

            // https://datatracker.ietf.org/doc/html/rfc1996
            //   "4.8 Master Receives a NOTIFY Response from Slave
            //
            //    When a master server receives a NOTIFY response, it deletes this
            //    query from the retry queue, thus completing the "notification
            //    process" of "this" RRset change to "that" server."
            //
            // TODO: We have no retry queue at the moment. Do we need one?

            // let res = if let Some(key) = tsig_key {
            //     let client = net::client::tsig::Connection::new(key.clone(), client);
            //     client.send_request(req.clone()).get_response().await
            // } else {
            //     client.send_request(req.clone()).get_response().await
            // };
            let res = client.send_request(req.clone()).get_response().await;

            if let Err(err) = res {
                warn!("Unable to send NOTIFY to nameserver {nameserver_addr}: {err}");
            }
        });
    }
}
