use std::future::Future;
use std::marker::Sync;
use std::net::IpAddr;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use domain::base::iana::{Class, Opcode};
use domain::base::{MessageBuilder, Name, Rtype, Serial, ToName};
use domain::net::client::dgram::Connection;
use domain::net::client::protocol::UdpConnect;
use domain::net::client::request::{RequestMessage, SendRequest};
use domain::net::server::ConnectionConfig;
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::{self, DgramServer};
use domain::net::server::middleware::cookies::CookiesMiddlewareSvc;
use domain::net::server::middleware::edns::EdnsMiddlewareSvc;
use domain::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use domain::net::server::middleware::notify::{Notifiable, NotifyError, NotifyMiddlewareSvc};
use domain::net::server::middleware::tsig::TsigMiddlewareSvc;
use domain::net::server::service::Service;
use domain::net::server::stream::{self, StreamServer};
use domain::tsig::{Algorithm, KeyStore};
use domain::zonetree::StoredName;
use tracing::{debug, error, info, trace, warn};

use crate::api::{
    ZoneReviewDecision, ZoneReviewError, ZoneReviewOutput, ZoneReviewResult, ZoneReviewStatus,
};
use crate::center::Center;
use crate::config::SocketConfig;
use crate::daemon::SocketProvider;
use crate::manager::Terminated;
use crate::manager::record_zone_event;
use crate::policy::{NameserverCommsPolicy, OnReject, ReviewMode};
use crate::server::{LoadedReviewServer, PublicationServer, SignedReviewServer};
use crate::util::AbortOnDrop;
use crate::zone::{
    HistoricalEvent, SignedZoneVersionState, UnsignedZoneVersionState, Zone, ZoneVersionReviewState,
};
use crate::zonedata::{OldRecord, SoaRecord};

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
            info!("Obtaining UDP socket for address {addr}");
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
            info!("Obtaining TCP listener for address {addr}");
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
            info!("Receieved additional UDP socket {addr}");
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
            info!("Receieved additional TCP listener {addr}");
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
    pub fn run<S>(
        center: &Arc<Center>,
        source: Source,
        socket_provider: &mut SocketProvider,
        service: S,
    ) -> Result<Vec<AbortOnDrop>, Terminated>
    where
        S: Service<Vec<u8>, Option<Arc<domain::tsig::Key>>> + Unpin + Clone,
        S::Future: Unpin + Sync,
        S::Stream: Sync,
    {
        let unit_name = match source {
            Source::Unsigned => "RS",
            Source::Signed => "RS2",
            Source::Published => "PS",
        };

        // TODO: metrics and status reporting

        // Propagate NOTIFY messages if this is the publication server.
        let notifier = LoaderNotifier {
            enabled: matches!(source, Source::Published),
            center: center.clone(),
        };

        let svc = service;
        let svc = NotifyMiddlewareSvc::new(svc, notifier);
        let svc = CookiesMiddlewareSvc::with_random_secret(svc);
        let svc = EdnsMiddlewareSvc::new(svc);
        let svc = TsigMiddlewareSvc::new(svc, CenterKeyStore(center.clone()));
        let svc = MandatoryMiddlewareSvc::<_, _, ()>::new(svc);
        let svc = Arc::new(svc);

        let servers = match source {
            Source::Unsigned => &center.config.loader.review.servers,
            Source::Signed => &center.config.signer.review.servers,
            Source::Published => &center.config.server.servers,
        };

        let handles = spawn_servers(socket_provider, source, svc, servers)
            .inspect_err(|err| error!("[{unit_name}]: Spawning nameservers failed: {err}"))
            .map_err(|_| Terminated)?;

        Ok(handles)
    }

    fn unit_name(&self) -> &'static str {
        match self.source {
            Source::Unsigned => "RS",
            Source::Signed => "RS2",
            Source::Published => "PS",
        }
    }

    pub fn on_publish_signed_zone(
        &self,
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        zone_serial: Serial,
    ) {
        let unit_name = self.unit_name();
        let zone_name = &zone.name;
        info!("[{unit_name}]: Publishing signed zone '{zone_name}' at serial {zone_serial}.",);

        // Move next_min_expiration to min_expiration, and determine policy.
        let (policy, soa) = {
            // Use a block to make sure that the lock is clearly dropped.
            let mut zone_state = zone.write(center);

            // Save as next_min_expiration. After the signed zone is approved
            // this value should be move to min_expiration.
            zone_state.min_expiration = zone_state.next_min_expiration;
            zone_state.next_min_expiration = None;

            (
                zone_state.policy.clone(),
                zone_state.storage.signed_review_soa.clone().unwrap(),
            )
        };

        // Send NOTIFY if configured to do so.
        if let Some(policy) = policy {
            info!(
                "[{unit_name}]: Found {} NOTIFY targets",
                policy.server.outbound.send_notify_to.len()
            );
            trace!(
                "NOTIFY targets: {:?}",
                policy.server.outbound.send_notify_to
            );
            if !policy.server.outbound.send_notify_to.is_empty() {
                let addrs = policy
                    .server
                    .outbound
                    .send_notify_to
                    .iter()
                    .filter(|s| s.addr.port() != 0);

                send_notify_to_addrs(zone_name.clone(), soa.clone(), addrs, center);
            }
        }
    }

    pub fn on_seek_approval_for_zone(
        &self,
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        zone_serial: Serial,
    ) -> Option<Result<(), Terminated>> {
        let unit_name = self.unit_name();
        let zone_type = match self.source {
            Source::Unsigned => "unsigned",
            Source::Signed => "signed",
            Source::Published => unreachable!(),
        };

        let review = {
            let zone_state = zone.read();
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

        let zone_name = &zone.name;
        match review.mode {
            ReviewMode::Off => {
                // Approve immediately.
                match self.source {
                    Source::Unsigned => {
                        info!("[{unit_name}]: Adding '{zone_name}' to the set of signable zones.");
                        self.on_unsigned_zone_approved(center, zone, zone_serial);
                    }
                    Source::Signed => {
                        self.on_signed_zone_approved(center, zone, zone_serial);
                    }
                    Source::Published => unreachable!(),
                }
                return None;
            }
            ReviewMode::Manual => {
                info!(
                    "[{unit_name}]: Seeking approval for {zone_type} zone '{zone_name}' at serial {zone_serial}."
                );
                info!(
                    "[{unit_name}] Manual review required; use the CLI to approve or reject the zone"
                );
                info!(
                    "[{unit_name}]: Approve with command: cascade zone approve --{zone_type} {zone_name} {zone_serial}"
                );
                info!(
                    "[{unit_name}]: Reject with command: cascade zone reject --{zone_type} {zone_name} {zone_serial}"
                );
            }
            ReviewMode::Script { .. } => {
                info!(
                    "[{unit_name}]: Seeking approval for {zone_type} zone '{zone_name}' at serial {zone_serial}."
                );
            }
        };

        // Mark this version of the zone as pending approval.
        //
        // TODO: These entries should have been created a long time ago, but
        // not all components use these fields yet.  For now, they need to be
        // created over here -- hence 'or_insert_with()'.
        {
            let mut zone_state = zone.write(center);
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

        record_zone_event(center, zone, pending_event, Some(zone_serial));

        let ReviewMode::Script { hook } = review.mode else {
            // The only other case is ReviewMode::Manual, in which case we don't
            // need to do anything here anymore.
            return None;
        };
        let Some(review_server) = review_server else {
            warn!(
                "[{unit_name}]: No review server has been specified, so the review script won't be executed. Approve or reject with the CLI instead."
            );
            return None;
        };

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
                let center = center.clone();
                let stdout = child.stdout.take().expect("we use Stdio::piped");
                let stderr = child.stderr.take().expect("we use Stdio::piped");

                tokio::spawn(async move {
                    let _: Result<_, _> = Self::process_output(stdout, false).await;
                });
                tokio::spawn(async move {
                    let _: Result<_, _> = Self::process_output(stderr, true).await;
                });
                let zone = zone.clone();
                let source = self.source;
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

                    match source {
                        Source::Unsigned => {
                            let _ = LoadedReviewServer::process_review(
                                &center,
                                &zone,
                                zone_serial,
                                decision,
                            );
                        }
                        Source::Signed => {
                            let _ = SignedReviewServer::process_review(
                                &center,
                                &zone,
                                zone_serial,
                                decision,
                            );
                        }
                        Source::Published => unreachable!(),
                    };
                });
            }
            Err(err) => {
                error!(
                    "[{unit_name}]: Failed to execute hook '{hook}' for {zone_type} zone '{zone_name}' at serial {zone_serial}: {err}"
                );

                {
                    let mut zone_state = zone.write(center);
                    match self.source {
                        Source::Unsigned => {
                            zone_state.record_event(
                                HistoricalEvent::UnsignedHookFailed {
                                    err: err.to_string(),
                                },
                                Some(zone_serial),
                            );
                            zone_state.unsigned.get_mut(&zone_serial).unwrap().review =
                                ZoneVersionReviewState::Rejected;
                        }
                        Source::Signed => {
                            zone_state.record_event(
                                HistoricalEvent::SignedHookFailed {
                                    err: err.to_string(),
                                },
                                Some(zone_serial),
                            );
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

    fn on_unsigned_zone_approved(
        &self,
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        zone_serial: Serial,
    ) {
        let _ = zone_serial; // TODO
        zone.write_handle(center).get().approve_loaded();
    }

    fn on_signed_zone_approved(&self, center: &Arc<Center>, zone: &Arc<Zone>, zone_serial: Serial) {
        {
            zone.write_handle(center).get().approve_signed();
        }

        // Send a message to the zone signer to trigger a re-scan of
        // when to re-sign next.
        center.signer.on_publish_signed_zone(center);

        info!("[CC]: Instructing publication server to publish the signed zone");
        PublicationServer::publish(center, zone, zone_serial);
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

    pub fn on_zone_review(
        &self,
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        zone_serial: Serial,
        decision: ZoneReviewDecision,
    ) -> ZoneReviewResult {
        let unit_name = self.unit_name();
        let zone_name = &zone.name;

        // Look up the zone.

        let new_review_state = match decision {
            ZoneReviewDecision::Approve => ZoneVersionReviewState::Approved,
            ZoneReviewDecision::Reject => ZoneVersionReviewState::Rejected,
        };

        // Look up the version of the zone being reviewed.
        match self.source {
            Source::Unsigned => {
                {
                    let mut zone_state = zone.write(center);
                    let Some(version) = zone_state.unsigned.get_mut(&zone_serial) else {
                        // 'on_seek_approval_for_zone_cmd()' should have created
                        // this.  Since it doesn't exist, the zone is not under
                        // review.

                        debug!(
                            "[{unit_name}] Got a review for {zone_name}/{zone_serial}, but it was not pending review"
                        );
                        return Err(ZoneReviewError::NotUnderReview);
                    };

                    // Check that the zone was not already approved.
                    if matches!(version.review, ZoneVersionReviewState::Approved) {
                        // This version of the zone is no longer being reviewed.
                        //
                        // TODO: Differentiate this from 'NotUnderReview'?

                        return Err(ZoneReviewError::NotUnderReview);
                    }

                    version.review = new_review_state;
                }
                if matches!(decision, ZoneReviewDecision::Approve) {
                    info!(
                        "Unsigned zone '{zone_name}' with serial {zone_serial} has been approved."
                    );
                    self.on_unsigned_zone_approved(center, zone, zone_serial);
                } else {
                    error!(
                        "Unsigned zone '{zone_name}' with serial {zone_serial} has been rejected."
                    );

                    let mut handle = zone.write_handle(center);
                    let policy = handle.state.policy.as_ref().unwrap();
                    match policy.loader.review.on_reject {
                        OnReject::Discard => {
                            handle.get().soft_reject_loaded();
                        }
                        OnReject::Halt => {
                            handle.get().hard_reject_loaded();
                        }
                    }
                }
            }

            Source::Signed => {
                {
                    let mut zone_state = zone.write(center);
                    let Some(version) = zone_state.signed.get_mut(&zone_serial) else {
                        // 'on_seek_approval_for_zone_cmd()' should have created
                        // this.  Since it doesn't exist, the zone is not under
                        // review.

                        debug!(
                            "[{unit_name}] Got a review for {zone_name}/{zone_serial}, but it was not pending review"
                        );
                        return Err(ZoneReviewError::NotUnderReview);
                    };

                    // Check that the zone was not already approved.
                    if matches!(version.review, ZoneVersionReviewState::Approved) {
                        // This version of the zone is no longer being reviewed.
                        //
                        // TODO: Differentiate this from 'NotUnderReview'?

                        return Err(ZoneReviewError::NotUnderReview);
                    }

                    version.review = new_review_state;
                }
                if matches!(decision, ZoneReviewDecision::Approve) {
                    info!("Signed zone '{zone_name}' with serial {zone_serial} has been approved.");
                    self.on_signed_zone_approved(center, zone, zone_serial);
                } else {
                    error!(
                        "Signed zone '{zone_name}' with serial {zone_serial} has been rejected."
                    );
                    let mut handle = zone.write_handle(center);
                    let policy = handle.state.policy.as_ref().unwrap();
                    match policy.signer.review.on_reject {
                        OnReject::Discard => {
                            handle.get().soft_reject_signed();
                        }
                        OnReject::Halt => {
                            handle.get().hard_reject_signed();
                        }
                    }
                }
            }

            Source::Published => unreachable!(),
        };

        Ok(ZoneReviewOutput {})
    }
}

impl std::fmt::Debug for ZoneServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneLoader").finish()
    }
}

//----------- CenterKeyStore -------------------------------------------------

#[derive(Clone)]
struct CenterKeyStore(Arc<Center>);

impl KeyStore for CenterKeyStore {
    type Key = Arc<domain::tsig::Key>;

    fn get_key<N: ToName>(&self, name: &N, algorithm: Algorithm) -> Option<Self::Key> {
        let tsig_store = &self.0.state.lock().unwrap().tsig_store;
        let key_name: domain::tsig::KeyName = name.try_to_name().ok()?;
        tsig_store
            .map
            .get(&key_name)
            .map(|k| k.inner.clone())
            .filter(|k| k.algorithm() == algorithm)
    }
}

//----------- LoaderNotifier ---------------------------------------------------

/// A forwarder of NOTIFY messages to the zone loader.
#[derive(Clone, Debug)]
pub struct LoaderNotifier {
    /// Whether the forwarder is enabled.
    enabled: bool,

    center: Arc<Center>,
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
            //
            // We ignore the serial because we will just do a SOA query to our
            // configured upstream.
            //
            // TODO: Do we want to try enforcing IP address based access
            // control at this point? Would we want CIDR matching support?
            // Would we want to require a DNS COOKIE if the transport is UDP?
            //
            // TODO: Do we want to try enforcing TSIG key based access control
            // at this point? We can determine the key that the zone source
            // is configured to use but we can't actually verify that that key
            // was used. The TsigMiddlewareSvc will have ensured that the a
            // valid key present in our key store was used, but that may not
            // be the actual key configured on the zone source. We cannot test
            // for the actual correct key because NotifyMiddlewareSvc that
            // invokes us doesn't pass us the Request from which we would be
            // able to learn the used TSIG key.
            let center = &self.center;
            if let Some(zone) = crate::center::get_zone(center, apex_name) {
                // Don't allow NOTIFY to trigger re-signing of a zone loaded
                // from disk because the operator may be in the middle
                // of editing the file and thus the zone may not be ready
                // to reload. Zones sourced from files should be reloaded
                // explicitly using the `cascade zone reload` CLI command.
                // Also ignore NOTIFY for a zone that has no source at all.

                // Clone the source so that we don't hold the zone state lock
                // when calling on_refresh_zone().
                let zone_source = zone.read().loader.source.clone();
                match zone_source {
                    crate::loader::Source::Server { .. } => {
                        info!("Instructing zone loader to refresh zone '{apex_name}");
                        center.loader.on_refresh_zone(center, &zone);
                    }

                    crate::loader::Source::Zonefile { .. } => {
                        warn!(
                            "Ignoring NOTIFY for zone '{apex_name}': zone source is not an upstream nameserver"
                        );
                    }

                    crate::loader::Source::None => {
                        warn!("Ignoring NOTIFY for zone '{apex_name}': zone has no source")
                    }
                }
            } else {
                warn!(
                    "Ignoring NOTIFY for zone '{apex_name}': zone is not registered with Cascade"
                );
            }
        }

        Box::pin(std::future::ready(Ok(())))
    }
}

pub fn send_notify_to_addrs<'a>(
    apex_name: StoredName,
    soa: SoaRecord,
    notify_set: impl Iterator<Item = &'a NameserverCommsPolicy>,
    center: &Arc<Center>,
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

    // Include the current zone SOA as an RFC 1996 "unsecure hint" (see
    // section 3.7) to the receiving nameserver so that it can choose to avoid
    // sending a SOA query if it deems that it has this version of the zone
    // already.
    let mut msg = msg.answer();
    msg.push(OldRecord::from(soa)).unwrap();

    for nameserver in notify_set {
        let dgram_config = dgram_config.clone();
        let req = RequestMessage::new(msg.clone()).unwrap();

        let nameserver = nameserver.clone();
        let center = center.clone();
        tokio::spawn(async move {
            // TODO: Use the connection factory here.
            let udp_connect = UdpConnect::new(nameserver.addr);
            let client = Connection::with_config(udp_connect, dgram_config.clone());

            trace!("Sending NOTIFY to nameserver {nameserver}");
            let span = tracing::trace_span!("auth", addr = %nameserver);
            let _guard = span.enter();

            // https://datatracker.ietf.org/doc/html/rfc1996
            //   "4.8 Master Receives a NOTIFY Response from Slave
            //
            //    When a master server receives a NOTIFY response, it deletes this
            //    query from the retry queue, thus completing the "notification
            //    process" of "this" RRset change to "that" server."
            //
            // TODO: We have no retry queue at the moment. Do we need one?

            let tsig_key = {
                let state = center.state.lock().unwrap();
                nameserver
                    .tsig_key_name
                    .as_ref()
                    .and_then(|tsig_key_name| state.tsig_store.get(tsig_key_name))
                    .map(|key| key.inner.clone())
            };

            if let Some(key) = &tsig_key {
                debug!(
                    "Found TSIG key '{}' (algorithm {}) for NOTIFY to {nameserver}",
                    key.name(),
                    key.algorithm()
                );
            }
            let res = if let Some(key) = tsig_key {
                let client = domain::net::client::tsig::Connection::new(key.clone(), client);
                client.send_request(req.clone()).get_response().await
            } else {
                client.send_request(req.clone()).get_response().await
            };

            if let Err(err) = res {
                warn!("Unable to send NOTIFY to nameserver {nameserver}: {err}");
            }
        });
    }
}
