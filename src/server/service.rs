//! Servicing DNS requests.

use std::sync::{Arc, RwLock};

use cascade_zonedata::{
    LoadedZoneReviewer, RegularRecord, SignedZoneReviewer, SoaRecord, ZoneViewer,
};
use domain::{
    new::base::{
        name::{RevName, RevNameBuf},
        wire::ParseBytes,
    },
    utils::dst::UnsizedCopy,
};

use crate::zone::Zone;

//----------- ZoneService ------------------------------------------------------

/// Cascade's DNS service.
///
/// This type is responsible for answering DNS queries received by Cascade,
/// using zone viewer objects. When a query is received, the corresponding zone
/// is looked up, the appropriate information is retrieved from its viewer, and
/// the appropriate DNS answer is synthesized and returned.
///
/// The viewer type has to implement [`Viewer`]. It should only be
/// [`LoadedZoneReviewer`], [`SignedZoneReviewer`], or [`ZoneViewer`].
///
/// The service can be interacted with through a [`ZoneServiceHandle`], which
/// is also returned by [`ZoneService::new()`].
pub struct ZoneService<V> {
    /// The underlying state.
    //
    // TODO: The state is currently wrapped in an 'RwLock'. This is necessary
    // as the state might have to change, e.g. in response to changes to zones.
    // It would be preferable to hold the state directly, and use channels to
    // communicate the need for changes. This is currently impossible because
    // of the limitations of 'domain::net::server'; that architecture should be
    // gradually replaced locally for better flexibility and efficiency.
    state: Arc<std::sync::RwLock<ZoneServiceState<V>>>,
}

impl<V> ZoneService<V> {
    /// Construct a new [`ZoneService`].
    ///
    /// In addition to the service, a [`ZoneServiceHandle`] is returned through
    /// which the service can be interacted with.
    pub fn new() -> (ZoneService<V>, ZoneServiceHandle<V>) {
        let state = Arc::new(std::sync::RwLock::default());
        let service = ZoneService {
            state: state.clone(),
        };
        let handle = ZoneServiceHandle { state };
        (service, handle)
    }
}

impl<V> Clone for ZoneService<V> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

/// A compatibility layer to [`domain::net::server`].
///
/// In the future, the network server stack should be gradually inlined here,
/// so it can use [`domain::new`] and support more functionality (e.g. handling
/// XFRs by spawning OS threads).
mod compat {
    use std::{pin::Pin, sync::Arc};

    use cascade_zonedata::OldRecord;
    use domain::{
        base::{Message, MessageBuilder, iana::Rcode},
        net::server::{
            message::Request,
            service::{CallResult, Service, ServiceResult},
        },
        new::{
            base::{name::Name, wire::ParseBytesZC},
            rdata::Soa,
        },
        tsig,
    };
    use futures::Stream;
    use tracing::{Level, debug, trace};

    use crate::server::request::{RequestKind, ZoneRequestKind};

    use super::{ServedZone, Viewer, ZoneService};

    impl<V> Service<Vec<u8>, Option<Arc<tsig::Key>>> for ZoneService<V>
    where
        V: Viewer + Send + Sync + 'static,
    {
        type Target = Vec<u8>;
        type Stream = ResponseStream;
        type Future = Response;

        fn call(&self, old_request: Request<Vec<u8>, Option<Arc<tsig::Key>>>) -> Response {
            // Parse the request.
            let message = old_request.message().as_slice();
            let message = domain::new::base::Message::parse_bytes_by_ref(message)
                .expect("'message' was already checked to be a valid DNS message");
            let request = match crate::server::request::parse(message) {
                Ok(request) => request,
                Err(_error) => {
                    // TODO: Generate the response using 'error'.
                    return Box::pin(std::future::ready(error(
                        old_request.message(),
                        Rcode::FORMERR,
                    )));
                }
            };

            // Determine how to handle the request.
            match request.kind {
                RequestKind::Zone(zone_request) => {
                    // Look up the relevant zone.
                    let state = self.state.read().unwrap();
                    let Some(zone) = state.zones.get(&*zone_request.name) else {
                        // No such zone could be found.
                        let rcode = match zone_request.kind {
                            // Return NXDOMAIN for normal queries.
                            ZoneRequestKind::Soa => Rcode::NXDOMAIN,
                            // Return NOTAUTH for zone transfers.
                            ZoneRequestKind::Axfr | ZoneRequestKind::Ixfr { .. } => Rcode::NOTAUTH,
                        };
                        return Box::pin(std::future::ready(error(old_request.message(), rcode)));
                    };

                    if !is_permitted(zone, &old_request) {
                        return Box::pin(std::future::ready(error(
                            old_request.message(),
                            Rcode::REFUSED,
                        )));
                    }

                    match zone_request.kind {
                        ZoneRequestKind::Soa => Box::pin({
                            let viewer = zone.viewer.clone();
                            async move {
                                let viewer = viewer.read_owned().await;
                                soa(old_request.message(), &*viewer)
                            }
                        }) as Response,

                        ZoneRequestKind::Axfr => {
                            Box::pin(axfr(old_request, zone.clone())) as Response
                        }

                        ZoneRequestKind::Ixfr { known_soa } => {
                            Box::pin(ixfr(old_request, known_soa.rdata, zone.clone())) as Response
                        }
                    }
                }
            }
        }
    }

    fn is_permitted<V: Viewer>(
        zone: &ServedZone<V>,
        old_request: &Request<Vec<u8>, Option<Arc<tsig::Key>>>,
    ) -> bool {
        let zone_state = zone.handle.state.lock().unwrap();

        if tracing::enabled!(Level::TRACE) {
            let tsig_key = old_request.metadata().as_ref().map(|key| key.name());
            trace!(
                "Received request {} from {} for {} in zone {} with TSIG key {tsig_key:?}",
                old_request.message().header().id(),
                old_request.client_addr().ip(),
                old_request
                    .message()
                    .qtype()
                    .map(|rtype| rtype.to_string())
                    .unwrap_or("<NO QTYPE>".to_string()),
                zone.handle.name,
            );
        }

        if let Some(acls) = zone_state
            .policy
            .as_ref()
            .map(|p| &p.server.outbound.accept_xfr_from)
        {
            // If at least one ACL was specified, enforce it.
            if !acls.is_empty() {
                let wanted_tsig_key_name = old_request.metadata().as_ref().map(|key| key.name());

                for acl in acls {
                    // Does the client address match the allowed address?
                    if acl.addr.ip() == old_request.client_addr().ip() {
                        // Is the request signed with the right TSIG key?
                        if acl.tsig_key_name.as_ref() == wanted_tsig_key_name {
                            // Allow the request.
                            return true;
                        }
                    }
                }

                // No ACL matched, reject the request.
                if tracing::enabled!(Level::DEBUG) {
                    let extra = if tracing::enabled!(Level::TRACE) {
                        &format!(
                            " (TSIG key={wanted_tsig_key_name:?}) [no matching ACL found: {acls:?}]"
                        )
                    } else {
                        ""
                    };
                    debug!(
                        "Rejecting request {} from {} for {} in zone {}: access denied{extra}",
                        old_request.message().header().id(),
                        old_request.client_addr().ip(),
                        old_request
                            .message()
                            .qtype()
                            .map(|rtype| rtype.to_string())
                            .unwrap_or("<NO QTYPE>".to_string()),
                        zone.handle.name,
                    );
                }

                return false;
            }
        }

        // No ACL defined, accept the request.
        true
    }

    /// Generate a SOA DNS message response stream for the given zone viewer.
    ///
    /// Note: Also used by [`axfr()`] and [`ixfr()`] as well as in response to
    /// a direct SOA query.
    ///
    /// Returns an NXDOMAIN response if we have the zone but no data for it.
    fn soa<V: Viewer>(request: &Message<Vec<u8>>, viewer: &V) -> ResponseStream {
        if viewer.is_empty() {
            return error(request, Rcode::NXDOMAIN);
        }
        let soa = viewer.soa().clone();

        let builder = MessageBuilder::new_stream_vec();
        let mut builder = builder.start_answer(request, Rcode::NOERROR).unwrap();
        builder.header_mut().set_aa(true);
        builder.push(OldRecord::from(soa)).unwrap();

        let response = builder.additional();
        let result = Ok(CallResult::new(response));
        Box::new(futures::stream::once(std::future::ready(result))) as _
    }

    /// Generate an AXFR DNS message response stream for the given zone.
    async fn axfr<V: Viewer + Send + Sync + 'static>(
        request: Request<Vec<u8>, Option<Arc<tsig::Key>>>,
        zone: ServedZone<V>,
    ) -> ResponseStream {
        // Refuse AXFR requests over UDP.
        if request.transport_ctx().is_udp() {
            return error(request.message(), Rcode::NOTIMP);
        }

        // Obtain a read lock to read the zone for an extended duration.
        let viewer = zone.viewer.read_owned().await;

        if viewer.is_empty() {
            // The zone is known to exist, but we don't have any data for it.
            return error(request.message(), Rcode::NOTAUTH);
        }

        // NOTE: The following code is a bit tricky. Ideally, we would elide
        // the channel and return the `messages` iterator as an async `Stream`;
        // but the iterator borrows from `viewer` via `.non_soa_records()`, and
        // this prevents the iterator from satisfying `'static`. Rust actually
        // _does_ have machinery to work around this, in async functions, so we
        // prepare the messages in an async function (as a Tokio task) and send
        // them over a channel from there.
        //
        // In the future, IXFRs could be implemented by spawning an OS thread
        // and doing all the work there. This is incompatible with the API of
        // `domain::net::server`, as the underlying TCP connection cannot be
        // extracted, but we plan to stop using that API anyway.

        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);

        tokio::task::spawn(async move {
            // Extract the records to serve.
            let soa = viewer.soa().clone();
            let mut records = [soa.clone().into()]
                .into_iter()
                .chain(viewer.non_soa_records())
                .chain([soa.into()])
                .peekable();

            // Divide the records into DNS messages.
            let mut max_message_size = u16::MAX; // TCP
            max_message_size -= request.num_reserved_bytes();
            let messages = std::iter::from_fn(move || {
                records.peek()?;

                let mut builder = MessageBuilder::new_stream_vec();
                builder.set_push_limit(max_message_size as usize);
                let mut builder = builder
                    .start_answer(request.message(), Rcode::NOERROR)
                    .unwrap();
                builder.header_mut().set_aa(true);

                while let Some(record) = records.peek() {
                    match builder.push(OldRecord::from(record.clone())) {
                        // On success, consume the record.
                        Ok(()) => {
                            let _ = records.next();
                        }

                        // Once the message runs out of space, stop.
                        Err(_) => break,
                    }
                }

                let response = builder.additional();
                Some(CallResult::new(response))
            });

            for message in messages {
                if tx.send(message).await.is_err() {
                    // The channel has closed; stop.
                    break;
                }
            }
        });

        let stream = futures::stream::poll_fn(move |cx| rx.poll_recv(cx).map(|m| m.map(Ok)));

        Box::new(stream) as _
    }

    /// Generate an IXFR DNS message response stream for the given zone.
    async fn ixfr<V: Viewer + Send + Sync + 'static>(
        request: Request<Vec<u8>, Option<Arc<tsig::Key>>>,
        client_soa: Soa<Box<Name>>,
        zone: ServedZone<V>,
    ) -> ResponseStream {
        // Save a cheap clone of the zone to avoid a borrow checker error.
        let zone_clone = zone.clone();

        // Obtain a read lock to read the zone for an extended duration.
        let viewer = zone.viewer.read_owned().await;

        if viewer.is_empty() {
            // The zone is known to exist, but we don't have any data for it.
            return error(request.message(), Rcode::NOTAUTH);
        }

        // UDP is unlikely to work for any but the smallest of diffs,
        // especially with a DNSSEC signed zone because even removal of a
        // single A record can result in many RRs being changed due to the
        // impact on the NSEC(3) chain, plus any change has to include a SOA
        // SERIAL bump causing both the SOA RR and its RRSIG to also be in
        // every IXFR diff. However, RFC 1995 says that "Transport of a query
        // may be by either UDP or TCP" so we can't refuse UDP entirely. We
        // can however return a single SOA record per RFC 1995 "to inform the
        // client that a TCP query should be initiated".
        if request.transport_ctx().is_udp() {
            trace!(
                "Signalling UDP IXR client at {} to retry by TCP",
                request.client_addr().ip()
            );
            return soa(request.message(), &*viewer);
        }

        // Remember the latest SOA.
        let new_soa = viewer.soa().clone();

        // https://datatracker.ietf.org/doc/html/rfc1995#section-4
        // 4. Response Format
        //    "If incremental zone transfer is not available, the entire zone
        //     is returned.  The first and the last RR of the response is the
        //     SOA record of the zone. I.e. the behavior is the same as an
        //     AXFR response except the query type is IXFR."

        // https://datatracker.ietf.org/doc/html/rfc1995#section-2
        // 2. Brief Description of the Protocol
        //   "If an IXFR query with the same or newer version number than that
        //    of the server is received, it is replied to with a single SOA
        //    record of the server's current version, just as in AXFR."
        let our_soa_serial = viewer.soa().rdata.serial;

        if client_soa.serial >= our_soa_serial {
            trace!("Responding to IXFR with single SOA because query serial >= zone serial");
            return soa(request.message(), &*viewer);
        }

        let diffs = zone.handle.state.lock().unwrap().storage.diffs.clone();

        // TODO: Add something like the Bind `max-ixfr-ratio` option that
        // "sets the size threshold (expressed as a percentage of the size of
        // the full zone) beyond which named chooses to use an AXFR response
        // rather than IXFR when answering zone transfer requests"?

        // Note: Unlike RFC 5936 for AXFR, neither RFC 1995 nor RFC 9103 say
        // anything about whether an IXFR response can consist of more than
        // one response message, but given the 2^16 byte maximum response
        // size of a TCP DNS message and the 2^16 maximum number of ANSWER
        // RRs allowed per DNS response, large zones may not fit in a single
        // response message and will have to be split into multiple response
        // messages.

        if tracing::enabled!(Level::TRACE) {
            trace!(
                "IXFR out: {} diffs available for zone {}:",
                diffs.len(),
                zone.handle.name
            );
            for (i, (loaded_diff, signed_diff)) in diffs.iter().enumerate() {
                trace!(
                    "IXFR out: Diff #{i}: serial {} => serial {}, loaded -{}+{}, signed -{}+{}",
                    signed_diff.removed_soa.as_ref().unwrap().0.rdata.serial,
                    signed_diff.added_soa.as_ref().unwrap().0.rdata.serial,
                    loaded_diff.removed_records.len(),
                    loaded_diff.added_records.len(),
                    signed_diff.removed_records.len(),
                    signed_diff.added_records.len(),
                );
            }
        }

        // Find the diff, if we have it, that removes the SOA serial number
        // that the client currently has. That will be the start of the diff
        // that we need to serve. The SOA serial has to match the one seen by
        // the client, i.e. the one we published in the signed zone, not the
        // one from the loaded zone which could be completely different.
        let start_idx = diffs.iter().position(|(_, signed_diff)| {
            signed_diff.removed_soa.as_ref().map(|rr| rr.0.rdata.serial) == Some(client_soa.serial)
        });

        let Some(start_idx) = start_idx else {
            trace!(
                "Falling back from IXFR to AXFR because no diff is available for zone '{}' from serial {}",
                zone.handle.name, client_soa.serial,
            );
            return axfr(request, zone_clone).await;
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);

        // NOTE: The following code is a bit tricky. Ideally, we would elide
        // the channel and return the `messages` iterator as an async `Stream`;
        // but the iterator borrows from `viewer` via `.non_soa_records()`, and
        // this prevents the iterator from satisfying `'static`. Rust actually
        // _does_ have machinery to work around this, in async functions, so we
        // prepare the messages in an async function (as a Tokio task) and send
        // them over a channel from there.
        //
        // In the future, AXFRs could be implemented by spawning an OS thread
        // and doing all the work there. This is incompatible with the API of
        // `domain::net::server`, as the underlying TCP connection cannot be
        // extracted, but we plan to stop using that API anyway.

        // Stream the records in the background.
        tokio::task::spawn(async move {
            // Collect the sequence of IXFR output records.
            let mut rrs = vec![new_soa.clone().into()];
            // TODO: Use diffs[..].iter().flat_map() here to avoid the
            // intermediate Vec allocation?
            for (loaded_diff, signed_diff) in &diffs[start_idx..] {
                rrs.push(signed_diff.removed_soa.clone().unwrap().into());
                rrs.extend(loaded_diff.removed_records.clone());
                rrs.extend(signed_diff.removed_records.clone());
                rrs.push(signed_diff.added_soa.clone().unwrap().into());
                rrs.extend(loaded_diff.added_records.clone());
                rrs.extend(signed_diff.added_records.clone());
            }
            rrs.push(new_soa.into());

            // Divide the records into DNS messages.
            let mut rr_iter = rrs.into_iter().peekable();
            let mut max_message_size = u16::MAX; // TCP
            max_message_size -= request.num_reserved_bytes();
            let messages = std::iter::from_fn(move || {
                rr_iter.peek()?;

                let mut builder = MessageBuilder::new_stream_vec();
                builder.set_push_limit(max_message_size as usize);
                let mut builder = builder
                    .start_answer(request.message(), Rcode::NOERROR)
                    .unwrap();
                builder.header_mut().set_aa(true);

                while let Some(record) = rr_iter.peek() {
                    match builder.push(OldRecord::from(record.clone())) {
                        // On success, consume the record.
                        Ok(()) => {
                            let _ = rr_iter.next();
                        }

                        // Once the message runs out of space, stop.
                        Err(_) => break,
                    }
                }

                let response = builder.additional();
                Some(CallResult::new(response))
            });

            for message in messages {
                if tx.send(message).await.is_err() {
                    // The channel has closed; stop.
                    break;
                }
            }
        });

        let stream = futures::stream::poll_fn(move |cx| rx.poll_recv(cx).map(|m| m.map(Ok)));

        Box::new(stream) as _
    }

    fn error(request: &Message<Vec<u8>>, rcode: Rcode) -> ResponseStream {
        let response = MessageBuilder::new_stream_vec()
            .start_error(request, rcode)
            .additional();
        let result = Ok(CallResult::new(response));
        Box::new(futures::stream::once(std::future::ready(result))) as _
    }

    type ResponseStream = Box<dyn Stream<Item = ServiceResult<Vec<u8>>> + Unpin + Send + Sync>;
    type Response = Pin<Box<dyn Future<Output = ResponseStream> + Send + Sync>>;
}

//----------- Viewer -----------------------------------------------------------

/// A viewer through which zone data can be served.
trait Viewer {
    /// Whether the zone instance is empty.
    fn is_empty(&self) -> bool;

    /// Return the SOA record.
    fn soa(&self) -> &SoaRecord;

    /// Return all records in the zone (excluding SOA).
    fn non_soa_records(&self) -> impl Iterator<Item = RegularRecord> + Send;
}

impl Viewer for LoadedZoneReviewer {
    fn is_empty(&self) -> bool {
        self.read().is_none()
    }

    fn soa(&self) -> &SoaRecord {
        self.read().unwrap().soa()
    }

    fn non_soa_records(&self) -> impl Iterator<Item = RegularRecord> + Send {
        self.read().unwrap().regular_records().iter().cloned()
    }
}

impl Viewer for SignedZoneReviewer {
    fn is_empty(&self) -> bool {
        self.read().is_none()
    }

    fn soa(&self) -> &SoaRecord {
        self.read().unwrap().soa()
    }

    fn non_soa_records(&self) -> impl Iterator<Item = RegularRecord> + Send {
        let reader = self.read().unwrap();
        reader
            .loaded_records()
            .chain(reader.generated_records().iter().cloned())
    }
}

impl Viewer for ZoneViewer {
    fn is_empty(&self) -> bool {
        self.read().is_none()
    }

    fn soa(&self) -> &SoaRecord {
        self.read().unwrap().soa()
    }

    fn non_soa_records(&self) -> impl Iterator<Item = RegularRecord> + Send {
        let reader = self.read().unwrap();
        reader
            .loaded_records()
            .chain(reader.generated_records().iter().cloned())
    }
}

//----------- ZoneServiceHandle ------------------------------------------------

/// A handle for controlling a [`ZoneService`].
pub struct ZoneServiceHandle<V> {
    /// The underlying state.
    state: Arc<RwLock<ZoneServiceState<V>>>,
}

impl<V> ZoneServiceHandle<V> {
    /// Register a new zone.
    ///
    /// ## Panics
    ///
    /// Panics if the zone is already registered.
    pub fn add_zone(&self, zone: Arc<Zone>, viewer: V) {
        let mut state = self.state.write().unwrap();
        let name = RevNameBuf::parse_bytes(zone.name.as_slice()).unwrap();
        let zone = ServedZone {
            handle: zone,
            viewer: Arc::new(tokio::sync::RwLock::new(viewer)),
        };
        let previous = state.zones.insert(name.unsized_copy_into(), zone);
        assert!(previous.is_none(), "the zone is already registered");
    }

    /// Update the viewer of a zone.
    ///
    /// The old viewer is returned.
    ///
    /// ## Panics
    ///
    /// Panics if the zone has not been registered.
    pub async fn update_viewer(&self, zone: &Arc<Zone>, viewer: V) -> V {
        // Locate the slot for the viewer.
        let slot = {
            let state = self.state.read().unwrap();
            let name = RevNameBuf::parse_bytes(zone.name.as_slice()).unwrap();
            let zone = state
                .zones
                .get(&*name)
                .expect("the zone has been registered");
            zone.viewer.clone()
        };
        let mut slot = slot.write().await;
        std::mem::replace(&mut *slot, viewer)
    }

    /// Remove a zone.
    ///
    /// ## Panics
    ///
    /// Panics if the zone is not known to the service.
    pub fn remove_zone(&self, zone: &Arc<Zone>) {
        let mut state = self.state.write().unwrap();
        let name = RevNameBuf::parse_bytes(zone.name.as_slice()).unwrap();
        let existed = state.zones.remove(&*name);
        let ServedZone { handle, viewer } = existed.expect("the zone exists");
        assert!(
            Arc::ptr_eq(&handle, zone),
            "distinct 'Arc<Zone>'s had the same name"
        );
        let _ = viewer;
    }
}

//----------- ZoneServiceState -------------------------------------------------

/// State for serving zone data.
struct ZoneServiceState<V> {
    /// Zones being served.
    zones: foldhash::HashMap<Box<RevName>, ServedZone<V>>,
}

impl<V> Default for ZoneServiceState<V> {
    fn default() -> Self {
        Self {
            zones: Default::default(),
        }
    }
}

/// A zone being served.
struct ServedZone<V> {
    /// The zone handle.
    handle: Arc<Zone>,

    /// The viewer for the zone.
    ///
    /// [`tokio::sync::RwLock`] is used as viewers might be held for extended
    /// periods of time (e.g. across whole AXFRs).
    //
    // TODO: Use a more advanced double-buffering mechanism that allows new
    // readers to use the updated value, while old readers can retain their
    // lock.
    viewer: Arc<tokio::sync::RwLock<V>>,
}

impl<V> Clone for ServedZone<V> {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            viewer: self.viewer.clone(),
        }
    }
}
