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
        new::base::wire::ParseBytesZC,
        tsig,
    };
    use futures::Stream;

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

                        // TODO: Support IXFR.
                        ZoneRequestKind::Ixfr { .. } => Box::pin(std::future::ready(error(
                            old_request.message(),
                            Rcode::NOTIMP,
                        ))),
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
                return false;
            }
        }

        // No ACL defined, accept the request.
        true
    }

    fn soa<V: Viewer>(request: &Message<Vec<u8>>, viewer: &V) -> ResponseStream {
        if viewer.is_empty() {
            // The zone is known to exist, but we don't have any data for it.
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
        // In the future, AXFRs could be implemented by spawning an OS thread
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
