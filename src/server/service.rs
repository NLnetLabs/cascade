//! Servicing DNS requests.

use std::sync::{Arc, RwLock};

use cascade_zonedata::DiffData;
use domain::{
    new::base::{
        name::{RevName, RevNameBuf},
        wire::ParseBytes,
    },
    utils::dst::UnsizedCopy,
};

use crate::{
    zone::{Instances, Zone},
    zonedata::{LoadedZoneReviewer, RegularRecord, SignedZoneReviewer, SoaRecord, ZoneViewer},
};

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

    use cascade_zonedata::RegularRecord;
    use domain::base::iana::ExtendedErrorCode;
    use domain::base::opt::ExtendedError;
    use domain::new::base::RType;
    use domain::new::base::name::RevName;
    use domain::{
        base::{Message, MessageBuilder, iana::Rcode},
        net::server::{
            message::Request,
            service::{CallResult, Service, ServiceFeedback, ServiceResult},
        },
        new::{
            base::{name::Name, wire::ParseBytesZC},
            rdata::Soa,
        },
        tsig,
    };
    use futures::Stream;
    use futures_util as futures;
    use tracing::{debug, trace, warn};

    use crate::{
        server::request::{RequestKind, ZoneRequestKind},
        zonedata::{DiffData, OldRecord},
    };

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
                        None,
                    )));
                }
            };

            // Determine how to handle the request.
            match request.kind {
                RequestKind::Zone(zone_request) => {
                    // Look up the relevant zone. The zone should exist,
                    // this checked by AccessControlSvc. Return SERVFAIL
                    // if something goes wrong.
                    let state = self.state.read().unwrap();
                    let Some(zone) = state.zones.get(&*zone_request.name) else {
                        // No such zone could be found.
                        let rcode = Rcode::SERVFAIL;
                        return Box::pin(std::future::ready(error(
                            old_request.message(),
                            rcode,
                            None,
                        )));
                    };

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

    /// Generate a SOA DNS message response stream for the given zone viewer.
    ///
    /// Note: Also used by [`axfr()`] and [`ixfr()`] as well as in response to
    /// a direct SOA query.
    ///
    /// Returns a SERVFAIL response if we have the zone but no data for it.
    fn soa<V: Viewer>(request: &Message<Vec<u8>>, viewer: &V) -> ResponseStream {
        if viewer.is_empty() {
            return error(
                request,
                Rcode::SERVFAIL,
                Some(
                    ExtendedError::<Vec<u8>>::new_with_str(
                        ExtendedErrorCode::NOT_READY,
                        "zone exists but no data available",
                    )
                    .expect("should fit"),
                ),
            );
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
            return error(request.message(), Rcode::NOTIMP, None);
        }

        // Obtain a read lock to read the zone for an extended duration.
        let viewer = zone.viewer.read_owned().await;

        if viewer.is_empty() {
            // The zone is known to exist, but we don't have any data for it.
            warn!(
                "Returning SERVFAIL for AXFR request from client '{}' for zone '{}': zone is empty",
                request.client_addr().ip(),
                zone.handle.name,
            );
            return error(
                request.message(),
                Rcode::SERVFAIL,
                Some(
                    ExtendedError::<Vec<u8>>::new_with_str(
                        ExtendedErrorCode::NOT_READY,
                        "zone exists but no data available",
                    )
                    .expect("should fit"),
                ),
            );
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
                .chain(viewer.non_soa_records().cloned())
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

            // Enable transaction mode so that the connection handler will
            // block if we try to enqueue more messages than the response
            // buffer can hold, which can happen if the responses cannot be
            // sent to the client fast enough, rather than abort with a queue
            // full error.
            if tx
                .send(ServiceFeedback::BeginTransaction.into())
                .await
                .is_err()
            {
                // The channel has closed; stop.
                return;
            }

            for message in messages {
                if tx.send(message).await.is_err() {
                    // The channel has closed; stop.
                    break;
                }
            }

            let _ = tx.send(ServiceFeedback::EndTransaction.into()).await;
        });

        let stream = futures::stream::poll_fn(move |cx| rx.poll_recv(cx).map(|m| m.map(Ok)));

        Box::new(stream) as _
    }

    /// Generate an IXFR DNS message response stream for the given zone.
    ///
    /// For the loaded review server match the client provided SOA against
    /// loaded diff SOAs. For the signed review and publication servers match
    /// the client provided SOA against signed diff SOAs.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %zone.handle.name)
    )]
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
            warn!(
                "Returning SERVFAIL for IXFR request from client '{}' for zone '{}': zone is empty",
                request.client_addr().ip(),
                zone.handle.name,
            );
            return error(
                request.message(),
                Rcode::SERVFAIL,
                Some(
                    ExtendedError::<Vec<u8>>::new_with_str(
                        ExtendedErrorCode::NOT_READY,
                        "zone exists but no data available",
                    )
                    .expect("should fit"),
                ),
            );
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

        // TODO: Add something like the Bind `max-ixfr-ratio` option that
        // "sets the size threshold (expressed as a percentage of the size of
        // the full zone) beyond which named chooses to use an AXFR response
        // rather than IXFR when answering zone transfer requests"?

        // Try to find a diff sequence that starts from the client's serial.
        let diffs = 'get_diffs: {
            let zone_state = zone.handle.read();
            let mut diffs = Vec::new();
            for diff in viewer.diffs(&zone_state.instances) {
                if diff.removed_soa.is_none() || diff.added_soa.is_none() {
                    warn!("Bug: a diff is missing SOA removals/additions");
                    // Force the AXFR path.
                    break 'get_diffs None;
                }
                diffs.push(diff.clone());
                if let Some(soa) = &diff.removed_soa
                    && soa.rdata.serial == client_soa.serial
                {
                    // Found the right starting point!
                    break 'get_diffs Some(diffs);
                }
            }

            // Couldn't find a matching start point.
            None
        };

        let Some(diffs) = diffs else {
            // https://datatracker.ietf.org/doc/html/rfc1995#section-4
            // 4. Response Format
            //    "If incremental zone transfer is not available, the entire zone
            //     is returned.  The first and the last RR of the response is the
            //     SOA record of the zone. I.e. the behavior is the same as an
            //     AXFR response except the query type is IXFR."
            debug!(
                "Falling back from IXFR to AXFR because no diff is available for zone '{}' from serial {}",
                zone.handle.name, client_soa.serial,
            );
            return axfr(request, zone_clone).await;
        };

        trace!(client_serial = ?client_soa.serial, server_serial = ?our_soa_serial, len = diffs.len(), "Found satisfactory diff sequence:");
        for (i, diff) in diffs.iter().rev().enumerate() {
            trace!(
                "Diff #{i}: -{:?}+{:?} (-{}+{} records)",
                diff.removed_soa.as_ref().map(|s| s.rdata.serial),
                diff.added_soa.as_ref().map(|s| s.rdata.serial),
                diff.removed_records.len(),
                diff.added_records.len(),
            );
        }

        // Note: Unlike RFC 5936 for AXFR, neither RFC 1995 nor RFC 9103 say
        // anything about whether an IXFR response can consist of more than
        // one response message, but given the 2^16 byte maximum response
        // size of a TCP DNS message and the 2^16 maximum number of ANSWER
        // RRs allowed per DNS response, large zones may not fit in a single
        // response message and will have to be split into multiple response
        // messages.

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
            /// Format a diff for IXFR.
            //
            // NOTE: Rust is getting pretty mad about lifetimes here, so we
            // just collect the whole diff into a single new `Vec`. Each diff
            // should be relatively small so this shouldn't consume too much
            // memory at once.
            fn format_ixfr(diff: DiffData, origin: &RevName) -> Vec<RegularRecord> {
                let removed_soa = diff.removed_soa.unwrap();
                let added_soa = diff.added_soa.unwrap();

                let removed_records = diff
                    .removed_records
                    .into_iter()
                    .filter(|r| r.rtype != RType::SOA || *r.rname != *origin);
                let added_records = diff
                    .added_records
                    .into_iter()
                    .filter(|r| r.rtype != RType::SOA || *r.rname != *origin);

                std::iter::once(removed_soa.into())
                    .chain(removed_records)
                    .chain(std::iter::once(added_soa.into()))
                    .chain(added_records)
                    .collect()
            }

            let origin = &viewer.soa().rname;
            let soa = viewer.soa().clone();
            let mut records = [soa.clone().into()]
                .into_iter()
                .chain(diffs.into_iter().rev().flat_map(|d| format_ixfr(d, origin)))
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

            // Enable transaction mode so that the connection handler will
            // block if we try to enqueue more messages than the response
            // buffer can hold, which can happen if the responses cannot be
            // sent to the client fast enough, rather than abort with a queue
            // full error.
            if tx
                .send(ServiceFeedback::BeginTransaction.into())
                .await
                .is_err()
            {
                // The channel has closed; stop.
                return;
            }

            for message in messages {
                if tx.send(message).await.is_err() {
                    // The channel has closed; stop.
                    break;
                }
            }

            let _ = tx.send(ServiceFeedback::EndTransaction.into()).await;
        });

        let stream = futures::stream::poll_fn(move |cx| rx.poll_recv(cx).map(|m| m.map(Ok)));

        Box::new(stream) as _
    }

    fn error(
        request: &Message<Vec<u8>>,
        rcode: Rcode,
        opt_ede: Option<ExtendedError<Vec<u8>>>,
    ) -> ResponseStream {
        let mut response = MessageBuilder::new_stream_vec()
            .start_error(request, rcode)
            .additional();
        if let Some(ede) = opt_ede
            && let Err(err) = response.opt(|opt_builder| opt_builder.push(&ede))
        {
            return Box::new(futures::stream::once(std::future::ready(Err(err.into())))) as _;
        }
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
    fn non_soa_records<'d>(
        &'d self,
    ) -> impl Iterator<Item = &'d RegularRecord> + Send + use<'d, Self>;

    /// Diffs for serving IXFRs, from newest to oldest.
    fn diffs<'d>(
        &'d self,
        instances: &'d Instances,
    ) -> impl Iterator<Item = DiffData> + use<'d, Self>;
}

impl Viewer for LoadedZoneReviewer {
    fn is_empty(&self) -> bool {
        self.read().is_none()
    }

    fn soa(&self) -> &SoaRecord {
        self.read().unwrap().soa()
    }

    fn non_soa_records<'d>(&'d self) -> impl Iterator<Item = &'d RegularRecord> + Send + use<'d> {
        let soa = self.soa();
        self.read()
            .unwrap()
            .regular_records()
            .iter()
            .filter(|&r| r.rname != soa.rname || r.rtype != soa.rtype)
    }

    fn diffs<'d>(&'d self, instances: &'d Instances) -> impl Iterator<Item = DiffData> + use<'d> {
        // TODO: Ensure that the new loaded diff is always correctly available.

        std::iter::once(self.loaded_diff())
            .chain(
                instances
                    .obsolete
                    .per_load
                    .iter()
                    .rev()
                    .map(|is| is.loaded.diff_into_next.as_ref()),
            )
            .take_while(|d| d.is_some())
            .map(|d| (**d.unwrap()).clone())
    }
}

impl Viewer for SignedZoneReviewer {
    fn is_empty(&self) -> bool {
        self.read().is_none()
    }

    fn soa(&self) -> &SoaRecord {
        self.read().unwrap().soa()
    }

    fn non_soa_records<'d>(&'d self) -> impl Iterator<Item = &'d RegularRecord> + Send + use<'d> {
        let soa = self.soa();
        let reader = self.read().unwrap();
        reader
            .generated_records()
            .iter()
            .filter(|&r| r.rname != soa.rname || r.rtype != soa.rtype)
            .chain(reader.loaded_records())
    }

    fn diffs<'d>(&'d self, instances: &'d Instances) -> impl Iterator<Item = DiffData> + use<'d> {
        // TODO: Ensure that the new signed diff is always correctly available.

        build_signed_diffs(
            [
                self.signed_diff().map(DiffKind::Signed),
                self.loaded_diff().map(DiffKind::Loaded),
            ]
            .into_iter()
            .chain(
                instances
                    .obsolete
                    .latest_signed
                    .iter()
                    .rev()
                    .map(|i| i.diff_into_next.as_ref().map(DiffKind::Signed)),
            )
            .chain(instances.obsolete.per_load.iter().rev().flat_map(|is| {
                is.signed
                    .iter()
                    .rev()
                    .map(|i| i.diff_into_next.as_ref().map(DiffKind::Signed))
                    .chain([is.loaded.diff_into_next.as_ref().map(DiffKind::Loaded)])
            }))
            .take_while(|d| d.is_some())
            .map(|d| d.unwrap()),
        )
    }
}

impl Viewer for ZoneViewer {
    fn is_empty(&self) -> bool {
        self.read().is_none()
    }

    fn soa(&self) -> &SoaRecord {
        self.read().unwrap().soa()
    }

    fn non_soa_records<'d>(&'d self) -> impl Iterator<Item = &'d RegularRecord> + Send + use<'d> {
        let soa = self.soa();
        let reader = self.read().unwrap();
        reader
            .generated_records()
            .iter()
            .filter(|&r| r.rname != soa.rname || r.rtype != soa.rtype)
            .chain(reader.loaded_records())
    }

    fn diffs<'d>(&'d self, instances: &'d Instances) -> impl Iterator<Item = DiffData> + use<'d> {
        build_signed_diffs(
            instances
                .obsolete
                .latest_signed
                .iter()
                .rev()
                .map(|i| i.diff_into_next.as_ref().map(DiffKind::Signed))
                .chain(instances.obsolete.per_load.iter().rev().flat_map(|is| {
                    is.signed
                        .iter()
                        .rev()
                        .map(|i| i.diff_into_next.as_ref().map(DiffKind::Signed))
                        .chain([is.loaded.diff_into_next.as_ref().map(DiffKind::Loaded)])
                }))
                .take_while(|d| d.is_some())
                .map(|d| d.unwrap()),
        )
    }
}

/// A kind of diff (loaded or signed).
enum DiffKind<'a> {
    Loaded(&'a Arc<DiffData>),
    Signed(&'a Arc<DiffData>),
}

/// Combine loaded and signed diffs to build a sequence of diffs for a signed
/// zone.
fn build_signed_diffs<'a>(
    mut kind_diffs: impl Iterator<Item = DiffKind<'a>>,
) -> impl Iterator<Item = DiffData> {
    // The next diff (which is always signed).
    let mut signed = kind_diffs.next().map(|kind| {
        if let DiffKind::Signed(signed) = kind {
            signed
        } else {
            panic!("must start with a signed diff")
        }
    });

    std::iter::from_fn(move || {
        // Get the base signed diff.
        let mut diff: DiffData = (**signed.take()?).clone();

        let origin = &diff.added_soa.as_ref().unwrap().rname;

        // Find succeeding loaded instances and merge them in.
        for kind in kind_diffs.by_ref() {
            match kind {
                DiffKind::Loaded(loaded) => {
                    // Merge this diff in.
                    diff.removed_records
                        .extend(loaded.unsigned_removed_non_soa(origin).cloned());
                    diff.added_records
                        .extend(loaded.unsigned_added_non_soa(origin).cloned());
                }

                DiffKind::Signed(next_signed) => {
                    // Save this to use in the next iteration.
                    signed = Some(next_signed);
                    break;
                }
            }
        }

        Some(diff)
    })
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

    /// Get a viewer for a zone.
    ///
    /// If Cascade is still starting up there may not be a viewer for the zone
    /// yet.
    pub fn viewer(&self, zone: &Arc<Zone>) -> Option<Arc<tokio::sync::RwLock<V>>> {
        let state = self.state.read().unwrap();
        let name = RevNameBuf::parse_bytes(zone.name.as_slice()).unwrap();
        state.zones.get(&*name).map(|z| z.viewer.clone())
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
