//! Loading zones from DNS servers.

use std::{
    fmt,
    iter::Peekable,
    mem,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering::Relaxed},
};

use bytes::Bytes;
use domain::{
    base::iana::Rcode,
    net::{
        client::{
            self,
            request::{RequestMessage, RequestMessageMulti, SendRequest, SendRequestMulti},
        },
        xfr::{
            self,
            protocol::{XfrResponseInterpreter, XfrZoneUpdateIterator},
        },
    },
    new::{
        base::{
            CanonicalRecordData, HeaderFlags, Message, MessageItem, QClass, QType, Question,
            RClass, RType, Record, Serial,
            build::MessageBuilder,
            name::{Name, NameCompressor, RevNameBuf},
            wire::{AsBytes, ParseBytes, ParseBytesZC, ParseError},
        },
        rdata::RecordData,
    },
    rdata::ZoneRecordData,
    tsig,
    utils::dst::UnsizedCopy,
    zonetree::types::ZoneUpdate,
};
use tokio::net::TcpStream;
use tracing::trace;

use crate::{
    loader::ActiveLoadMetrics,
    zone::{
        Zone,
        contents::{self, RegularRecord, SoaRecord, ZoneContents},
    },
};

use super::RefreshError;

//----------- refresh() --------------------------------------------------------

/// Refresh a zone from a DNS server.
///
/// See [`super::refresh()`].
pub async fn refresh(
    zone: &Arc<Zone>,
    addr: &SocketAddr,
    tsig_key: Option<tsig::Key>,
    contents: &mut Option<ZoneContents>,
    metrics: &ActiveLoadMetrics,
) -> Result<(), RefreshError> {
    if contents.is_none() {
        trace!("Attempting an AXFR against {addr:?} for {:?}", zone.name);

        // Fetch the whole zone.
        axfr(zone, addr, tsig_key, contents, metrics).await?;

        return Ok(());
    };

    trace!("Attempting an IXFR against {addr:?} for {:?}", zone.name);

    // Fetch the zone relative to the latest local copy.
    ixfr(zone, addr, tsig_key, contents, metrics).await?;

    Ok(())
}

//----------- ixfr() -----------------------------------------------------------

/// Perform an incremental zone transfer.
///
/// The server is queried for the diff between the version of the zone indicated
/// by the provided SOA record, and the latest version known to the server.  The
/// diff is transformed into a compressed representation of the _local_ version
/// of the zone.  If the local version is identical to the server's version,
/// [`None`] is returned.
pub async fn ixfr(
    zone: &Arc<Zone>,
    addr: &SocketAddr,
    tsig_key: Option<tsig::Key>,
    contents: &mut Option<ZoneContents>,
    metrics: &ActiveLoadMetrics,
) -> Result<(), IxfrError> {
    let zone_name: &Name = ParseBytes::parse_bytes(zone.name.as_slice()).unwrap();
    let local_soa = &contents.as_ref().unwrap().soa;

    // Prepare the IXFR query message.
    let mut buffer = [0u8; 1024];
    let mut compressor = NameCompressor::default();
    let mut builder = MessageBuilder::new(
        &mut buffer,
        &mut compressor,
        0u16.into(),
        *HeaderFlags::default().set_qr(false),
    );
    builder
        .push_question(&Question {
            qname: zone_name,
            // TODO: 'QType::IXFR'.
            qtype: QType { code: 251.into() },
            qclass: QClass::IN,
        })
        .unwrap();
    builder.push_authority(local_soa).unwrap();
    let message = Bytes::copy_from_slice(builder.finish().as_bytes());
    let message =
        domain::base::Message::from_octets(message).expect("'Message' is at least 12 bytes long");

    // If UDP is supported, try it before TCP.
    // Prepare a UDP client.
    let udp_conn = client::protocol::UdpConnect::new(*addr);
    let client = client::dgram::Connection::new(udp_conn);

    // Attempt the IXFR, possibly with TSIG.
    let response = if let Some(tsig_key) = &tsig_key {
        let client = client::tsig::Connection::new(tsig_key.clone(), client);
        let request = RequestMessage::new(message.clone()).unwrap();
        client.send_request(request).get_response().await?
    } else {
        let request = RequestMessage::new(message.clone()).unwrap();
        client.send_request(request).get_response().await?
    };

    // If the server does not support IXFR, fall back to an AXFR.
    if response.header().rcode() == Rcode::NOTIMP {
        // Query the server for its SOA record only.
        let remote_soa = query_soa(zone, addr, tsig_key.clone()).await?;

        if local_soa.rdata.serial != remote_soa.rdata.serial {
            // Perform a full AXFR.
            axfr(zone, addr, tsig_key, contents, metrics).await?;
        }

        return Ok(());
    }

    // Process the transfer data.
    let mut interpreter = XfrResponseInterpreter::new();
    metrics
        .num_loaded_bytes
        .fetch_add(response.as_slice().len(), Relaxed);
    let mut updates = interpreter.interpret_response(response)?.peekable();

    match updates.peek() {
        Some(Ok(ZoneUpdate::DeleteAllRecords)) => {
            // This is an AXFR.
            let _ = updates.next().unwrap();
            let mut all = Vec::new();
            let Some(soa) = process_axfr(&mut all, updates, metrics)? else {
                // Fail: UDP-based IXFR returned a partial AXFR.
                return Err(IxfrError::IncompleteResponse);
            };

            assert!(interpreter.is_finished());
            let all = all.into_boxed_slice();
            *contents = Some(ZoneContents { soa, all });
            return Ok(());
        }

        Some(Ok(ZoneUpdate::BeginBatchDelete(_))) => {
            // This is an IXFR.
            let mut versions = Vec::new();
            let mut this_soa = None;
            let mut next_soa = None;
            let mut all_this = Vec::new();
            let mut all_next = Vec::new();
            process_ixfr(
                &mut versions,
                &mut this_soa,
                &mut next_soa,
                &mut all_this,
                &mut all_next,
                updates,
                metrics,
            )?;
            if !interpreter.is_finished() {
                // Fail: UDP-based IXFR returned a partial IXFR
                return Err(IxfrError::IncompleteResponse);
            }

            // Coalesce the diffs together.
            let mut versions = versions.into_iter();
            let initial = versions.next().unwrap();
            let compressed = versions.try_fold(initial, |mut whole, sub| {
                whole.merge_from_next(&sub).map(|()| whole)
            })?;

            // Forward the local copy through the compressed diffs.
            let new_contents = contents.as_ref().unwrap().forward(&compressed)?;
            *contents = Some(new_contents);

            return Ok(());
        }

        // NOTE: 'domain' currently reports 'None' for a single-SOA IXFR,
        // apparently assuming it means the local copy is up-to-date.  But
        // this misses two other possibilities:
        // - The remote copy is older than the local copy.
        // - The IXFR was too big for UDP.
        None => {
            // Assume the remote copy is identical to to the local copy.
            return Ok(());
        }

        // NOTE: The XFR response interpreter will not return this right
        // now; it needs to be modified to report single-SOA IXFRs here.
        Some(Ok(ZoneUpdate::Finished(record))) => {
            let ZoneRecordData::Soa(soa) = record.data() else {
                unreachable!("'ZoneUpdate::Finished' must hold a SOA");
            };

            metrics.num_loaded_records.fetch_add(1, Relaxed);

            let serial = Serial::from(soa.serial().into_int());
            if local_soa.rdata.serial == serial {
                // The local copy is up-to-date.
                return Ok(());
            }

            // The transfer may have been too big for UDP; fall back to a
            // TCP-based IXFR.
        }

        _ => unreachable!(),
    }

    // UDP didn't pan out; attempt a TCP-based IXFR.

    // Prepare a TCP client.
    let tcp_conn = TcpStream::connect(*addr)
        .await
        .map_err(IxfrError::Connection)?;
    // TODO: Avoid the unnecessary heap allocation + trait object.
    let client: Box<dyn SendRequestMulti<RequestMessageMulti<Bytes>> + Send + Sync> =
        if let Some(tsig_key) = tsig_key.clone() {
            let (client, transport) = client::stream::Connection::<
                RequestMessage<Bytes>,
                client::tsig::RequestMessage<RequestMessageMulti<Bytes>, tsig::Key>,
            >::new(tcp_conn);
            tokio::task::spawn(transport.run());
            Box::new(client::tsig::Connection::new(tsig_key, client)) as _
        } else {
            let (client, transport) = client::stream::Connection::<
                RequestMessage<Bytes>,
                RequestMessageMulti<Bytes>,
            >::new(tcp_conn);
            tokio::task::spawn(transport.run());
            Box::new(client) as _
        };

    // Attempt the IXFR, possibly with TSIG.
    let request = RequestMessageMulti::new(message).unwrap();
    let mut response = SendRequestMulti::send_request(&*client, request);
    let mut interpreter = XfrResponseInterpreter::new();

    // Process the first message.
    let initial = response
        .get_response()
        .await?
        .ok_or(IxfrError::IncompleteResponse)?;

    // If the server does not support IXFR, fall back to an AXFR.
    if initial.header().rcode() == Rcode::NOTIMP {
        // Query the server for its SOA record only.
        let remote_soa = query_soa(zone, addr, tsig_key.clone()).await?;

        if local_soa.rdata.serial != remote_soa.rdata.serial {
            // Perform a full AXFR.
            axfr(zone, addr, tsig_key, contents, metrics).await?;
        }

        return Ok(());
    }

    let mut bytes = initial.as_slice().len();
    let mut updates = interpreter.interpret_response(initial)?.peekable();

    match updates.peek().unwrap() {
        Ok(ZoneUpdate::DeleteAllRecords) => {
            // This is an AXFR.
            let _ = updates.next().unwrap();
            let mut all = Vec::new();

            // Process the response messages.
            let soa = loop {
                if let Some(soa) = process_axfr(&mut all, updates, metrics)? {
                    break soa;
                } else {
                    // Retrieve the next message.
                    let message = response
                        .get_response()
                        .await?
                        .ok_or(IxfrError::IncompleteResponse)?;
                    bytes += message.as_slice().len();
                    updates = interpreter.interpret_response(message)?.peekable();
                }
            };

            assert!(interpreter.is_finished());
            let all = all.into_boxed_slice();
            *contents = Some(ZoneContents { soa, all });
            metrics.num_loaded_bytes.fetch_add(bytes, Relaxed);
            Ok(())
        }

        Ok(ZoneUpdate::BeginBatchDelete(_)) => {
            // This is an IXFR.
            let mut versions = Vec::new();
            let mut this_soa = None;
            let mut next_soa = None;
            let mut all_this = Vec::new();
            let mut all_next = Vec::new();

            // Process the response messages.
            loop {
                process_ixfr(
                    &mut versions,
                    &mut this_soa,
                    &mut next_soa,
                    &mut all_this,
                    &mut all_next,
                    updates,
                    metrics,
                )?;

                if interpreter.is_finished() {
                    break;
                } else {
                    // Retrieve the next message.
                    let message = response
                        .get_response()
                        .await?
                        .ok_or(IxfrError::IncompleteResponse)?;
                    bytes += message.as_slice().len();
                    updates = interpreter.interpret_response(message)?.peekable();
                }
            }

            metrics.num_loaded_bytes.fetch_add(bytes, Relaxed);
            assert!(interpreter.is_finished());

            // Coalesce the diffs together.
            let mut versions = versions.into_iter();
            let initial = versions.next().unwrap();
            let compressed = versions.try_fold(initial, |mut whole, sub| {
                whole.merge_from_next(&sub).map(|()| whole)
            })?;

            // Forward the local copy through the compressed diffs.
            let new_contents = contents.as_ref().unwrap().forward(&compressed)?;
            *contents = Some(new_contents);

            Ok(())
        }

        Ok(ZoneUpdate::Finished(record)) => {
            let ZoneRecordData::Soa(soa) = record.data() else {
                unreachable!("'ZoneUpdate::Finished' must hold a SOA");
            };

            let serial = Serial::from(soa.serial().into_int());
            if local_soa.rdata.serial == serial {
                // The local copy is up-to-date.
                Ok(())
            } else {
                // The server says the local copy is up-to-date, but it's not.
                Err(IxfrError::InconsistentUpToDate)
            }
        }

        _ => unreachable!(),
    }
}

/// Process an IXFR message.
fn process_ixfr(
    versions: &mut Vec<contents::Compressed>,
    this_soa: &mut Option<SoaRecord>,
    next_soa: &mut Option<SoaRecord>,
    only_this: &mut Vec<RegularRecord>,
    only_next: &mut Vec<RegularRecord>,
    updates: Peekable<XfrZoneUpdateIterator<'_, '_>>,
    metrics: &ActiveLoadMetrics,
) -> Result<(), IxfrError> {
    for update in updates {
        metrics.num_loaded_records.fetch_add(1, Relaxed);
        match update? {
            ZoneUpdate::BeginBatchDelete(record) => {
                // If there was a previous zone version, write it out.
                assert!(this_soa.is_some() == next_soa.is_some());
                if let Some((soa, next_soa)) = this_soa.take().zip(next_soa.take()) {
                    // Sort the contents of the batch addition.
                    only_next.sort_unstable();

                    let only_this = mem::take(only_this).into_boxed_slice();
                    let only_next = mem::take(only_next).into_boxed_slice();
                    versions.push(contents::Compressed {
                        soa,
                        next_soa,
                        only_this,
                        only_next,
                    });
                }

                assert!(this_soa.is_none());
                assert!(next_soa.is_none());
                assert!(only_this.is_empty());
                assert!(only_next.is_empty());

                *this_soa = Some(record.into());
            }

            ZoneUpdate::DeleteRecord(record) => {
                assert!(this_soa.is_some());
                assert!(next_soa.is_none());

                only_this.push(record.into());
            }

            ZoneUpdate::BeginBatchAdd(record) => {
                assert!(this_soa.is_some());
                assert!(next_soa.is_none());
                assert!(only_next.is_empty());

                // Sort the contents of the batch deletion.
                only_this.sort_unstable_by(|l, r| {
                    (&l.rname, l.rtype)
                        .cmp(&(&r.rname, r.rtype))
                        .then_with(|| l.rdata.cmp_canonical(&r.rdata))
                });

                *next_soa = Some(record.into());
            }

            ZoneUpdate::AddRecord(record) => {
                assert!(this_soa.is_some());
                assert!(next_soa.is_some());

                only_next.push(record.into());
            }

            ZoneUpdate::Finished(record) => {
                assert!(this_soa.is_some());
                assert!(next_soa.is_some());

                assert!(*next_soa == Some(record.into()));

                // Sort the contents of the batch addition.
                only_next.sort_unstable();

                let only_this = mem::take(only_this).into_boxed_slice();
                let only_next = mem::take(only_next).into_boxed_slice();
                versions.push(contents::Compressed {
                    soa: this_soa.take().unwrap(),
                    next_soa: next_soa.take().unwrap(),
                    only_this,
                    only_next,
                });

                break;
            }

            _ => unreachable!(),
        }
    }

    Ok(())
}

//----------- axfr() -----------------------------------------------------------

/// Perform an authoritative zone transfer.
pub async fn axfr(
    zone: &Arc<Zone>,
    addr: &SocketAddr,
    tsig_key: Option<tsig::Key>,
    contents: &mut Option<ZoneContents>,
    metrics: &ActiveLoadMetrics,
) -> Result<(), AxfrError> {
    let zone_name: &Name = ParseBytes::parse_bytes(zone.name.as_slice()).unwrap();

    // Prepare the AXFR query message.
    let mut buffer = [0u8; 512];
    let mut compressor = NameCompressor::default();
    let mut builder = MessageBuilder::new(
        &mut buffer,
        &mut compressor,
        0u16.into(),
        *HeaderFlags::default().set_qr(false),
    );
    builder
        .push_question(&Question {
            qname: zone_name,
            // TODO: 'QType::AXFR'.
            qtype: QType { code: 252.into() },
            qclass: QClass::IN,
        })
        .unwrap();
    let message = Bytes::copy_from_slice(builder.finish().as_bytes());
    let message =
        domain::base::Message::from_octets(message).expect("'Message' is at least 12 bytes long");

    // Prepare a TCP client.
    let tcp_conn = TcpStream::connect(*addr)
        .await
        .map_err(AxfrError::Connection)?;
    // TODO: Avoid the unnecessary heap allocation + trait object.
    let client: Box<dyn SendRequestMulti<RequestMessageMulti<Bytes>> + Send + Sync> =
        if let Some(tsig_key) = tsig_key {
            let (client, transport) = client::stream::Connection::<
                RequestMessage<Bytes>,
                client::tsig::RequestMessage<RequestMessageMulti<Bytes>, tsig::Key>,
            >::new(tcp_conn);
            tokio::task::spawn(transport.run());
            Box::new(client::tsig::Connection::new(tsig_key, client)) as _
        } else {
            let (client, transport) = client::stream::Connection::<
                RequestMessage<Bytes>,
                RequestMessageMulti<Bytes>,
            >::new(tcp_conn);
            tokio::task::spawn(transport.run());
            Box::new(client) as _
        };

    // Attempt the AXFR.
    let request = RequestMessageMulti::new(message).unwrap();
    let mut response = SendRequestMulti::send_request(&*client, request);
    let mut interpreter = XfrResponseInterpreter::new();

    // Process the first message.
    let initial = response
        .get_response()
        .await?
        .ok_or(AxfrError::IncompleteResponse)?;

    let mut bytes = initial.as_slice().len();
    let mut updates = interpreter.interpret_response(initial)?.peekable();

    assert!(updates.next().unwrap()? == ZoneUpdate::DeleteAllRecords);
    let mut all = Vec::new();

    // Process the response messages.
    let soa = loop {
        if let Some(soa) = process_axfr(&mut all, updates, metrics)? {
            break soa;
        } else {
            // Retrieve the next message.
            let message = response
                .get_response()
                .await?
                .ok_or(AxfrError::IncompleteResponse)?;
            bytes += message.as_slice().len();
            updates = interpreter.interpret_response(message)?.peekable();
        }
    };

    assert!(interpreter.is_finished());
    let all = all.into_boxed_slice();

    metrics.num_loaded_bytes.fetch_add(bytes, Relaxed);
    *contents = Some(ZoneContents { soa, all });

    Ok(())
}

/// Process an AXFR message.
fn process_axfr(
    all: &mut Vec<RegularRecord>,
    updates: Peekable<XfrZoneUpdateIterator<'_, '_>>,
    metrics: &ActiveLoadMetrics,
) -> Result<Option<SoaRecord>, AxfrError> {
    // Process the updates.
    for update in updates {
        metrics.num_loaded_records.fetch_add(1, Relaxed);
        match update? {
            ZoneUpdate::AddRecord(record) => {
                all.push(record.into());
            }

            ZoneUpdate::Finished(record) => {
                // Sort the zone contents.
                all.sort_unstable_by(|l, r| {
                    (&l.rname, l.rtype)
                        .cmp(&(&r.rname, r.rtype))
                        .then_with(|| l.rdata.cmp_canonical(&r.rdata))
                });

                return Ok(Some(record.into()));
            }

            _ => unreachable!(),
        }
    }

    Ok(None)
}

//----------- query_soa() ------------------------------------------------------

/// Query a DNS server for the SOA record of a zone.
pub async fn query_soa(
    zone: &Arc<Zone>,
    addr: &SocketAddr,
    tsig_key: Option<tsig::Key>,
) -> Result<SoaRecord, QuerySoaError> {
    let zone_name: RevNameBuf = ParseBytes::parse_bytes(zone.name.as_slice()).unwrap();

    // Prepare the SOA query message.
    let mut buffer = [0u8; 512];
    let mut compressor = NameCompressor::default();
    let mut builder = MessageBuilder::new(
        &mut buffer,
        &mut compressor,
        0u16.into(),
        *HeaderFlags::default().set_qr(false),
    );
    builder
        .push_question(&Question {
            qname: &zone_name,
            qtype: QType::SOA,
            qclass: QClass::IN,
        })
        .unwrap();
    let message = Bytes::copy_from_slice(builder.finish().as_bytes());
    let message =
        domain::base::Message::from_octets(message).expect("'Message' is at least 12 bytes long");

    let response = if let Some(tsig_key) = tsig_key {
        let udp_conn = client::protocol::UdpConnect::new(*addr);
        let tcp_conn = client::protocol::TcpConnect::new(*addr);
        let (client, transport) = client::dgram_stream::Connection::new(udp_conn, tcp_conn);
        tokio::task::spawn(transport.run());

        let client = client::tsig::Connection::new(Arc::new(tsig_key), client);

        // Send the query.
        let request = RequestMessage::new(message.clone()).unwrap();
        SendRequest::send_request(&client, request)
            .get_response()
            .await?
    } else {
        // Send the query.
        let udp_conn = client::protocol::UdpConnect::new(*addr);
        // Prepare a TCP client.
        let tcp_conn = client::protocol::TcpConnect::new(*addr);
        let (client, transport) = client::dgram_stream::Connection::new(udp_conn, tcp_conn);
        tokio::task::spawn(transport.run());

        // Send the query.
        let request = RequestMessage::new(message.clone()).unwrap();
        client.send_request(request).get_response().await?
    };

    // Parse the response message.
    let response = Message::parse_bytes_by_ref(response.as_slice())
        .expect("'Message' is at least 12 bytes long");
    if response.header.flags.rcode() != 0 {
        return Err(QuerySoaError::MismatchedResponse);
    }
    let mut parser = response.parse();
    let Some(MessageItem::Question(Question {
        qname,
        qtype: QType::SOA,
        qclass: QClass::IN,
    })) = parser.next().transpose()?
    else {
        return Err(QuerySoaError::MismatchedResponse);
    };
    if qname != zone_name {
        return Err(QuerySoaError::MismatchedResponse);
    }
    let Some(MessageItem::Answer(Record {
        rname,
        rtype: rtype @ RType::SOA,
        rclass: rclass @ RClass::IN,
        ttl,
        rdata: RecordData::Soa(rdata),
    })) = parser.next().transpose()?
    else {
        return Err(QuerySoaError::MismatchedResponse);
    };
    if rname != zone_name {
        return Err(QuerySoaError::MismatchedResponse);
    }
    let None = parser.next() else {
        return Err(QuerySoaError::MismatchedResponse);
    };

    Ok(SoaRecord(Record {
        rname: zone_name.unsized_copy_into(),
        rtype,
        rclass,
        ttl,
        rdata: rdata.map_names(|n| n.unsized_copy_into()),
    }))
}

//============ Errors ==========================================================

//----------- IxfrError --------------------------------------------------------

/// An error when performing an incremental zone transfer.
//
// TODO: Expand into less opaque variants.
#[derive(Debug)]
pub enum IxfrError {
    /// A DNS client error occurred.
    Client(client::request::Error),

    /// Could not connect to the server.
    Connection(std::io::Error),

    /// An XFR interpretation error occurred.
    Xfr(xfr::protocol::Error),

    /// An XFR interpretation error occurred.
    XfrIter(xfr::protocol::IterationError),

    /// An incomplete response was received.
    IncompleteResponse,

    /// An inconsistent [`Ixfr::UpToDate`] response was received.
    InconsistentUpToDate,

    /// A query for a SOA record failed.
    QuerySoa(QuerySoaError),

    /// An AXFR related error occurred.
    Axfr(AxfrError),

    /// An IXFR's diff was internally inconsistent.
    MergeIxfr(contents::MergeError),

    /// An IXFR's diff was not consistent with the local copy.
    ForwardIxfr(contents::ForwardError),
}

impl std::error::Error for IxfrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IxfrError::Client(error) => Some(error),
            IxfrError::Connection(error) => Some(error),
            IxfrError::Xfr(_) => None,
            IxfrError::XfrIter(_) => None,
            IxfrError::IncompleteResponse => None,
            IxfrError::InconsistentUpToDate => None,
            IxfrError::QuerySoa(error) => Some(error),
            IxfrError::Axfr(error) => Some(error),
            IxfrError::MergeIxfr(error) => Some(error),
            IxfrError::ForwardIxfr(error) => Some(error),
        }
    }
}

impl fmt::Display for IxfrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IxfrError::Client(error) => write!(f, "could not communicate with the server: {error}"),
            IxfrError::Connection(error) => write!(f, "could not connect to the server: {error}"),
            IxfrError::Xfr(error) => write!(
                f,
                "the server's response was semantically incorrect: {error}"
            ),
            IxfrError::XfrIter(_) => write!(f, "the server's response was semantically incorrect"),
            IxfrError::IncompleteResponse => {
                write!(f, "the server's response appears to be incomplete")
            }
            IxfrError::InconsistentUpToDate => write!(
                f,
                "the server incorrectly reported that the local copy is up-to-date"
            ),
            IxfrError::QuerySoa(error) => write!(f, "could not query for the SOA record: {error}"),
            IxfrError::Axfr(error) => write!(f, "the fallback AXFR failed: {error}"),
            IxfrError::MergeIxfr(error) => {
                write!(f, "the IXFR was internally inconsistent: {error}")
            }
            IxfrError::ForwardIxfr(error) => {
                write!(
                    f,
                    "the IXFR was inconsistent with the local zone contents: {error}"
                )
            }
        }
    }
}

//--- Conversion

impl From<client::request::Error> for IxfrError {
    fn from(value: client::request::Error) -> Self {
        Self::Client(value)
    }
}

impl From<xfr::protocol::Error> for IxfrError {
    fn from(value: xfr::protocol::Error) -> Self {
        Self::Xfr(value)
    }
}

impl From<xfr::protocol::IterationError> for IxfrError {
    fn from(value: xfr::protocol::IterationError) -> Self {
        Self::XfrIter(value)
    }
}

impl From<QuerySoaError> for IxfrError {
    fn from(v: QuerySoaError) -> Self {
        Self::QuerySoa(v)
    }
}

impl From<AxfrError> for IxfrError {
    fn from(value: AxfrError) -> Self {
        Self::Axfr(value)
    }
}

impl From<contents::MergeError> for IxfrError {
    fn from(v: contents::MergeError) -> Self {
        Self::MergeIxfr(v)
    }
}

impl From<contents::ForwardError> for IxfrError {
    fn from(v: contents::ForwardError) -> Self {
        Self::ForwardIxfr(v)
    }
}

//----------- AxfrError --------------------------------------------------------

/// An error when performing an authoritative zone transfer.
#[derive(Debug)]
pub enum AxfrError {
    /// A DNS client error occurred.
    Client(client::request::Error),

    /// Could not connect to the server.
    Connection(std::io::Error),

    /// An XFR interpretation error occurred.
    Xfr(xfr::protocol::Error),

    /// An XFR interpretation error occurred.
    XfrIter(xfr::protocol::IterationError),

    /// An incomplete response was received.
    IncompleteResponse,
}

impl std::error::Error for AxfrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AxfrError::Client(error) => Some(error),
            AxfrError::Connection(error) => Some(error),
            AxfrError::Xfr(_) => None,
            AxfrError::XfrIter(_) => None,
            AxfrError::IncompleteResponse => None,
        }
    }
}

impl fmt::Display for AxfrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AxfrError::Client(error) => write!(f, "could not communicate with the server: {error}"),
            AxfrError::Connection(error) => write!(f, "could not connect to the server: {error}"),
            AxfrError::Xfr(error) => write!(
                f,
                "the server's response was semantically incorrect: {error}"
            ),
            AxfrError::XfrIter(_) => {
                write!(f, "the server's response was semantically incorrect")
            }
            AxfrError::IncompleteResponse => {
                write!(f, "the server's response appears to be incomplete")
            }
        }
    }
}

//--- Conversion

impl From<client::request::Error> for AxfrError {
    fn from(value: client::request::Error) -> Self {
        Self::Client(value)
    }
}

impl From<xfr::protocol::Error> for AxfrError {
    fn from(value: xfr::protocol::Error) -> Self {
        Self::Xfr(value)
    }
}

impl From<xfr::protocol::IterationError> for AxfrError {
    fn from(value: xfr::protocol::IterationError) -> Self {
        Self::XfrIter(value)
    }
}

//----------- QuerySoaError ----------------------------------------------------

/// An error when querying a DNS server for a SOA record.
#[derive(Debug)]
pub enum QuerySoaError {
    /// A DNS client error occurred.
    Client(client::request::Error),

    /// Could not connect to the server.
    Connection(std::io::Error),

    /// The response could not be parsed.
    Parse(ParseError),

    /// The response did not match the query.
    MismatchedResponse,
}

impl std::error::Error for QuerySoaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            QuerySoaError::Client(error) => Some(error),
            QuerySoaError::Connection(error) => Some(error),
            QuerySoaError::Parse(_) => None,
            QuerySoaError::MismatchedResponse => None,
        }
    }
}

impl fmt::Display for QuerySoaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuerySoaError::Client(error) => {
                write!(f, "could not communicate with the server: {error}")
            }
            QuerySoaError::Connection(error) => {
                write!(f, "could not connect to the server: {error}")
            }
            QuerySoaError::Parse(_) => write!(f, "could not parse the server's response"),
            QuerySoaError::MismatchedResponse => {
                write!(f, "the server's response did not match the query")
            }
        }
    }
}

//--- Conversion

impl From<client::request::Error> for QuerySoaError {
    fn from(v: client::request::Error) -> Self {
        Self::Client(v)
    }
}

impl From<ParseError> for QuerySoaError {
    fn from(v: ParseError) -> Self {
        Self::Parse(v)
    }
}
