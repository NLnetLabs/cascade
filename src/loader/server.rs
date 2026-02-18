//! Loading zones from DNS servers.

use std::{
    fmt,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering::Relaxed},
};

use bytes::Bytes;
use cascade_zonedata::{
    PatchError, ReplaceError, SoaRecord, UnsignedZonePatcher, UnsignedZoneReplacer, ZoneBuilder,
};
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
            HeaderFlags, Message, MessageItem, QClass, QType, Question, RClass, RType, Record,
            Serial,
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
use tracing::{debug, trace};

use crate::{loader::ActiveLoadMetrics, zone::Zone};

use super::RefreshError;

//----------- refresh() --------------------------------------------------------

/// Refresh a zone from a DNS server.
///
/// The DNS server will be queried for the latest version of the zone; if a
/// local copy of this version is not already available, it will be loaded.
/// Where possible, an incremental zone transfer will be used to communicate
/// more efficiently.
///
/// Returns `true` if a new instance of the zone was loaded.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name, addr = ?addr),
)]
pub async fn refresh(
    zone: &Arc<Zone>,
    addr: &SocketAddr,
    tsig_key: Option<tsig::Key>,
    builder: &mut ZoneBuilder,
    metrics: &ActiveLoadMetrics,
) -> Result<bool, RefreshError> {
    debug!("Refreshing {:?} from server {addr:?}", zone.name);

    if builder.curr_unsigned().is_none() {
        // Fetch the whole zone.
        axfr(zone, addr, tsig_key, builder, metrics).await?;

        return Ok(true);
    };

    trace!("Attempting an IXFR against {addr:?} for {:?}", zone.name);

    // Fetch the zone relative to the latest local copy.
    Ok(ixfr(zone, addr, tsig_key, builder, metrics).await?)
}

//----------- ixfr() -----------------------------------------------------------

/// Perform an incremental zone transfer.
///
/// The server is queried for the diff between the version of the zone indicated
/// by the provided SOA record, and the latest version known to the server. The
/// diff is transformed into a compressed representation of the _local_ version
/// of the zone.
///
/// Returns `true` if a new instance of the zone was loaded.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name, addr = ?addr),
)]
pub async fn ixfr(
    zone: &Arc<Zone>,
    addr: &SocketAddr,
    tsig_key: Option<tsig::Key>,
    builder: &mut ZoneBuilder,
    metrics: &ActiveLoadMetrics,
) -> Result<bool, IxfrError> {
    debug!("Attempting an IXFR against {addr:?} for {:?}", zone.name);

    let zone_name: &Name = ParseBytes::parse_bytes(zone.name.as_slice()).unwrap();
    let local_soa = builder.curr_unsigned().unwrap().soa().clone();

    // Prepare the IXFR query message.
    let mut buffer = [0u8; 1024];
    let mut compressor = NameCompressor::default();
    let mut msgbuilder = MessageBuilder::new(
        &mut buffer,
        &mut compressor,
        0u16.into(),
        *HeaderFlags::default().set_qr(false),
    );
    msgbuilder
        .push_question(&Question {
            qname: zone_name,
            // TODO: 'QType::IXFR'.
            qtype: QType { code: 251.into() },
            qclass: QClass::IN,
        })
        .unwrap();
    msgbuilder.push_authority(&local_soa).unwrap();
    let message = Bytes::copy_from_slice(msgbuilder.finish().as_bytes());
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

        if local_soa.rdata.serial == remote_soa.rdata.serial {
            // The zone has not changed.
            return Ok(false);
        } else {
            // If the remote serial is ahead of the local serial, the new zone
            // needs to be fetched. If the remote serial is behind, we treat it
            // as a new instance of the zone anyway.

            // Perform a full AXFR.
            axfr(zone, addr, tsig_key, builder, metrics).await?;
            return Ok(true);
        }
    }

    // Process the transfer data.
    let mut interpreter = XfrResponseInterpreter::new();
    metrics
        .num_loaded_bytes
        .fetch_add(response.as_slice().len(), Relaxed);
    let mut updates = interpreter.interpret_response(response)?;

    match updates.next() {
        Some(Ok(ZoneUpdate::DeleteAllRecords)) => {
            // This is an AXFR.
            let mut writer = builder.replace_unsigned().unwrap();
            let Some(soa) = process_axfr(&mut writer, updates, metrics)? else {
                // Fail: UDP-based IXFR returned a partial AXFR.
                return Err(IxfrError::IncompleteResponse);
            };

            assert!(interpreter.is_finished());
            writer.set_soa(soa)?;
            writer.apply()?;
            return Ok(true);
        }

        Some(Ok(ZoneUpdate::BeginBatchDelete(_))) => {
            // This is an IXFR.
            let mut writer = builder.patch_unsigned().unwrap();
            process_ixfr(&mut writer, updates, metrics)?;
            if !interpreter.is_finished() {
                // Fail: UDP-based IXFR returned a partial IXFR
                return Err(IxfrError::IncompleteResponse);
            }

            writer.apply()?;
            return Ok(true);
        }

        // NOTE: 'domain' currently reports 'None' for a single-SOA IXFR,
        // apparently assuming it means the local copy is up-to-date. But
        // this misses two other possibilities:
        // - The remote copy is older than the local copy.
        // - The IXFR was too big for UDP.
        None => {
            // Assume the remote copy is identical to to the local copy.
            return Ok(false);
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
                return Ok(false);
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

        if local_soa.rdata.serial == remote_soa.rdata.serial {
            // The zone has not changed.
            return Ok(false);
        } else {
            // If the remote serial is ahead of the local serial, the new zone
            // needs to be fetched. If the remote serial is behind, we treat it
            // as a new instance of the zone anyway.

            // Perform a full AXFR.
            axfr(zone, addr, tsig_key, builder, metrics).await?;
            return Ok(true);
        }
    }

    let mut bytes = initial.as_slice().len();
    let mut updates = interpreter.interpret_response(initial)?;

    match updates.next().unwrap() {
        Ok(ZoneUpdate::DeleteAllRecords) => {
            // This is an AXFR.
            let mut writer = builder.replace_unsigned().unwrap();

            // Process the response messages.
            let soa = loop {
                if let Some(soa) = process_axfr(&mut writer, updates, metrics)? {
                    break soa;
                } else {
                    // Retrieve the next message.
                    let message = response
                        .get_response()
                        .await?
                        .ok_or(IxfrError::IncompleteResponse)?;
                    bytes += message.as_slice().len();
                    updates = interpreter.interpret_response(message)?;
                }
            };

            assert!(interpreter.is_finished());
            writer.set_soa(soa)?;
            writer.apply()?;
            metrics.num_loaded_bytes.fetch_add(bytes, Relaxed);
            Ok(true)
        }

        Ok(ZoneUpdate::BeginBatchDelete(_)) => {
            // This is an IXFR.
            let mut writer = builder.patch_unsigned().unwrap();

            // Process the response messages.
            loop {
                process_ixfr(&mut writer, updates, metrics)?;

                if interpreter.is_finished() {
                    break;
                } else {
                    // Retrieve the next message.
                    let message = response
                        .get_response()
                        .await?
                        .ok_or(IxfrError::IncompleteResponse)?;
                    bytes += message.as_slice().len();
                    updates = interpreter.interpret_response(message)?;
                }
            }

            metrics.num_loaded_bytes.fetch_add(bytes, Relaxed);
            assert!(interpreter.is_finished());

            writer.apply()?;
            Ok(true)
        }

        Ok(ZoneUpdate::Finished(record)) => {
            let ZoneRecordData::Soa(soa) = record.data() else {
                unreachable!("'ZoneUpdate::Finished' must hold a SOA");
            };

            let serial = Serial::from(soa.serial().into_int());
            if local_soa.rdata.serial == serial {
                // The local copy is up-to-date.
                Ok(false)
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
    writer: &mut UnsignedZonePatcher,
    updates: XfrZoneUpdateIterator<'_, '_>,
    metrics: &ActiveLoadMetrics,
) -> Result<(), IxfrError> {
    for update in updates {
        metrics.num_loaded_records.fetch_add(1, Relaxed);
        match update? {
            ZoneUpdate::BeginBatchDelete(soa) => {
                // A previous deletion-addition set (i.e. a complete diff) has
                // been finished, and a new one is starting.
                writer.next_patchset()?;
                writer.remove_soa(soa.into())?;
            }

            ZoneUpdate::DeleteRecord(record) => {
                writer.remove(record.into())?;
            }

            ZoneUpdate::BeginBatchAdd(soa) => {
                writer.add_soa(soa.into())?;
            }

            ZoneUpdate::AddRecord(record) => {
                writer.add(record.into())?;
            }

            ZoneUpdate::Finished(_soa) => {
                // Finish this last set of deletions and additions.
                writer.next_patchset()?;
                break;
            }

            _ => unreachable!(),
        }
    }

    Ok(())
}

//----------- axfr() -----------------------------------------------------------

/// Perform an authoritative zone transfer.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name, addr = ?addr),
)]
pub async fn axfr(
    zone: &Arc<Zone>,
    addr: &SocketAddr,
    tsig_key: Option<tsig::Key>,
    builder: &mut ZoneBuilder,
    metrics: &ActiveLoadMetrics,
) -> Result<(), AxfrError> {
    debug!("Attempting an AXFR against {addr:?} for {:?}", zone.name);

    let zone_name: &Name = ParseBytes::parse_bytes(zone.name.as_slice()).unwrap();

    // Prepare the AXFR query message.
    let mut buffer = [0u8; 512];
    let mut compressor = NameCompressor::default();
    let mut msgbuilder = MessageBuilder::new(
        &mut buffer,
        &mut compressor,
        0u16.into(),
        *HeaderFlags::default().set_qr(false),
    );
    msgbuilder
        .push_question(&Question {
            qname: zone_name,
            // TODO: 'QType::AXFR'.
            qtype: QType { code: 252.into() },
            qclass: QClass::IN,
        })
        .unwrap();
    let message = Bytes::copy_from_slice(msgbuilder.finish().as_bytes());
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

    metrics
        .num_loaded_bytes
        .fetch_add(initial.as_slice().len(), Relaxed);
    let mut updates = interpreter.interpret_response(initial)?;

    assert!(updates.next().unwrap()? == ZoneUpdate::DeleteAllRecords);
    let mut writer = builder.replace_unsigned().unwrap();

    // Process the response messages.
    let soa = loop {
        if let Some(soa) = process_axfr(&mut writer, updates, metrics)? {
            break soa;
        } else {
            // Retrieve the next message.
            let message = response
                .get_response()
                .await?
                .ok_or(AxfrError::IncompleteResponse)?;
            metrics
                .num_loaded_bytes
                .fetch_add(message.as_slice().len(), Relaxed);
            updates = interpreter.interpret_response(message)?;
        }
    };

    assert!(interpreter.is_finished());
    writer.set_soa(soa)?;
    writer.apply()?;
    Ok(())
}

/// Process an AXFR message.
fn process_axfr(
    writer: &mut UnsignedZoneReplacer,
    updates: XfrZoneUpdateIterator<'_, '_>,
    metrics: &ActiveLoadMetrics,
) -> Result<Option<SoaRecord>, AxfrError> {
    // Process the updates.
    for update in updates {
        metrics.num_loaded_records.fetch_add(1, Relaxed);
        match update? {
            ZoneUpdate::AddRecord(record) => {
                writer.add(record.into())?;
            }

            ZoneUpdate::Finished(record) => {
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

    /// The zone data could not be written.
    Write(PatchError),
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
            IxfrError::Write(error) => Some(error),
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
            IxfrError::Write(error) => {
                write!(f, "could not write the zone data: {error}")
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

impl From<PatchError> for IxfrError {
    fn from(error: PatchError) -> Self {
        Self::Write(error)
    }
}

impl From<ReplaceError> for IxfrError {
    fn from(error: ReplaceError) -> Self {
        Self::Axfr(AxfrError::Write(error))
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

    /// The zone data could not be written.
    Write(ReplaceError),
}

impl std::error::Error for AxfrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AxfrError::Client(error) => Some(error),
            AxfrError::Connection(error) => Some(error),
            AxfrError::Xfr(_) => None,
            AxfrError::XfrIter(_) => None,
            AxfrError::IncompleteResponse => None,
            AxfrError::Write(error) => Some(error),
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
            AxfrError::Write(error) => {
                write!(f, "could not write the zone data: {error}")
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

impl From<ReplaceError> for AxfrError {
    fn from(error: ReplaceError) -> Self {
        Self::Write(error)
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
