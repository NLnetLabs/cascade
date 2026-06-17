//! Transferring catalog zones from a primary.
//!
//! A catalog zone is transferred in full (AXFR) into an in-memory
//! [`Zone`][domain::zonetree::Zone] and then parsed into a
//! [`Catalog`][domain::catalog::Catalog]. Catalog zones are small, so an AXFR
//! on every refresh is acceptable; the reconciler is idempotent regardless.

use std::fmt;
use std::net::SocketAddr;

use bytes::Bytes;
use domain::base::iana::Class;
use domain::base::{Message as OldMessage, Name, Ttl};
use domain::catalog::{Catalog, ParseCatalogError};
use domain::net::client::{
    self,
    request::{RequestMessage, RequestMessageMulti, SendRequestMulti},
};
use domain::net::xfr::{self, protocol::XfrResponseInterpreter};
use domain::new::base::{
    HeaderFlags, QClass, QType, Question,
    build::MessageBuilder,
    name::{Name as NewName, NameCompressor},
    wire::{AsBytes, ParseBytes},
};
use domain::rdata::ZoneRecordData;
use domain::tsig;
use domain::zonetree::ZoneBuilder;
use domain::zonetree::types::ZoneUpdate;
use domain::zonetree::update::ZoneUpdater;
use tokio::net::TcpStream;
use tracing::debug;

//----------- TransferredCatalog ---------------------------------------------

/// A catalog transferred from a primary.
#[derive(Clone, Debug)]
pub struct TransferredCatalog {
    /// The parsed catalog.
    pub catalog: Catalog,

    /// The SOA REFRESH interval of the catalog zone.
    pub refresh: Ttl,

    /// The SOA RETRY interval of the catalog zone.
    pub retry: Ttl,
}

//----------- transfer() -----------------------------------------------------

/// Transfers and parses a catalog zone from a primary via AXFR.
#[tracing::instrument(level = "debug", skip(tsig_key), fields(catalog = %apex))]
pub async fn transfer(
    apex: &Name<Bytes>,
    addr: &SocketAddr,
    tsig_key: Option<tsig::Key>,
) -> Result<TransferredCatalog, TransferError> {
    debug!("Transferring catalog {apex} from {addr}");

    // Build an empty in-memory zone to receive the catalog into.
    let zone = ZoneBuilder::new(apex.clone(), Class::IN).build();
    let mut updater = ZoneUpdater::new(zone.clone())
        .await
        .map_err(TransferError::Update)?;

    // Prepare the AXFR query message.
    let zone_name: &NewName =
        ParseBytes::parse_bytes(apex.as_slice()).expect("a parsed zone apex is a valid name");
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
        .expect("the AXFR query fits in the buffer");
    let message = Bytes::copy_from_slice(msgbuilder.finish().as_bytes());
    let message = OldMessage::from_octets(message).expect("'Message' is at least 12 bytes long");

    // Prepare a TCP client, possibly with TSIG.
    let tcp_conn = TcpStream::connect(*addr)
        .await
        .map_err(TransferError::Connect)?;
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

    // Send the AXFR and interpret the response stream.
    let request = RequestMessageMulti::new(message).unwrap();
    let mut response = SendRequestMulti::send_request(&*client, request);
    let mut interpreter = XfrResponseInterpreter::new();

    let mut refresh = DEFAULT_REFRESH;
    let mut retry = DEFAULT_RETRY;

    while !interpreter.is_finished() {
        let message = response
            .get_response()
            .await
            .map_err(TransferError::Client)?
            .ok_or(TransferError::IncompleteResponse)?;
        let updates = interpreter
            .interpret_response(message)
            .map_err(TransferError::Xfr)?;
        for update in updates {
            let update = update.map_err(TransferError::XfrIter)?;
            if let Some((soa_refresh, soa_retry)) = soa_timers(&update) {
                refresh = soa_refresh;
                retry = soa_retry;
            }
            updater.apply(update).await.map_err(TransferError::Update)?;
        }
    }

    let catalog = Catalog::parse_zone(&zone).map_err(TransferError::Parse)?;

    Ok(TransferredCatalog {
        catalog,
        refresh,
        retry,
    })
}

/// The default SOA REFRESH used when the catalog has no usable SOA.
const DEFAULT_REFRESH: Ttl = Ttl::from_secs(3600);

/// The default SOA RETRY used when the catalog has no usable SOA.
const DEFAULT_RETRY: Ttl = Ttl::from_secs(600);

/// Extracts the SOA REFRESH and RETRY intervals from a zone update, if it
/// carries an apex SOA record.
fn soa_timers<N>(
    update: &ZoneUpdate<domain::base::Record<N, ZoneRecordData<Bytes, N>>>,
) -> Option<(Ttl, Ttl)> {
    let record = match update {
        ZoneUpdate::AddRecord(record) => record,
        ZoneUpdate::Finished(record) => record,
        _ => return None,
    };
    if let ZoneRecordData::Soa(soa) = record.data() {
        Some((soa.refresh(), soa.retry()))
    } else {
        None
    }
}

//============ Errors ========================================================

//----------- TransferError --------------------------------------------------

/// An error transferring or parsing a catalog zone.
#[derive(Debug)]
pub enum TransferError {
    /// Could not connect to the primary.
    Connect(std::io::Error),

    /// A DNS client error occurred.
    Client(client::request::Error),

    /// An XFR interpretation error occurred.
    Xfr(xfr::protocol::Error),

    /// An XFR iteration error occurred.
    XfrIter(xfr::protocol::IterationError),

    /// The response stream ended prematurely.
    IncompleteResponse,

    /// The zone could not be updated from the transfer.
    Update(domain::zonetree::update::Error),

    /// The transferred zone is not a valid catalog zone.
    Parse(ParseCatalogError),
}

impl std::error::Error for TransferError {}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(error) => {
                write!(f, "could not connect to the primary: {error}")
            }
            Self::Client(error) => {
                write!(f, "could not communicate with the primary: {error}")
            }
            Self::Xfr(error) => {
                write!(f, "the catalog transfer was malformed: {error}")
            }
            Self::XfrIter(_) => {
                write!(f, "the catalog transfer was malformed")
            }
            Self::IncompleteResponse => {
                write!(f, "the catalog transfer ended prematurely")
            }
            Self::Update(error) => {
                write!(f, "could not assemble the catalog zone: {error}")
            }
            Self::Parse(error) => {
                write!(f, "the catalog zone is invalid: {error}")
            }
        }
    }
}
