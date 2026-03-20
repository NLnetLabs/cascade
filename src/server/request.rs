//! Parsing DNS requests.
//!
//! This module provides [`Request`], which DNS request messages can be parsed
//! into. It collates all relevant information from the request message and
//! limits itself to the kinds of requests supported by Cascade.

use domain::{
    new::{
        base::{
            Message, MessageItem, QType, RClass, RType, Record,
            name::{Name, RevName},
            wire,
        },
        rdata::{RecordData, Soa},
    },
    utils::dst::UnsizedCopy,
};

/// Parse a DNS request message into a [`Request`].
pub fn parse(message: &Message) -> Result<Request, RequestParseError> {
    let mut parser = message.parse();

    // TODO: Store domain names in a bump allocator.
    // TODO: Check the message header.
    // TODO: Support EDNS cookie requests with QCOUNT=0.
    // TODO: Check for NOTIFY messages.

    // Extract the question in the message.
    let Some(MessageItem::Question(question)) = parser.next().transpose()? else {
        return Err(RequestParseError::Wire(wire::ParseError));
    };
    // TODO: Check all fields of 'question'.

    match question.qtype {
        QType::SOA => {
            // This is a zone-related query for a SOA record.
            //
            // TODO: Check for later records.
            Ok(Request {
                kind: RequestKind::Zone(ZoneRequest {
                    name: question.qname.unsized_copy_into(),
                    kind: ZoneRequestKind::Soa,
                }),
            })
        }

        qt if qt.code == 252 => {
            // TODO: 'QType::AXFR'
            // This is a zone-related request for an AXFR.
            //
            // TODO: Check for later records.
            Ok(Request {
                kind: RequestKind::Zone(ZoneRequest {
                    name: question.qname.unsized_copy_into(),
                    kind: ZoneRequestKind::Axfr,
                }),
            })
        }

        qt if qt.code == 251 => {
            // TODO: 'QType::IXFR'
            // This is a zone-related request for an IXFR.

            // Parse the SOA record known to the client.
            let Some(MessageItem::Authority(Record {
                rname,
                rtype: rtype @ RType::SOA,
                rclass: rclass @ RClass::IN,
                ttl,
                rdata: RecordData::Soa(rdata),
            })) = parser.next().transpose()?
            else {
                return Err(RequestParseError::Wire(wire::ParseError));
            };
            if rname != question.qname {
                return Err(RequestParseError::Wire(wire::ParseError));
            }
            let known_soa = Record {
                rname: (),
                rtype,
                rclass,
                ttl,
                rdata: rdata.map_names(|n| n.unsized_copy_into()),
            };

            // TODO: Check for later records.

            Ok(Request {
                kind: RequestKind::Zone(ZoneRequest {
                    name: question.qname.unsized_copy_into(),
                    kind: ZoneRequestKind::Ixfr { known_soa },
                }),
            })
        }

        // TODO: Return a more appropriate error type?
        _ => Err(RequestParseError::Wire(wire::ParseError)),
    }
}

/// A DNS request.
//
// TODO: Borrow from the original message.
pub struct Request {
    /// The kind of request.
    pub kind: RequestKind,
    //
    // TODO:
    // - EDNS cookie state.
    // - Other EDNS options?
    // - TSIG state.
}

/// A kind of DNS request.
pub enum RequestKind {
    /// A zone related request.
    Zone(ZoneRequest),
    //
    // TODO: Generic queries.
}

/// A DNS request related to a zone.
pub struct ZoneRequest {
    /// The name of the relevant zone.
    //
    // TODO: Borrow this data.
    pub name: Box<RevName>,

    /// The kind of zone request.
    pub kind: ZoneRequestKind,
}

/// A kind of zone-related DNS request.
pub enum ZoneRequestKind {
    /// A query for the SOA record.
    Soa,

    /// An AXFR request.
    Axfr,

    /// An IXFR request.
    #[expect(dead_code)]
    Ixfr {
        /// The SOA record known to the client.
        known_soa: Record<(), Soa<Box<Name>>>,
    },
    //
    // TODO: NOTIFY messages.
}

/// An error parsing a DNS request.
pub enum RequestParseError {
    /// A low-level wire format parsing error.
    Wire(wire::ParseError),
}

impl From<wire::ParseError> for RequestParseError {
    fn from(error: wire::ParseError) -> Self {
        Self::Wire(error)
    }
}
