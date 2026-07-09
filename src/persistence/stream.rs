//! Support for streamed parsing of persisted zone data from disk.
//!
//! Rather than loading entire zone snapshots and diffs into memory and then
//! parsing it.
use std::io::{BufRead, BufReader, Read, Seek};

use cascade_zonedata::SoaRecord;
use domain::{
    new::{
        base::{
            RType, Record,
            name::{NameBuf, RevNameBuf},
            parse::SplitMessageBytes,
        },
        rdata::{BoxedRecordData, Soa},
    },
    utils::dst::UnsizedCopy,
};

#[allow(rustdoc::bare_urls)]
/// The maximum size a DNS message is allowed to be, according to RFC 1035:
///
/// https://www.rfc-editor.org/info/rfc1035/#section-4.2.2
///   "The message is prefixed with a two byte length field which gives the
///    message length, excluding the two byte length field."
const MAX_DNS_MESSAGE_LEN_IN_BYTES: usize = 65535;

/// The maximum amount of data to load into memory from disk at once.
///
/// Too small and more time is spent copying partial messages from the end
/// of the buffer and the start of the next buffer in order to make a
/// contiguous message that can be parsed by split_message_bytes().
///
/// Too large and memory usage is increased.
///
/// The current value, 5 MiB, is a value chosen somewhat arbitrarily as being
/// larger than a single DNS message (65 KiB) and large enough to be able to
/// parse many messages without incurring the cost of joining message parts
/// at the buffer boundary, but small enough to impact total memory usage
/// much less than loading a large snapshot (e.g. 1 GiB) or diff entirely
/// into memory.
const STREAMING_BUF_SIZE_IN_BYTES: usize = 5 * 1024 * 1024;

pub enum StreamingParserError {
    IoError(std::io::Error),
    ParseError(String),
}

impl std::fmt::Display for StreamingParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamingParserError::IoError(err) => write!(f, "I/O error: {err}"),
            StreamingParserError::ParseError(err) => write!(f, "Parsing error: {err}"),
        }
    }
}

impl From<std::io::Error> for StreamingParserError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<String> for StreamingParserError {
    fn from(err: String) -> Self {
        Self::ParseError(err)
    }
}

/// A DNS message parser wrapper that can parse a subset of an entire
/// persisted zone AXFR snapshot/IXFR diff zone without loading the entire
/// snapshot/diff in memory.
pub struct StreamingParser<R> {
    /// A buffered reader for amortizing the cost of kernel I/O read calls.
    reader: BufReader<R>,

    /// Scratch space used to reconstruct a complete DNS message from the
    /// part at the end of a full reader buffer and the beginning of the
    /// next filled reader buffer.
    overflow: [u8; MAX_DNS_MESSAGE_LEN_IN_BYTES],
}

impl<R: Read> StreamingParser<R> {
    /// Construct a new streaming parser over the given reader.
    ///
    /// The reader must impl std::io::Read.
    pub fn new(reader: R) -> Self {
        let reader = BufReader::with_capacity(STREAMING_BUF_SIZE_IN_BYTES, reader);

        Self {
            reader,
            overflow: [0u8; MAX_DNS_MESSAGE_LEN_IN_BYTES],
        }
    }

    /// Read a single resource record of any type from the data stream.
    pub fn parse_rr(
        &mut self,
    ) -> Result<Record<RevNameBuf, BoxedRecordData>, StreamingParserError> {
        self.parse_any_rr()
    }

    /// Convenience function: Read a SOA resource record from the data stream.
    ///
    /// Returns the SOA record and the extracted SOA RDATA.
    pub fn parse_soa(&mut self) -> Result<(SoaRecord, Soa<NameBuf>), StreamingParserError> {
        let first_rr: Record<RevNameBuf, Soa<NameBuf>> = self.parse_any_rr()?;

        if first_rr.rtype != RType::SOA {
            return Err(format!(
                "Persisted XFR dump record has RTYPE '{}' but expected a SOA RR.",
                first_rr.rtype.code
            )
            .into());
        }

        // Save the SOA rdata for comparison later, before we convert it from
        // using NameBuf typed fields to having Box<Name> typed fields (which
        // is the format we store resource records in longer term in memory).
        let soa_rdata = first_rr.rdata.clone();
        let soa_rr = SoaRecord(first_rr.transform_ref(
            |name: &RevNameBuf| (*name).unsized_copy_into(),
            |data: &Soa<NameBuf>| data.map_names_by_ref(|name| (*name).unsized_copy_into()),
        ));

        Ok((soa_rr, soa_rdata))
    }

    fn parse_any_rr<T: for<'a> SplitMessageBytes<'a>>(
        &mut self,
    ) -> Result<T, StreamingParserError> {
        let mut num_already_consumed = 0;

        // Get the remaining bytes from the buffer that we haven't yet consumed,
        // reading more from the source if needed. As we created the BufReader with
        // a max capacity of MAX_DNS_MESSAGE_LEN bytes there can only be an entire
        // DNS message in the buffer, or a partial DNS message.
        let mut buf = self.reader.fill_buf()?;

        // Try and parse the DNS message. This will fail if the DNS message
        // is incomplete or invalid or unsupported, but we don't know which of
        // these failure modes occurred.
        let mut res = T::split_message_bytes(buf, 0);

        // If parsing failed it might be because the DNS message didn't fit
        // in the buffer. To find out we have to try and fetch more bytes of
        // data but we can only do that once we have consumed the bytes still
        // pending in the buffer.
        if res.is_err() && buf.len() < MAX_DNS_MESSAGE_LEN_IN_BYTES {
            // In order to try parsing the message we need all of its bytes
            // to be stored contiguously, so copy what we have into the
            // overflow buffer, consume them from the reader so that we can
            // fill up the reader again (as much as possible) then copy the
            // number of bytes that in theory could be missing from the DNS
            // message (or as many as are available).

            // 1. Copy the partial message bytes and remember how many there
            //    were so that we can later calculate the maximum number of
            //    extra message bytes that might be available.
            let partial_message_len = buf.len();
            self.overflow[0..partial_message_len].copy_from_slice(buf);

            // 2. Consume the copied bytes so that we can refill the reader.
            self.reader.consume(partial_message_len);
            num_already_consumed = partial_message_len;

            // 3. Refill the reader.
            buf = self.reader.fill_buf()?;

            // 4. Copy newly read additional message bytes, if any.
            //
            // We don't know how long the message is, DNS messages have no
            // length information (unless preceeded by a length as when sent
            // over TCP but that isn't the case here), so append up to the
            // maximum possible additional bytes of message from the reader
            // to the overflow buffer.
            if !buf.is_empty() {
                let max_extra_message_bytes = MAX_DNS_MESSAGE_LEN_IN_BYTES - num_already_consumed;
                let remaining = std::cmp::min(buf.len(), max_extra_message_bytes);
                self.overflow[num_already_consumed..num_already_consumed + remaining]
                    .copy_from_slice(&buf[0..remaining]);
            }

            // 5. Try parsing the hopefully complete DNS message bytes
            //    now that we have them in contiguous form (as required by
            //    split_message_bytes()).
            res = T::split_message_bytes(&self.overflow, 0);
        }

        res.map(|(rr, num_bytes_parsed)| {
            // Parsing succeeded, consume the (extra) message bytes that we
            // parsed.
            let num_bytes_to_consume = num_bytes_parsed - num_already_consumed;
            self.reader.consume(num_bytes_to_consume);

            // Pass the completely parsed record back to the caller.
            rr
        })
        .map_err(|err| format!("Invalid wire format RR: {err}").into())
    }
}

impl<R: Read + Seek> StreamingParser<R> {
    pub fn stream_position(&mut self) -> u64 {
        self.reader.stream_position().unwrap_or_default()
    }
}
