//! Restoring persisted zone data.

use std::{
    fs::File,
    io::{self},
    path::Path,
    sync::Arc,
};

use cascade_zonedata::{
    DiffData, LoadedZonePatcher, LoadedZoneRestorer, RegularRecord, SignedZonePatcher,
    SignedZoneRestorer, SoaRecord,
};
use domain::{
    new::{
        base::{RType, Serial, name::NameBuf, parse::ParseMessageBytes},
        rdata::Soa,
    },
    utils::dst::UnsizedCopy,
};
use tracing::{info, trace};

use crate::{
    center::Center,
    persistence::stream::{StreamingParser, StreamingParserError},
    zone::Zone,
};

/// Restore the loaded instance data of a zone.
///
/// Returns Ok(true) if data was stored, Ok(false) if there was nothing to
/// restore, or Err(..) on error.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn restore_loaded(
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    restorer: &mut LoadedZoneRestorer,
) -> io::Result<bool> {
    let mut state = zone.write(center);
    if state.persisted_loaded_diff_paths.is_empty() {
        return io::Result::Ok(false);
    }

    info!(
        "Restoring loaded records for zone '{}' from persisted data",
        zone.name
    );
    state.storage.diffs.clear();

    // Determine the paths to read from. Each zone is persisted as an AXFR
    // plus zero or more IXFRs. The restorer takes a base path ending in an
    // unsigned integer number and loads that file plus N more, where the
    // final number in the path is replaced by the previous number plus one
    // each time.
    let loaded_source = center
        .config
        .zone_state_dir
        .join(format!("{}.loaded.0", zone.name));
    let count = state.persisted_loaded_diff_paths.len();
    drop(state);

    // Process the initial "loaded" AXFR wire format dump.
    let (soa, records) = load_axfr_wire_dump(loaded_source.as_std_path()).map_err(|err| {
        io::Error::other(format!("Loading snapshot '{loaded_source}' failed: {err}"))
    })?;
    let mut loaded_replacer = restorer.fill().ok_or(io::Error::other(
        "Internal error: Could not acquire replacer".to_string(),
    ))?;
    loaded_replacer.set_soa(soa.clone()).unwrap();
    loaded_replacer.set_records(records).unwrap();
    loaded_replacer.add(soa.clone().into()).unwrap();
    loaded_replacer.apply().unwrap();
    trace!(
        "Restored loaded snapshot for SOA serial {} for zone '{}' from file '{loaded_source}'",
        soa.rdata.serial, zone.name
    );

    if count == 1 {
        info!("Restored loaded snapshot for zone '{}'", zone.name);
        return io::Result::Ok(true);
    }

    let mut source = loaded_source.to_path_buf();
    let mut all_serials = vec![];

    for i in 1..count {
        let mut loaded_patcher = restorer
            .patch()
            .ok_or(io::Error::other("Internal error: Patch failed".to_string()))?;
        source.set_extension(i.to_string());

        let (start_serial, end_serial) = load_ixfr_wire_dump(source.as_std_path(), |event| {
            apply_ixfr_event_to_loaded_data(&mut loaded_patcher, event);
        })
        .map_err(|err| io::Error::other(format!("Loading diff '{source}' failed: {err}",)))?;

        loaded_patcher.next_patchset().map_err(|err| {
            io::Error::other(format!("Internal error: Next patchset failed: {err}"))
        })?;

        loaded_patcher
            .apply()
            .map_err(|err| io::Error::other(format!("Internal error: Apply failed: {err}")))?;

        if let Some(diff) = restorer.take_diff() {
            // Store the loaded diff to be used as part of serving an IXFR.
            let mut state = zone.write(center);
            state
                .storage
                .diffs
                .push((diff.into(), DiffData::new().into()));

            trace!(
                "Stored IXFR loaded diff for SOA serial {} from file '{loaded_source}': serial {start_serial} -> {end_serial}",
                soa.rdata.serial,
            );
        }

        let start_serial: u32 = start_serial.into();
        let end_serial: u32 = end_serial.into();
        all_serials.push((start_serial, end_serial));
    }
    trace!(
        "Restored loaded diff for SOA serial {} for zone '{}' from file '{loaded_source}' with diff serials: {all_serials:?}",
        soa.rdata.serial, zone.name
    );

    info!(
        "Restored loaded snapshot and {} diffs for zone '{}'",
        count - 1,
        zone.name
    );
    io::Result::Ok(true)
}

/// Restore the signed instance data of a zone.
///
/// Returns Ok(true) if data was stored, Ok(false) if there was nothing to
/// restore, or Err(..) on error.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn restore_signed(
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    restorer: &mut SignedZoneRestorer,
) -> io::Result<bool> {
    let state = zone.read();
    if state.persisted_signed_diff_paths.is_empty() {
        return io::Result::Ok(false);
    }

    info!(
        "Restoring signed records for zone '{}' from persisted data",
        zone.name
    );

    // Determine the paths to read from. Each zone is persisted as an AXFR
    // plus zero or more IXFRs. The restorer takes a base path ending in an
    // unsigned integer number and loads that file plus N more, where the
    // final number in the path is replaced by the previous number plus one
    // each time.
    let signed_source = center
        .config
        .zone_state_dir
        .join(format!("{}.signed.0", zone.name));
    let count = state.persisted_signed_diff_paths.len();
    drop(state);

    // Process the initial "signed" AXFR wire format dump.
    let (soa, records) = load_axfr_wire_dump(signed_source.as_std_path()).map_err(|err| {
        io::Error::other(format!(
            "Loading snapshot from '{signed_source}' failed: {err}"
        ))
    })?;
    let mut signed_replacer = restorer.fill().ok_or(io::Error::other(
        "Internal error: Could not acquire replacer".to_string(),
    ))?;
    signed_replacer.set_soa(soa.clone()).unwrap();
    signed_replacer.set_records(records).unwrap();
    signed_replacer.add(soa.clone().into()).unwrap();
    signed_replacer.apply().unwrap();
    trace!(
        "Restored signed snapshot for SOA serial {} for zone '{}' from file '{signed_source}'",
        soa.rdata.serial, zone.name
    );

    if count == 1 {
        info!("Restored signed snapshot for zone '{}'", zone.name);
        return io::Result::Ok(true);
    }

    // Process zero or more "signed" IXFR wire format dumps.
    let mut source = signed_source.to_path_buf();
    let mut all_serials = vec![];

    // Load each diff and apply it to the zone, retrieving a single DiffData
    // per signed diff. Store each signed DiffData alongside the corresponding
    // loaded DiffData that was restored earlier in restore_loaded(). These
    // DiffData's will be used to respond to IXFR requests, while at the same
    // time also building up the entire signed zone that should be served for
    // AXFR requests.
    for i in 1..count {
        let mut signed_patcher = restorer
            .patch()
            .ok_or(io::Error::other("Internal error: Patch failed".to_string()))?;
        source.set_extension(i.to_string());

        let (start_serial, end_serial) = load_ixfr_wire_dump(source.as_std_path(), |event| {
            apply_ixfr_event_to_signed_data(&mut signed_patcher, event);
        })
        .map_err(|err| io::Error::other(format!("Loading diff '{source}' failed: {err}")))?;

        signed_patcher.next_patchset().map_err(|err| {
            io::Error::other(format!("Internal error: Next patchset failed: {err}"))
        })?;

        signed_patcher
            .apply()
            .map_err(|err| io::Error::other(format!("Internal error: Apply failed: {err}")))?;

        if let Some(signed_diff) = restorer.take_diff() {
            let mut state = zone.write(center);
            // Get the diff pair (loaded diff and missing signed diff) that
            // this signed diff needs to be inserted into. If the signed diff
            // was caused by incremental signing then a loaded diff won't have
            // been available to restore, we need to use an empty loaded diff
            // in that case.
            if let Some(partial_diff) = state.storage.diffs.get_mut(i - 1) {
                // Insert the signed diff alongside the loaded diff, unless
                // the signed diff already unexpectedly exists.
                assert!(partial_diff.1.is_empty());
                partial_diff.1 = signed_diff.into();
                trace!(
                    "Updated signed part of IXFR in-memory diff for SOA loaded serial -{:?}:+{:?} -> signed serial -{:?}:+{:?} from file '{signed_source}'",
                    partial_diff
                        .0
                        .removed_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                    partial_diff
                        .0
                        .added_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                    partial_diff
                        .1
                        .removed_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                    partial_diff
                        .1
                        .added_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                );
            } else {
                let loaded_diff = Arc::new(DiffData::new());
                trace!(
                    "Storing IXFR in-memory diff for SOA loaded serial -{:?}:+{:?} -> signed serial -{:?}:+{:?} from file '{signed_source}'",
                    loaded_diff
                        .removed_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                    loaded_diff
                        .added_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                    signed_diff
                        .removed_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                    signed_diff
                        .added_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                );
                state.storage.diffs.push((loaded_diff, signed_diff.into()));
            }
        }

        let start_serial: u32 = start_serial.into();
        let end_serial: u32 = end_serial.into();
        all_serials.push((start_serial, end_serial));
    }
    trace!(
        "Restored signed diff for SOA serial {} for zone '{}' from file '{signed_source}' with diff serials: {all_serials:?}",
        soa.rdata.serial, zone.name
    );

    info!(
        "Restored signed snapshot and {} diffs for zone '{}'",
        count - 1,
        zone.name
    );
    io::Result::Ok(true)
}

/// Maps IxfrEvents onto LoadedZonePatcher actions.
fn apply_ixfr_event_to_loaded_data(patcher: &mut LoadedZonePatcher<'_>, event: IxfrEvent) {
    match event {
        IxfrEvent::Remove(r) if r.rtype == RType::SOA => {
            patcher.remove(r.clone()).unwrap();
            patcher.remove_soa(r.into()).unwrap();
        }
        IxfrEvent::Remove(r) => patcher.remove(r).unwrap(),
        IxfrEvent::Add(r) if r.rtype == RType::SOA => {
            patcher.add(r.clone()).unwrap();
            patcher.add_soa(r.into()).unwrap()
        }
        IxfrEvent::Add(r) => patcher.add(r).unwrap(),
        IxfrEvent::EndOfUpdate => patcher.next_patchset().unwrap(),
    }
}

/// Maps IxfrEvents onto SignedZonePatcher actions.
fn apply_ixfr_event_to_signed_data(patcher: &mut SignedZonePatcher<'_>, event: IxfrEvent) {
    match event {
        IxfrEvent::Remove(r) if r.rtype == RType::SOA => {
            patcher.remove(r.clone()).unwrap();
            patcher.remove_soa(r.into()).unwrap();
        }
        IxfrEvent::Remove(r) => patcher.remove(r).unwrap(),
        IxfrEvent::Add(r) if r.rtype == RType::SOA => {
            patcher.add(r.clone()).unwrap();
            patcher.add_soa(r.into()).unwrap()
        }
        IxfrEvent::Add(r) => patcher.add(r).unwrap(),
        IxfrEvent::EndOfUpdate => patcher.next_patchset().unwrap(),
    }
}

/// An error occurred while restoring persisted zone data.
pub enum RestoreError {
    /// A SOA record was expected by some other record type was encountered.
    ExpectedSoaRecord(RType),

    /// A persisted wire format resource record could not be parsed.
    ParseError(String),

    /// An I/O error occurred while reading the persisted zone data.
    IoError(std::io::Error),
}

//--- impl From

impl From<std::io::Error> for RestoreError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<StreamingParserError> for RestoreError {
    fn from(err: StreamingParserError) -> Self {
        match err {
            StreamingParserError::IoError(err) => RestoreError::IoError(err),
            StreamingParserError::ParseError(err) => RestoreError::ParseError(err),
        }
    }
}

//--- impl Display

impl std::fmt::Display for RestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Restore error: ")?;
        match self {
            RestoreError::ExpectedSoaRecord(rtype) => write!(
                f,
                "incorrect remove diff header: expected SOA, found {rtype}"
            ),
            RestoreError::ParseError(err) => write!(f, "invalid record: {err}"),
            RestoreError::IoError(err) => write!(f, "i/o error: {err}"),
        }
    }
}

/// Read a collection of resource records in AXFR wire format from disk.
fn load_axfr_wire_dump(source: &Path) -> Result<(SoaRecord, Vec<RegularRecord>), RestoreError> {
    let mut reader = StreamingParser::new(File::open(source)?);

    let (start_soa, start_soa_rdata) = reader.parse_soa()?;

    let mut records = vec![];
    loop {
        // Parse remaining resource records from the current read
        // index in the buffer, each time receiving back the 'rest'
        // index at which parsing should start on the next iteration
        // of the loop.
        let r = reader.parse_rr()?;

        // If the parsed record is a SOA it should be identical to
        // the SOA record that started the AXFR dump and signals the
        // end of the dump.
        //
        // TODO: If the SOA is not at the apex should we keep it and
        // keep going?
        if r.rtype == RType::SOA {
            // An AXFR ends with a SOA RR identical to the start SOA.
            // Since we persisted the AXFR wire dump to disk it is a
            // very unexpected error if it does not match the starting
            // SOA.
            if (r.rname.as_ref() == &*start_soa.0.rname
                || r.rclass == start_soa.0.rclass
                || r.ttl == start_soa.ttl)
                && let Ok(soa_rdata) = Soa::<NameBuf>::parse_message_bytes(r.rdata.bytes(), 0)
                && soa_rdata == start_soa_rdata
            {
                break;
            }
        }

        let r = r.transform(|name| name.unsized_copy_into(), |data| data);
        records.push(RegularRecord(r));
    }

    Ok((start_soa, records))
}

/// An IXFR event to be handled by a caller of [`load_ixfr_wire_dump()`].
enum IxfrEvent {
    /// A record was removed from the zone.
    Remove(RegularRecord),

    /// A record was added to the zone.
    Add(RegularRecord),

    /// The end of a single diff from one serial to another was encountered.
    EndOfUpdate,
}

/// Apply the changes recorded in an IXFR wire format file.
///
/// The manner in which the changes are "applied" is defined by a caller
/// provided closure.
fn load_ixfr_wire_dump<F>(
    source: &Path,
    mut rr_handler: F,
) -> Result<(Serial, Serial), RestoreError>
where
    F: FnMut(IxfrEvent),
{
    let mut reader = StreamingParser::new(File::open(source)?);

    let (start_soa, start_soa_rdata) = reader.parse_soa()?;

    let mut oldest_soa = None;

    // Parse one or more diff sequences.
    loop {
        // Parse one diff sequence:
        //   "Each difference sequence represents one update to the
        //    zone (one SOA serial change) consisting of deleted RRs
        //    and added RRs.  The first RR of the deleted RRs is the
        //    older SOA RR and the first RR of the added RRs is the
        //    newer SOA RR."
        // Iterate over a sequence of resource records to remove
        // followed by a sequence of resource records to add,

        // Read the first deleted RR which should be a SOA RR.
        let r = reader.parse_rr()?;

        if r.rtype != RType::SOA {
            // If this is the first RR of the sequence it MUST
            // be a SOA RR.
            return Err(RestoreError::ExpectedSoaRecord(r.rtype));
        }

        if oldest_soa.is_none() {
            let soa = Soa::<NameBuf>::parse_message_bytes(r.rdata.bytes(), 0).unwrap();
            oldest_soa = Some(soa);
        }

        let r = RegularRecord(r.transform(|name| name.unsized_copy_into(), |data| data));
        rr_handler(IxfrEvent::Remove(r));

        // Read more removed RRs until a SOA signals the end of the
        // removed RRs and the start of the added RRs.
        loop {
            let r = reader.parse_rr().map_err(|err| {
                io::Error::other(format!(
                    "Failed to parse persisted diff removed resource record at pos {}: {err}",
                    reader.stream_position()
                ))
            })?;

            let r = RegularRecord(r.transform(|name| name.unsized_copy_into(), |data| data));
            if r.rtype == RType::SOA {
                rr_handler(IxfrEvent::Add(r));
                break;
            } else {
                rr_handler(IxfrEvent::Remove(r));
            }
        }

        // Read more added RRs until a SOA signals the end of added RRs.
        loop {
            let r = reader.parse_rr().map_err(|err| {
                io::Error::other(format!(
                    "Failed to parse persisted diff added resource record at pos {}: {err}",
                    reader.stream_position()
                ))
            })?;

            let r =
                RegularRecord(r.transform(|name| name.unsized_copy_into(), |data| data.clone()));
            if r.rtype == RType::SOA {
                if is_same_soa(&start_soa, &start_soa_rdata, &r) {
                    // This SOA signals the end of the IXFR dump.
                    return Ok((oldest_soa.unwrap().serial, start_soa.rdata.serial));
                }

                rr_handler(IxfrEvent::EndOfUpdate);
                rr_handler(IxfrEvent::Remove(r));
                break;
            } else {
                rr_handler(IxfrEvent::Add(r));
            }
        }
    }
}

/// Compare two SOA RRs.
///
/// A convenience wrapper around the data types that the caller has.
///
/// TODO: Taking both the record and a separate copy of its RDATA in alternate
/// form just to compare two SOA RRs is lazy and silly, there must be a better
/// way.
fn is_same_soa(start_soa: &SoaRecord, start_soa_rdata: &Soa<NameBuf>, r: &RegularRecord) -> bool {
    if (r.rtype == RType::SOA
        && r.rname.as_ref() == &*start_soa.0.rname
        && r.rclass == start_soa.0.rclass
        && r.ttl == start_soa.ttl)
        && let Ok(soa_rdata) = Soa::<NameBuf>::parse_message_bytes(r.rdata.bytes(), 0)
    {
        return &soa_rdata == start_soa_rdata;
    }
    false
}
