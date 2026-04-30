//! Restoring persisted zone data.

use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
    sync::Arc,
};

use cascade_zonedata::{
    LoadedZonePatcher, LoadedZoneRestorer, RegularRecord, SignedZonePatcher, SignedZoneRestorer,
    SoaRecord,
};
use domain::{
    new::{
        base::{
            RType, Record,
            name::{NameBuf, RevNameBuf},
            parse::{ParseMessageBytes, SplitMessageBytes},
        },
        rdata::{BoxedRecordData, Soa},
    },
    utils::dst::UnsizedCopy,
};

use crate::{center::Center, zone::Zone};

/// Restore the loaded instance data of a zone.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn restore_loaded(
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    restorer: &mut LoadedZoneRestorer,
) -> io::Result<()> {
    let state = zone.state.lock().unwrap();
    if !state.persisted_loaded_diffs.is_empty() {
        // Determine the paths to read from. Each zone is persisted as an AXFR
        // plus zero or more IXFRs. The restorer takes a base path ending in
        // an unsigned integer number and loads that file plus N more, where
        // the final number in the path is replaced by the previous number
        // plus one each time.
        let loaded_source = center
            .config
            .zone_state_dir
            .join(format!("{}.loaded.0", zone.name));
        let count = state.persisted_loaded_diffs.len();
        let mut buf = Vec::<u8>::new();

        // Extract the initial unsigned integer number file extension.
        let n = loaded_source
            .extension()
            .unwrap()
            .to_string()
            .parse::<usize>()
            .unwrap();

        // Process the initial "loaded" AXFR wire format dump.
        let (soa, records) = load_axfr_wire_dump(loaded_source.as_std_path(), &mut buf).unwrap();
        let mut loaded_replacer = restorer.fill().unwrap(); // TODO: SAFETY
        loaded_replacer.set_soa(soa).unwrap();
        loaded_replacer.set_records(records).unwrap();
        loaded_replacer.apply().unwrap();

        if count > 1 {
            let mut loaded_patcher = restorer.patch().unwrap(); // TODO: SAFETY
            let mut source = loaded_source.to_path_buf();
            for i in 1..count {
                source.set_extension((n + i).to_string());

                let loaded_patcher = &mut loaded_patcher;
                load_ixfr_wire_dump(source.as_std_path(), &mut buf, |event| {
                    apply_ixfr_event_to_loaded_data(loaded_patcher, event);
                })
                .unwrap();

                loaded_patcher.next_patchset().unwrap()
            }
            loaded_patcher.apply().unwrap();
        }
    }

    io::Result::Ok(())
}

/// Restore the loaded instance data of a zone.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn restore_signed(
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    restorer: &mut SignedZoneRestorer,
) -> io::Result<()> {
    let state = zone.state.lock().unwrap();
    if !state.persisted_loaded_diffs.is_empty() {
        // Determine the paths to read from. Each zone is persisted as an AXFR
        // plus zero or more IXFRs. The restorer takes a base path ending in
        // an unsigned integer number and loads that file plus N more, where
        // the final number in the path is replaced by the previous number
        // plus one each time.
        let signed_source = center
            .config
            .zone_state_dir
            .join(format!("{}.signed.0", zone.name));
        let count = state.persisted_signed_diffs.len();
        let mut buf = Vec::<u8>::new();

        // Extract the initial unsigned integer number file extension.
        let n = signed_source
            .extension()
            .unwrap()
            .to_string()
            .parse::<usize>()
            .unwrap();

        // Process the initial "signed" AXFR wire format dump.
        let (soa, records) = load_axfr_wire_dump(signed_source.as_std_path(), &mut buf).unwrap();
        let mut signed_replacer = restorer.fill().unwrap(); // TODO: SAFETY
        signed_replacer.set_soa(soa).unwrap();
        signed_replacer.set_records(records).unwrap();
        signed_replacer.apply().unwrap();

        // Process zero or more "signed" IXFR wire format dumps.
        if count > 1 {
            let mut signed_patcher = restorer.patch().unwrap(); // TODO: SAFETY
            let mut source = signed_source.to_path_buf();
            for i in 1..count {
                source.set_extension((n + i).to_string());

                load_ixfr_wire_dump(source.as_std_path(), &mut buf, |event| {
                    apply_ixfr_event_to_signed_data(&mut signed_patcher, event);
                })
                .unwrap();

                signed_patcher.next_patchset().unwrap()
            }
            signed_patcher.apply().unwrap();
        }
    }
    io::Result::Ok(())
}

fn parse_rr(
    buf: &[u8],
    pos: usize,
) -> Result<(Record<RevNameBuf, BoxedRecordData>, usize), String> {
    Record::<RevNameBuf, BoxedRecordData>::split_message_bytes(buf, pos)
        .map_err(|err| format!("Invalid wire format RR: {err}"))
}

fn parse_soa(buf: &[u8], pos: usize) -> Result<(SoaRecord, Soa<NameBuf>, usize), String> {
    let (first_rr, rest) = Record::<RevNameBuf, Soa<NameBuf>>::split_message_bytes(buf, pos)
        .map_err(|err| {
            format!("Failed to parse record of persisted XFR dump as a SOA record: {err}")
        })?;

    if first_rr.rtype != RType::SOA {
        return Err(format!(
            "Persisted XFR dump record has RTYPE '{}' which is not a SOA RR.",
            first_rr.rtype.code
        ));
    }

    // Save the SOA rdata for comparison later, before we convert it from
    // using NameBuf typed fields to having Box<Name> typed fields (which
    // is the format we store resource records in longer term in memory).
    let soa_rdata = first_rr.rdata.clone();
    let soa_rr = SoaRecord(first_rr.transform_ref(
        |name: &RevNameBuf| (*name).unsized_copy_into(),
        |data: &Soa<NameBuf>| data.map_names_by_ref(|name| (*name).unsized_copy_into()),
    ));

    Ok((soa_rr, soa_rdata, rest))
}

fn load_file_into_memory(source: &Path, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    buf.clear();
    BufReader::new(File::open(source)?).read_to_end(buf)
}

fn load_axfr_wire_dump(
    source: &Path,
    buf: &mut Vec<u8>,
) -> Result<(SoaRecord, Vec<RegularRecord>), String> {
    load_file_into_memory(source, buf).map_err(|err| err.to_string())?;

    let (start_soa, start_soa_rdata, mut rest) = parse_soa(buf, 0)?;

    let mut records = vec![];
    loop {
        // Parse remaining resource records from the current read
        // index in the buffer, each time receiving back the 'rest'
        // index at which parsing should start on the next iteration
        // of the loop.
        let r;
        (r, rest) = parse_rr(buf, rest)?;

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
            if r.rname.as_ref() == &*start_soa.0.rname
                || r.rclass == start_soa.0.rclass
                || r.ttl == start_soa.ttl
            {
                let soa_rdata = Soa::<NameBuf>::parse_message_bytes(r.rdata.bytes(), 0).unwrap();
                if soa_rdata == start_soa_rdata {
                    break;
                }
            }
        }

        let r = r.transform(|name| name.unsized_copy_into(), |data| data);
        records.push(RegularRecord(r));
    }

    Ok((start_soa, records))
}

fn load_ixfr_wire_dump<F>(source: &Path, buf: &mut Vec<u8>, mut rr_handler: F) -> Result<(), String>
where
    F: FnMut(IxfrEvent),
{
    load_file_into_memory(source, buf).map_err(|err| err.to_string())?;

    let buf = buf.as_slice();
    let (start_soa, start_soa_rdata, mut rest) = parse_soa(buf, 0)?;

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
        let r;
        (r, rest) = parse_rr(buf, rest)?;

        if r.rtype != RType::SOA {
            // If this is the first RR of the sequence it MUST
            // be a SOA RR.
            return Err(format!(
                "Expected first record of IXFR remove sequence to be a SOA RR but found RTYPE {}",
                r.rtype.code
            ));
        }

        let r = RegularRecord(r.transform(|name| name.unsized_copy_into(), |data| data));
        rr_handler(IxfrEvent::Remove(r));

        // Read more removed RRs until a SOA signals the end of the
        // removed RRs and the start of the added RRs.
        loop {
            let r;
            (r, rest) = parse_rr(buf, rest)?;

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
            let r;
            (r, rest) = parse_rr(buf, rest)?;

            let r = RegularRecord(r.transform(|name| name.unsized_copy_into(), |data| data));
            if r.rtype == RType::SOA {
                if is_same_soa(&start_soa, &start_soa_rdata, &r) {
                    // This SOA signals the end of the IXFR dump.
                    return Ok(());
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

fn is_same_soa(start_soa: &SoaRecord, start_soa_rdata: &Soa<NameBuf>, r: &RegularRecord) -> bool {
    if r.rtype == RType::SOA
        && r.rname.as_ref() == &*start_soa.0.rname
        && r.rclass == start_soa.0.rclass
        && r.ttl == start_soa.ttl
    {
        let soa_rdata = Soa::<NameBuf>::parse_message_bytes(r.rdata.bytes(), 0).unwrap();
        return &soa_rdata == start_soa_rdata;
    }
    false
}

enum IxfrEvent {
    Remove(RegularRecord),
    Add(RegularRecord),
    EndOfUpdate,
}

fn apply_ixfr_event_to_loaded_data(patcher: &mut LoadedZonePatcher<'_>, event: IxfrEvent) {
    match event {
        IxfrEvent::Remove(r) if r.rtype == RType::SOA => patcher.remove_soa(r.into()).unwrap(),
        IxfrEvent::Remove(r) => patcher.remove(r).unwrap(),
        IxfrEvent::Add(r) if r.rtype == RType::SOA => patcher.add_soa(r.into()).unwrap(),
        IxfrEvent::Add(r) => patcher.add(r).unwrap(),
        IxfrEvent::EndOfUpdate => patcher.next_patchset().unwrap(),
    }
}

fn apply_ixfr_event_to_signed_data(patcher: &mut SignedZonePatcher<'_>, event: IxfrEvent) {
    match event {
        IxfrEvent::Remove(r) if r.rtype == RType::SOA => patcher.remove_soa(r.into()).unwrap(),
        IxfrEvent::Remove(r) => patcher.remove(r).unwrap(),
        IxfrEvent::Add(r) if r.rtype == RType::SOA => patcher.add_soa(r.into()).unwrap(),
        IxfrEvent::Add(r) => patcher.add(r).unwrap(),
        IxfrEvent::EndOfUpdate => patcher.next_patchset().unwrap(),
    }
}
