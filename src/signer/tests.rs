//! Testing zone signing.

#![allow(clippy::disallowed_macros, reason = "tests")]

use std::{
    io::{BufReader, BufWriter, Write},
    sync::{Arc, RwLock},
};

use bytes::{BufMut, Bytes};
use camino::{Utf8Path, Utf8PathBuf};
use cascade_policy_file::v1::SignerDenialSpec;
use cascade_zonedata::{
    LoadedZoneReviewer, RegularRecord, SignedZoneBuilder, SignedZoneReviewer, ZoneDataStorage,
    ZoneViewer,
};
use domain::{
    base::{
        Name, Rtype,
        iana::SecurityAlgorithm,
        zonefile_fmt::{self, ZonefileFmt},
    },
    dep::octseq::OctetsInto,
    dnssec::sign::keys::keyset::{self, KeySet},
    rdata::dnssec::Timestamp,
};

use crate::{
    loader::{self, ActiveLoadMetrics},
    policy::{self, PolicyVersion},
    signer::{
        incremental::LocalState,
        status::{RequestedStatus, SigningStatusPerZone, ZoneSigningStatus},
    },
    units::zone_signer::KeySetState,
};

fn policy(denial: SignerDenialSpec) -> PolicyVersion {
    use cascade_policy_file::v1::*;

    let spec = Spec {
        signer: SignerSpec {
            serial_policy: SignerSerialPolicySpec::Keep,
            signature_inception_offset: TimeSpan::from_secs(0),
            signature_lifetime: TimeSpan::from_secs(100000000),
            denial,
            ..Default::default()
        },
        ..Default::default()
    };

    policy::file::Spec::V1(spec).parse("default")
}

struct SimpleStorage {
    storage: ZoneDataStorage,
    #[allow(dead_code)]
    loaded_reviewer: LoadedZoneReviewer,
    #[allow(dead_code)]
    signed_reviewer: SignedZoneReviewer,
    #[allow(dead_code)]
    viewer: ZoneViewer,
}

impl SimpleStorage {
    fn new() -> Self {
        let (restorer, storage) = ZoneDataStorage::new();
        let ZoneDataStorage::RestoringLoaded(storage) = storage else {
            unreachable!();
        };
        let (loaded_reviewer, signed_reviewer, viewer, storage) = storage.abandon(restorer);
        Self {
            storage: ZoneDataStorage::Passive(storage),
            loaded_reviewer,
            signed_reviewer,
            viewer,
        }
    }

    fn load(&mut self, zone_name: &Name<Bytes>, path: impl AsRef<Utf8Path>) -> SignedZoneBuilder {
        let path = path.as_ref();
        let ZoneDataStorage::Passive(storage) = self.storage.take() else {
            panic!()
        };
        let (storage, mut builder) = storage.load();
        let metrics = ActiveLoadMetrics::begin(loader::Source::Zonefile { path: path.into() });
        loader::zonefile::load(zone_name, path, &mut builder, &metrics).unwrap();
        let built = builder
            .finish()
            .unwrap_or_else(|_| unreachable!("zonefile loaded successfully"));
        let (storage, mut loaded_reviewer) = storage.finish(built);
        std::mem::swap(&mut loaded_reviewer, &mut self.loaded_reviewer);
        let storage = storage.start(loaded_reviewer);
        let (storage, persister) = storage.mark_approved();
        let persisted = persister.mark_complete();
        let (storage, builder) = storage.mark_complete(persisted);
        self.storage = ZoneDataStorage::Signing(storage);
        builder
    }
}

fn keyset_state(zone_name: &Name<Bytes>) -> KeySetState {
    let mut keyset = KeySet::new(zone_name.clone().octets_into());
    let cwd: Utf8PathBuf = std::env::current_dir().unwrap().try_into().unwrap();
    let pubref =
        format!("file://{cwd}/integration-tests/incremental-signing/keys/Kexample.+015+02835.key");
    let privref = format!(
        "file://{cwd}/integration-tests/incremental-signing/keys/Kexample.+015+02835.private"
    );
    keyset
        .add_key_csk(
            pubref.clone(),
            Some(privref),
            SecurityAlgorithm::ED25519,
            2835,
            Timestamp::from(0).into(),
            keyset::Available::Available,
        )
        .unwrap();
    keyset.set_signer(&pubref, true).unwrap();
    KeySetState {
        keyset,
        apex_remove: [Rtype::DNSKEY, Rtype::CDS, Rtype::CDNSKEY].into(),
        apex_extra: [
            "example. IN DNSKEY 256 3 15 BnnbKMXdvQp2v+tzyvO/HxQGY8iYcJsWD4MN6fnr84Q=",
            "example. 3600 IN RRSIG DNSKEY 15 1 3600 1700000000 1600000000 2835 example. RMn96put9kteW8DjunEY3o0J7+MZlrC/zXVBU0h0gpFwjz9mrqo/1EvQUSO6faKaNLD2uhiJ9mg91Z1AQSq4AQ==",
        ]
        .into_iter().map(String::from).collect(),
    }
}

fn load_zonefile(path: impl AsRef<Utf8Path>, zone_name: &Name<Bytes>) -> Vec<RegularRecord> {
    let path = path.as_ref();
    let mut reader = BufReader::new(std::fs::File::open(path).unwrap());
    let mut zonefile = domain::zonefile::inplace::Zonefile::new();
    zonefile.set_origin(zone_name.clone());
    let mut writer = zonefile.writer();
    std::io::copy(&mut reader, &mut writer).unwrap();
    let zonefile = writer.into_inner();
    let mut buffer = Vec::new();
    let mut records = zonefile
        .map(|entry| match entry {
            Ok(domain::zonefile::inplace::Entry::Record(record)) => {
                buffer.clear();
                record.compose(&mut buffer).unwrap();
                let bytes = bytes::Bytes::from(buffer.clone());
                buffer.clear();
                let mut parser = domain::dep::octseq::Parser::from_ref(&bytes);
                let record = cascade_zonedata::OldParsedRecord::parse(&mut parser)
                    .unwrap()
                    .unwrap();
                cascade_zonedata::RegularRecord::from(record)
            }
            _ => panic!(),
        })
        .collect::<Vec<_>>();
    records.sort_unstable();
    records
}

fn compare_records(
    zone_name: &Name<Bytes>,
    actual: &[RegularRecord],
    expected_path: impl AsRef<Utf8Path>,
) {
    let expected_path = expected_path.as_ref();
    let expected = load_zonefile(expected_path, zone_name);
    if expected != actual {
        eprintln!("--- Expected output ({expected_path}):");
        for record in &expected {
            let record = cascade_zonedata::OldRecord::from(record.clone());
            eprintln!(
                "{}",
                record.display_zonefile(zonefile_fmt::DisplayKind::Simple)
            );
        }
        let actual_file = tempfile::NamedTempFile::new().unwrap();
        let actual_path = Utf8PathBuf::from(actual_file.path().to_str().unwrap());
        let mut writer = BufWriter::new(actual_file);
        eprintln!("\n--- Actual output:");
        for record in actual {
            let record = cascade_zonedata::OldRecord::from(record.clone());
            let record = record.display_zonefile(zonefile_fmt::DisplayKind::Simple);
            eprintln!("{record}");
            writeln!(writer, "{record}").unwrap();
        }
        eprintln!("\n--- Diff:");
        std::process::Command::new("git")
            .args([
                "diff",
                "--no-index",
                "--word-diff",
                "--",
                expected_path.as_str(),
                actual_path.as_str(),
            ])
            .status()
            .unwrap();

        // Make sure the temporary file is cleaned up.
        std::mem::drop(writer);

        panic!("Zone did not match expectation");
    }
}

fn test_full(test_idx: usize, input_idx: usize, denial: SignerDenialSpec) {
    let config = crate::config::Config::default();
    let zone_name: Name<Bytes> = "example".parse().unwrap();
    let policy = policy(denial.clone());
    let hsm_store = Default::default();
    let kmip_servers = Default::default();
    let mut storage = SimpleStorage::new();
    let mut builder = storage.load(
        &zone_name,
        format!("integration-tests/incremental-signing/zones/incremental-signing-test{test_idx}-input{input_idx}.zone"),
    );
    let keyset_state = keyset_state(&zone_name);

    // TODO: Pass the fake-time info as a parameter to the signing code?
    unsafe { std::env::set_var("CASCADE_FAKETIME", "1600000000") };

    let status = Arc::new(RwLock::new(SigningStatusPerZone {
        current_action: String::new(),
        status: ZoneSigningStatus::Requested(RequestedStatus::new()),
    }));

    let mut local_state = LocalState {
        apex_remove: Default::default(),
        apex_extra: Default::default(),
        last_signature_refresh: Timestamp::from(0).into(),
        key_tags: Default::default(),
        key_roll: None,
        previous_serial: None,
        next_min_expiration: None,
    };

    super::full::sign_zone(
        &config,
        &zone_name,
        &policy,
        &hsm_store,
        &kmip_servers,
        &mut builder,
        &mut local_state,
        keyset_state,
        status,
    )
    .unwrap();

    let mut records = builder
        .next_signed()
        .unwrap()
        .all_records()
        .cloned()
        .collect::<Vec<_>>();
    records.sort_unstable();

    let denial = match denial {
        SignerDenialSpec::NSec => "nsec",
        SignerDenialSpec::NSec3 { opt_out: false } => "nsec3",
        SignerDenialSpec::NSec3 { opt_out: true } => "nsec3-opt-out",
    };

    compare_records(
        &zone_name,
        &records,
        format!(
            "integration-tests/incremental-signing/reference-output/incremental-signing-test{test_idx}-input{input_idx}.zone.{denial}.signed.sorted"
        ),
    );
}

#[test]
fn full_t1i2_nsec() {
    test_full(1, 2, SignerDenialSpec::NSec);
}

#[test]
fn full_t2i2_nsec() {
    test_full(2, 2, SignerDenialSpec::NSec);
}

#[test]
fn full_t3i2_nsec() {
    test_full(3, 2, SignerDenialSpec::NSec);
}

#[test]
fn full_t4i2_nsec() {
    test_full(4, 2, SignerDenialSpec::NSec);
}

#[test]
fn full_t4i3_nsec() {
    test_full(4, 3, SignerDenialSpec::NSec);
}

#[test]
fn full_t5i2_nsec() {
    test_full(5, 2, SignerDenialSpec::NSec);
}

#[test]
fn full_t1i2_nsec3() {
    test_full(1, 2, SignerDenialSpec::NSec3 { opt_out: false });
}

#[test]
fn full_t2i2_nsec3() {
    test_full(2, 2, SignerDenialSpec::NSec3 { opt_out: false });
}

#[test]
fn full_t3i2_nsec3() {
    test_full(3, 2, SignerDenialSpec::NSec3 { opt_out: false });
}

#[test]
fn full_t4i2_nsec3() {
    test_full(4, 2, SignerDenialSpec::NSec3 { opt_out: false });
}

#[test]
fn full_t4i3_nsec3() {
    test_full(4, 3, SignerDenialSpec::NSec3 { opt_out: false });
}

#[test]
fn full_t5i2_nsec3() {
    test_full(5, 2, SignerDenialSpec::NSec3 { opt_out: false });
}

#[test]
fn full_t1i2_nsec3_opt_out() {
    test_full(1, 2, SignerDenialSpec::NSec3 { opt_out: true });
}

#[test]
fn full_t2i2_nsec3_opt_out() {
    test_full(2, 2, SignerDenialSpec::NSec3 { opt_out: true });
}

#[test]
fn full_t3i2_nsec3_opt_out() {
    test_full(3, 2, SignerDenialSpec::NSec3 { opt_out: true });
}

#[test]
fn full_t4i2_nsec3_opt_out() {
    test_full(4, 2, SignerDenialSpec::NSec3 { opt_out: true });
}

#[test]
fn full_t4i3_nsec3_opt_out() {
    test_full(4, 3, SignerDenialSpec::NSec3 { opt_out: true });
}

#[test]
fn full_t5i2_nsec3_opt_out() {
    test_full(5, 2, SignerDenialSpec::NSec3 { opt_out: true });
}
