//! Launch Cascade.

// Only available on Unix machines.
#![cfg(unix)]

use cascade_tests::process;

#[test]
fn launch() {
    let daemon = process::DaemonBuilder::new().build();

    // Set up a simple policy.
    let policy = cascade_policy_file::v1::Spec::default();
    let policy = cascade_policy_file::VersionedSpec::V1(policy);
    let policy = toml::to_string(&policy).unwrap();
    let path = daemon.filesystem.policies.join("simple.toml");
    std::fs::write(path, policy).unwrap();
    println!("reload policies: {:?}", daemon.client.reload_policies());

    println!("zone names: {:?}", daemon.client.zone_names());
    println!("policy names: {:?}", daemon.client.policy_names());
}
