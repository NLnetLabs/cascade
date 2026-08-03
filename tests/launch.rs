//! Launch Cascade.

// Only available on Unix machines.
#![cfg(unix)]

use cascade_tests::process;
use tracing::info;

#[test]
fn launch() {
    let _ = tracing_subscriber::fmt::try_init();
    let daemon = process::DaemonBuilder::new().build();

    // Set up a simple policy.
    let policy = cascade_policy_file::v1::Spec::default();
    let policy = cascade_policy_file::VersionedSpec::V1(policy);
    let policy = toml::to_string(&policy).unwrap();
    let path = daemon.filesystem.policies.join("simple.toml");
    std::fs::write(path, policy).unwrap();
    info!("reload policies: {:?}", daemon.client.reload_policies());

    info!("zone names: {:?}", daemon.client.zone_names());
    info!("policy names: {:?}", daemon.client.policy_names());
}
