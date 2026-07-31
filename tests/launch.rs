//! Launch Cascade.

// Only available on Unix machines.
#![cfg(unix)]

use cascade_tests::process;

#[test]
fn launch() {
    let daemon = process::DaemonBuilder::new().build();
    println!("{daemon:?}");
}
