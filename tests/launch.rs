//! Launch Cascade.

// Only available on Unix machines.
#![cfg(unix)]

mod process;

#[test]
fn launch() {
    let daemon = process::DaemonBuilder::new().build();
    println!("{daemon:?}");
}
