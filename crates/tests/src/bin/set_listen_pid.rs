//! A simple binary to set the `LISTEN_PID` environment variable.
//!
//! Usage: `set_listen_pid <cmd> <args...>`.
//!
//! Sets `LISTEN_PID` to the current PID and then `exec`'s `<cmd>`.
//!
//! While it would be nice to spawn `<cmd>` directly and set `LISTEN_PID` for
//! it, this is surprisingly difficult to implement safely. An intermediate
//! process is the simplest way.

use std::os::unix::process::CommandExt;

fn main() {
    let pid = nix::unistd::getpid();

    let mut args = std::env::args_os();
    let _ = args.next(); // argv[0], path to self
    let cmd = args.next().unwrap();

    let err = std::process::Command::new(cmd)
        .args(args)
        .env("LISTEN_PID", pid.to_string())
        .exec();
    panic!("`exec()` failed: {err}");
}
