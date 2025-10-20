//! Cascade

pub mod api;
pub mod center;
pub mod cli;
pub mod common;
pub mod comms;
pub mod config;
pub mod daemon;
pub mod log;
pub mod manager;
pub mod metrics;
pub mod payload;
pub mod policy;
pub mod state;
pub mod targets;
pub mod tsig;
pub mod units;
pub mod util;
pub mod zone;
pub mod zonemaintenance;

#[cfg(test)]
pub mod tests;

#[macro_export]
macro_rules! println {
    ($($t:tt)*) => {{
        #[allow(clippy::disallowed_macros)]
        let x = anstream::println!($($t)*);
        x
    }};
}

#[macro_export]
macro_rules! eprintln {
    ($($t:tt)*) => {{
        #[allow(clippy::disallowed_macros)]
        let x = anstream::eprintln!($($t)*);
        x
    }};
}
