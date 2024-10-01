//! A DNS primary server – library crate.

pub use crate::config::Config;
pub use crate::error::ExitError;

pub mod config;
pub mod error;
pub mod operation;
pub mod process;
pub mod zonemaintenance;