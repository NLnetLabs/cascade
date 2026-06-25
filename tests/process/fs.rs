//! A filesystem for tests.
//!
//! The Cascade daemon works with many files and needs to be configured to use
//! certain directories. For tests, these need to be located within a temporary
//! directory that will be cleaned up appropriately. [`DaemonFs`] provides this
//! functionality, along with easy access to important files and directories.
