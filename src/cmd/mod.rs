//! Subcommand modules. One file per top-level verb (`auth`, `agents`,
//! `regulatory`). Each module exports an `Args` struct (clap derive)
//! and a `run()` that returns the subcommand's [`crate::ExitCode`].

pub mod agents;
pub mod auth;
pub mod doctor;
pub mod init;
pub mod migrate;
pub mod policy;
pub mod regulatory;
