//! Subcommand modules. One file per top-level verb (`auth`, `agents`,
//! `regulatory`). Each module exports an `Args` struct (clap derive)
//! and a `run()` that returns the subcommand's [`crate::ExitCode`].

pub(crate) mod agents;
pub(crate) mod assurance;
pub(crate) mod auth;
pub(crate) mod doctor;
pub(crate) mod init;
pub(crate) mod mcp_bridge;
pub(crate) mod import_scanner;
pub(crate) mod migrate;
pub(crate) mod policy;
pub(crate) mod policy_exchange;
pub(crate) mod policy_install;
pub(crate) mod policy_lab;
pub(crate) mod policy_library;
pub(crate) mod policy_scaffold;
pub(crate) mod regulatory;
