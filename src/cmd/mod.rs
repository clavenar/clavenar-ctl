//! Subcommand modules. Eleven top-level verbs ship today (`init`,
//! `doctor`, `generate-policy`, `policy`, `auth`, `agents`, `pending`,
//! `regulatory`, `assurance`, `mcp-bridge`, `import-provider-audit`);
//! the remaining modules here are their sub-handlers (e.g. `policy_lab`
//! and `policy_install` behind `policy`). Each module exports an `Args`
//! struct (clap derive) and a `run()` that returns the subcommand's
//! [`crate::ExitCode`].

pub(crate) mod agents;
pub(crate) mod agents_certify;
pub(crate) mod assurance;
pub(crate) mod auth;
pub(crate) mod bootstrap;
pub(crate) mod doctor;
pub(crate) mod init;
pub(crate) mod mcp_bridge;
pub(crate) mod import_provider_audit;
pub(crate) mod import_scanner;
pub(crate) mod import_workloads;
pub(crate) mod migrate;
pub(crate) mod pending;
pub(crate) mod policy;
pub(crate) mod policy_exchange;
pub(crate) mod policy_install;
pub(crate) mod policy_lab;
pub(crate) mod policy_library;
pub(crate) mod policy_scaffold;
pub(crate) mod regulatory;
