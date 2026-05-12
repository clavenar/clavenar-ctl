//! `wardenctl init` — scaffold a fresh operator config + (optionally)
//! emit a starter policy directory.
//!
//! Idempotent by default: refuses to clobber an existing
//! `config.toml`. Pass `--force` to rewrite. The intent is the
//! first-run experience for a partner-day-1 operator who just
//! `cargo install`'d wardenctl and wants the cheapest path from zero
//! to "I can run `wardenctl doctor`."

use std::path::PathBuf;

use clap::Args;

use crate::config::{config_path, Config};
use crate::ExitCode;

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Identity service base URL to write into the scaffolded config.
    /// Default `http://localhost:8086` matches the dev compose port.
    #[arg(long)]
    pub identity_url: Option<String>,

    /// Default tenant value for `--tenant`-taking commands. Optional —
    /// when unset, those commands require an explicit `--tenant` flag.
    #[arg(long)]
    pub tenant: Option<String>,

    /// Ledger service base URL (used by `wardenctl doctor`).
    /// Default `http://localhost:8083`.
    #[arg(long)]
    pub ledger_url: Option<String>,

    /// HIL service base URL (used by `wardenctl doctor`).
    /// Default `http://localhost:8084`.
    #[arg(long)]
    pub hil_url: Option<String>,

    /// Console base URL (used by `wardenctl doctor`).
    /// Default `http://localhost:8085`.
    #[arg(long)]
    pub console_url: Option<String>,

    /// Proxy base URL — note the proxy speaks mTLS, so doctor only
    /// probes liveness, not auth. Default `https://localhost:8443`.
    #[arg(long)]
    pub proxy_url: Option<String>,

    /// Optionally emit a starter `policies/` directory in the current
    /// working directory with `governance.rego` + every policy
    /// template under `templates/`. Off by default — call
    /// `wardenctl generate-policy` for individual templates.
    #[arg(long)]
    pub with_policies: bool,

    /// Overwrite an existing config.toml. The default is non-destructive.
    #[arg(long)]
    pub force: bool,
}

pub async fn run(args: InitArgs) -> ExitCode {
    let cfg_path = match config_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: could not resolve config path: {}", e);
            return ExitCode::Server;
        }
    };
    if cfg_path.exists() && !args.force {
        eprintln!(
            "error: {} already exists. Pass --force to overwrite.",
            cfg_path.display()
        );
        return ExitCode::Conflict;
    }
    if let Some(parent) = cfg_path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        eprintln!("error: create {}: {}", parent.display(), e);
        return ExitCode::Server;
    }

    let cfg = Config {
        identity_url: Some(
            args.identity_url
                .unwrap_or_else(|| "http://localhost:8086".to_string()),
        ),
        default_tenant: args.tenant,
    };
    let body = match toml::to_string_pretty(&cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: serialize config: {}", e);
            return ExitCode::Server;
        }
    };
    // Header comment makes the file human-discoverable — operators
    // who only know `wardenctl init` can `cat` the file and learn
    // every knob without `--help`.
    let header = format!(
        "# wardenctl operator config — written by `wardenctl init` on {}.\n\
         # Per-call --flag and WARDEN_* env vars override these values.\n\
         # See `wardenctl --help` for the full list.\n\n",
        chrono::Utc::now().to_rfc3339()
    );
    let full = format!("{}{}", header, body);
    if let Err(e) = std::fs::write(&cfg_path, full) {
        eprintln!("error: write {}: {}", cfg_path.display(), e);
        return ExitCode::Server;
    }
    eprintln!("wrote {}", cfg_path.display());

    if args.with_policies {
        let pol_dir = PathBuf::from("./policies");
        let templates_dir = pol_dir.join("templates");
        if let Err(e) = std::fs::create_dir_all(&templates_dir) {
            eprintln!("error: create {}: {}", templates_dir.display(), e);
            return ExitCode::Server;
        }
        let mut written = 0usize;
        for (name, _summary, body) in crate::cmd::policy::TEMPLATES {
            let path = templates_dir.join(format!("{}.rego", name));
            if path.exists() && !args.force {
                eprintln!("skipped {} (exists)", path.display());
                continue;
            }
            if let Err(e) = std::fs::write(&path, body) {
                eprintln!("error: write {}: {}", path.display(), e);
                return ExitCode::Server;
            }
            written += 1;
        }
        eprintln!("wrote {} template(s) under {}/", written, templates_dir.display());
    }

    eprintln!();
    eprintln!("next steps:");
    eprintln!("  wardenctl doctor                 # probe the running stack");
    eprintln!("  wardenctl generate-policy list   # browse the policy starter pack");
    eprintln!("  wardenctl auth login --help      # authenticate against warden-identity");
    ExitCode::Ok
}
