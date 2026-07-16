//! `clavenarctl init` — scaffold a fresh operator config + (optionally)
//! emit a starter policy directory.
//!
//! Idempotent by default: refuses to clobber an existing
//! `config.toml`. Pass `--force` to rewrite. The intent is the
//! first-run experience for a partner-day-1 operator who just
//! `cargo install`'d clavenarctl and wants the cheapest path from zero
//! to "I can run `clavenarctl doctor`."
//!
//! `--guard` is the one-command local-guard flow: scaffold a starter
//! policy + `clavenar-lite.env`, then print (or `--launch`) a
//! `clavenar-lite start --mode observe` command in front of `--upstream`.
//! `--print-config` resolves and prints the guard config without writing.

use std::path::PathBuf;

use clap::Args;

use crate::ExitCode;
use crate::config::{Config, config_path};

/// Complete starter policy the `--guard` flow drops into `./policies/` so
/// the local `clavenar-lite` boots with a valid ruleset. Sourced verbatim
/// from the lite edition's shipped `governance.rego` — a single
/// self-contained `package clavenar.authz` (loading the per-domain
/// templates flat would risk regorus rule-name conflicts).
const GUARD_GOVERNANCE_REGO: &str = include_str!("../../../clavenar-lite/policies/governance.rego");

#[derive(Debug, Args)]
pub(crate) struct InitArgs {
    /// Identity service base URL to write into the scaffolded config.
    /// Default `http://localhost:8086` matches the dev compose port.
    #[arg(long)]
    pub identity_url: Option<String>,

    /// Default tenant value for `--tenant`-taking commands. Optional —
    /// when unset, those commands require an explicit `--tenant` flag.
    #[arg(long)]
    pub tenant: Option<String>,

    /// Ledger service base URL (used by `clavenarctl doctor`).
    /// Default `http://localhost:8083`.
    #[arg(long)]
    pub ledger_url: Option<String>,

    /// HIL service base URL (used by `clavenarctl doctor`).
    /// Default `http://localhost:8084`.
    #[arg(long)]
    pub hil_url: Option<String>,

    /// Console base URL (used by `clavenarctl doctor`).
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
    /// `clavenarctl generate-policy` for individual templates.
    #[arg(long)]
    pub with_policies: bool,

    /// Overwrite an existing config.toml. The default is non-destructive.
    #[arg(long)]
    pub force: bool,

    /// Set up a one-command local guard: a `clavenar-lite` instance in
    /// observe mode in front of `--upstream`. Scaffolds policies + a
    /// `clavenar-lite.env`, then prints the launch command (or runs it
    /// with `--launch`).
    #[arg(long)]
    pub guard: bool,

    /// Upstream MCP server URL the guard sits in front of. Used with
    /// `--guard`. Default `http://localhost:9000/mcp`.
    #[arg(long)]
    pub upstream: Option<String>,

    /// Guard enforcement mode: `observe` (default — log-only, forwards
    /// everything) or `enforce`. Used with `--guard`.
    #[arg(long)]
    pub guard_mode: Option<String>,

    /// Local port the guard listens on. Used with `--guard`. Default 8088.
    #[arg(long)]
    pub guard_port: Option<u16>,

    /// Print the resolved effective guard config and exit, writing
    /// nothing. Inspect-before-commit for the `--guard` setup.
    #[arg(long)]
    pub print_config: bool,

    /// With `--guard`, spawn the `clavenar-lite` binary instead of just
    /// printing the launch command. Requires `clavenar-lite` on PATH.
    #[arg(long)]
    pub launch: bool,
}

/// Resolved guard configuration for the `--guard` flow. Mirrors the
/// `clavenar-lite start` knobs so the env file + launch command stay in
/// lockstep with what the lite binary actually reads.
struct GuardConfig {
    port: u16,
    upstream: String,
    policies: String,
    ledger: String,
    mode: String,
}

impl GuardConfig {
    fn resolve(args: &InitArgs) -> Self {
        GuardConfig {
            port: args.guard_port.unwrap_or(8088),
            upstream: args
                .upstream
                .clone()
                .unwrap_or_else(|| "http://localhost:9000/mcp".to_string()),
            policies: "./policies".to_string(),
            ledger: "./clavenar-lite.db".to_string(),
            mode: args
                .guard_mode
                .clone()
                .unwrap_or_else(|| "observe".to_string()),
        }
    }

    /// `clavenar-lite.env` body — the exact `CLAVENAR_LITE_*` names the
    /// lite binary reads (see its `start` subcommand env bindings).
    fn to_env(&self) -> String {
        format!(
            "CLAVENAR_LITE_PORT={}\n\
             CLAVENAR_LITE_UPSTREAM_URL={}\n\
             CLAVENAR_LITE_POLICY_DIR={}\n\
             CLAVENAR_LITE_LEDGER={}\n\
             CLAVENAR_LITE_MODE={}\n",
            self.port, self.upstream, self.policies, self.ledger, self.mode
        )
    }

    fn launch_args(&self) -> Vec<String> {
        vec![
            "start".to_string(),
            "--mode".to_string(),
            self.mode.clone(),
            "--upstream".to_string(),
            self.upstream.clone(),
            "--port".to_string(),
            self.port.to_string(),
            "--policies".to_string(),
            self.policies.clone(),
            "--ledger".to_string(),
            self.ledger.clone(),
        ]
    }

    fn launch_cmd(&self) -> String {
        format!("clavenar-lite {}", self.launch_args().join(" "))
    }
}

pub(crate) async fn run(args: InitArgs) -> ExitCode {
    // `--print-config` is a pure inspection: resolve the guard config,
    // print it, write nothing, launch nothing.
    if args.print_config {
        let guard = GuardConfig::resolve(&args);
        print!("{}", guard.to_env());
        eprintln!("\n# launch:\n{}", guard.launch_cmd());
        return ExitCode::Ok;
    }

    // Resolve the guard config now, while `args` is still whole — the
    // config-write below moves `identity_url`/`tenant` out of `args`,
    // after which it can't be borrowed as a whole.
    let guard = GuardConfig::resolve(&args);

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
    // who only know `clavenarctl init` can `cat` the file and learn
    // every knob without `--help`.
    let header = format!(
        "# clavenarctl operator config — written by `clavenarctl init` on {}.\n\
         # Per-call --flag and CLAVENAR_* env vars override these values.\n\
         # See `clavenarctl --help` for the full list.\n\n",
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
        eprintln!(
            "wrote {} template(s) under {}/",
            written,
            templates_dir.display()
        );
    }

    if args.guard {
        return scaffold_guard(&guard, args.force, args.launch);
    }

    eprintln!();
    eprintln!("next steps:");
    eprintln!("  clavenarctl doctor                 # probe the running stack");
    eprintln!("  clavenarctl generate-policy list   # browse the policy starter pack");
    eprintln!("  clavenarctl auth login --help      # authenticate against clavenar-identity");
    ExitCode::Ok
}

/// `--guard`: drop a complete starter policy + `clavenar-lite.env`, then
/// print the observe-mode launch command (or spawn it with `--launch`).
fn scaffold_guard(guard: &GuardConfig, force: bool, launch: bool) -> ExitCode {
    let pol_dir = PathBuf::from(&guard.policies);
    if let Err(e) = std::fs::create_dir_all(&pol_dir) {
        eprintln!("error: create {}: {}", pol_dir.display(), e);
        return ExitCode::Server;
    }
    let gov_path = pol_dir.join("governance.rego");
    if gov_path.exists() && !force {
        eprintln!("skipped {} (exists)", gov_path.display());
    } else if let Err(e) = std::fs::write(&gov_path, GUARD_GOVERNANCE_REGO) {
        eprintln!("error: write {}: {}", gov_path.display(), e);
        return ExitCode::Server;
    } else {
        eprintln!("wrote {}", gov_path.display());
    }

    let env_path = PathBuf::from("clavenar-lite.env");
    if env_path.exists() && !force {
        eprintln!("skipped {} (exists)", env_path.display());
    } else if let Err(e) = std::fs::write(&env_path, guard.to_env()) {
        eprintln!("error: write {}: {}", env_path.display(), e);
        return ExitCode::Server;
    } else {
        eprintln!("wrote {}", env_path.display());
    }

    if launch {
        eprintln!("launching: {}", guard.launch_cmd());
        match std::process::Command::new("clavenar-lite")
            .args(guard.launch_args())
            .status()
        {
            Ok(status) if status.success() => ExitCode::Ok,
            Ok(_) => ExitCode::Server,
            Err(e) => {
                eprintln!("error: could not launch clavenar-lite (is it on PATH?): {e}");
                eprintln!("install it with: cargo install clavenar-lite");
                ExitCode::Validation
            }
        }
    } else {
        eprintln!();
        eprintln!("guard ready — start it in observe mode:");
        eprintln!("  {}", guard.launch_cmd());
        eprintln!();
        eprintln!("after some traffic, graduate to enforce:");
        eprintln!("  openssl genpkey -algorithm ed25519 -out clavenar-lite.key");
        eprintln!("  clavenar-lite graduate report --signing-key clavenar-lite.key --format text");
        ExitCode::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> InitArgs {
        InitArgs {
            identity_url: None,
            tenant: None,
            ledger_url: None,
            hil_url: None,
            console_url: None,
            proxy_url: None,
            with_policies: false,
            force: false,
            guard: false,
            upstream: None,
            guard_mode: None,
            guard_port: None,
            print_config: false,
            launch: false,
        }
    }

    #[test]
    fn guard_config_defaults() {
        let g = GuardConfig::resolve(&base_args());
        assert_eq!(g.port, 8088);
        assert_eq!(g.mode, "observe");
        assert_eq!(g.upstream, "http://localhost:9000/mcp");
        assert_eq!(g.policies, "./policies");
    }

    #[test]
    fn guard_env_uses_lite_var_names() {
        let env = GuardConfig::resolve(&base_args()).to_env();
        assert!(env.contains("CLAVENAR_LITE_UPSTREAM_URL=http://localhost:9000/mcp"));
        assert!(env.contains("CLAVENAR_LITE_POLICY_DIR=./policies"));
        assert!(env.contains("CLAVENAR_LITE_MODE=observe"));
    }

    #[test]
    fn guard_launch_cmd_reflects_flags() {
        let mut a = base_args();
        a.upstream = Some("http://up:9000/mcp".to_string());
        a.guard_port = Some(9090);
        let cmd = GuardConfig::resolve(&a).launch_cmd();
        assert!(cmd.contains("clavenar-lite start --mode observe"));
        assert!(cmd.contains("--upstream http://up:9000/mcp"));
        assert!(cmd.contains("--port 9090"));
    }

    #[test]
    fn guard_governance_template_is_authz_package() {
        assert!(GUARD_GOVERNANCE_REGO.contains("package clavenar.authz"));
    }
}
