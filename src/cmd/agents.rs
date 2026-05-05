//! `wardenctl agents` — read-only access to the agents table (P1).
//!
//! Two subcommands:
//!
//! ```text
//! wardenctl agents list  --tenant <T> [--state ...] [--owner-team ...] [--json]
//! wardenctl agents get   <ID> --tenant <T> [--json]
//! ```
//!
//! Both are thin wrappers around [`warden_sdk::AgentsClient`]. Auth
//! comes from the cached credentials at `~/.warden/credentials.json`
//! (managed by `wardenctl auth login`); a missing entry exits 3.
//!
//! Writes (`create`, `suspend`, …) ship in P2 alongside the
//! identity-side lifecycle handlers.

use clap::{Args, Subcommand};
use warden_sdk::{AgentListFilter, AgentRecord, AgentState, AgentsClient};

use crate::config;
use crate::credentials;
use crate::ExitCode;

#[derive(Debug, Args)]
pub struct AgentsArgs {
    #[command(subcommand)]
    pub command: AgentsCommand,
}

#[derive(Debug, Subcommand)]
pub enum AgentsCommand {
    /// List agents in a tenant.
    List(ListArgs),
    /// Look up one agent by id.
    Get(GetArgs),
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Tenant to list within. Falls back to `WARDEN_TENANT` env, then
    /// `~/.warden/config.toml`'s `default_tenant`.
    #[arg(long)]
    pub tenant: Option<String>,
    /// Filter to one lifecycle state (active|suspended|decommissioned).
    #[arg(long)]
    pub state: Option<String>,
    /// Filter to a single owner team.
    #[arg(long = "owner-team")]
    pub owner_team: Option<String>,
    /// Emit JSON (machine-readable) instead of the human table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    /// Agent uuidv7 (the value the server returns under `id`).
    pub id: String,
    /// Tenant the agent belongs to.
    #[arg(long)]
    pub tenant: Option<String>,
    /// Emit JSON instead of the human key:value lines.
    #[arg(long)]
    pub json: bool,
}

pub async fn run(args: AgentsArgs, identity_url: Option<String>) -> ExitCode {
    let cfg = match config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: load config: {e}");
            return ExitCode::Validation;
        }
    };
    let env_url = std::env::var("WARDEN_IDENTITY_URL").ok();
    let url = config::resolve_identity_url(identity_url.as_deref(), env_url.as_deref(), &cfg);

    match args.command {
        AgentsCommand::List(a) => list(a, &cfg, &url).await,
        AgentsCommand::Get(a) => get(a, &cfg, &url).await,
    }
}

/// Resolve `--tenant` against the precedence chain: flag → env →
/// config file's `default_tenant`. Returns a typed exit code on
/// missing.
fn resolve_tenant(arg: Option<String>, cfg: &config::Config) -> Result<String, ExitCode> {
    arg.or_else(|| std::env::var("WARDEN_TENANT").ok())
        .or_else(|| cfg.default_tenant.clone())
        .ok_or_else(|| {
            eprintln!(
                "error: --tenant required (or set WARDEN_TENANT or default_tenant in config.toml)"
            );
            ExitCode::Validation
        })
}

fn build_client(url: &str, tenant: &str) -> Result<AgentsClient, ExitCode> {
    let creds = credentials::load().map_err(|e| {
        eprintln!("error: load credentials: {e}");
        ExitCode::Server
    })?;
    let bearer = credentials::bearer_for(&creds, tenant).map_err(|e| {
        eprintln!("error: {e}");
        ExitCode::Auth
    })?;
    AgentsClient::new(url)
        .map_err(|e| {
            eprintln!("error: invalid identity URL '{url}': {e}");
            ExitCode::Validation
        })
        .map(|c| c.with_bearer(bearer))
}

async fn list(args: ListArgs, cfg: &config::Config, url: &str) -> ExitCode {
    let tenant = match resolve_tenant(args.tenant, cfg) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let parsed_state = match args.state.as_deref() {
        None => None,
        Some(s) => match AgentState::parse(s) {
            Some(p) => Some(p),
            None => {
                eprintln!("error: invalid --state '{s}' (active|suspended|decommissioned)");
                return ExitCode::Validation;
            }
        },
    };
    let client = match build_client(url, &tenant) {
        Ok(c) => c,
        Err(c) => return c,
    };
    let filter = AgentListFilter {
        state: parsed_state,
        owner_team: args.owner_team,
    };
    match client.list(&tenant, filter).await {
        Ok(rows) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&rows).unwrap());
            } else {
                print_table(&rows);
            }
            ExitCode::Ok
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from_warden_error(&e)
        }
    }
}

async fn get(args: GetArgs, cfg: &config::Config, url: &str) -> ExitCode {
    let tenant = match resolve_tenant(args.tenant, cfg) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let client = match build_client(url, &tenant) {
        Ok(c) => c,
        Err(c) => return c,
    };
    match client.get(&args.id, &tenant).await {
        Ok(record) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&record).unwrap());
            } else {
                print_record(&record);
            }
            ExitCode::Ok
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from_warden_error(&e)
        }
    }
}

/// Plain-text "table" — fixed-width columns, no borders. Matches the
/// shape of `gh repo list` and `kubectl get` rather than a fancy
/// boxed renderer.
fn print_table(rows: &[AgentRecord]) {
    if rows.is_empty() {
        println!("(no agents)");
        return;
    }
    // Column widths derived from data + headers, capped to keep rows
    // readable. Cap is generous — agent names rarely exceed 32 chars.
    let name_w = rows
        .iter()
        .map(|r| r.agent_name.len())
        .max()
        .unwrap_or(0)
        .max("AGENT_NAME".len())
        .min(40);
    let team_w = rows
        .iter()
        .map(|r| r.owner_team.len())
        .max()
        .unwrap_or(0)
        .max("OWNER_TEAM".len())
        .min(32);
    println!(
        "{:<name_w$}  {:<14}  {:<team_w$}  {:>6}  {:>13}  ID",
        "AGENT_NAME", "STATE", "OWNER_TEAM", "SCOPES", "YELLOW_SCOPES",
        name_w = name_w,
        team_w = team_w
    );
    for r in rows {
        println!(
            "{:<name_w$}  {:<14}  {:<team_w$}  {:>6}  {:>13}  {}",
            truncate(&r.agent_name, name_w),
            r.state.as_wire(),
            truncate(&r.owner_team, team_w),
            r.scope_envelope.len(),
            r.yellow_envelope.len(),
            r.id,
            name_w = name_w,
            team_w = team_w,
        );
    }
}

/// Single-record human print — labelled lines, one field per line.
fn print_record(r: &AgentRecord) {
    println!("id:                          {}", r.id);
    println!("tenant:                      {}", r.tenant);
    println!("agent_name:                  {}", r.agent_name);
    println!("state:                       {}", r.state.as_wire());
    println!("owner_team:                  {}", r.owner_team);
    println!("created_by_sub:              {}", r.created_by_sub);
    println!("created_by_idp:              {}", r.created_by_idp);
    println!("created_at:                  {}", r.created_at);
    println!("state_changed_at:            {}", r.state_changed_at);
    println!("state_changed_by:            {}", r.state_changed_by);
    println!(
        "scope_envelope:              [{}]",
        r.scope_envelope.join(", ")
    );
    println!(
        "yellow_envelope:             [{}]",
        r.yellow_envelope.join(", ")
    );
    println!(
        "attestation_kinds_accepted:  [{}]",
        r.attestation_kinds_accepted.join(", ")
    );
    if let Some(d) = &r.description {
        println!("description:                 {}", d);
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else if max <= 1 {
        s.chars().take(max).collect()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &str, state: AgentState, owner: &str) -> AgentRecord {
        AgentRecord {
            id: format!("01HW...{name}"),
            tenant: "acme".into(),
            agent_name: name.into(),
            state,
            scope_envelope: vec!["x".into(), "y".into()],
            yellow_envelope: vec![],
            attestation_kinds_accepted: vec![],
            created_by_sub: "u".into(),
            created_by_idp: "okta".into(),
            owner_team: owner.into(),
            created_at: "2026-05-01T00:00:00Z".into(),
            state_changed_at: "2026-05-01T00:00:00Z".into(),
            state_changed_by: "u".into(),
            description: None,
        }
    }

    #[test]
    fn truncate_keeps_short_strings_intact() {
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn truncate_caps_long_strings_with_ellipsis() {
        let out = truncate("0123456789abc", 6);
        assert_eq!(out.chars().count(), 6);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn print_table_handles_empty() {
        // Smoke: just exercise the empty path without capturing stdout.
        // Matches the contract that we don't panic on an empty list.
        print_table(&[]);
    }

    #[test]
    fn print_table_handles_mixed_records() {
        let rows = vec![
            rec("support-bot-3", AgentState::Active, "payments"),
            rec("legacy-bot", AgentState::Suspended, "infra"),
        ];
        print_table(&rows);
    }

    #[test]
    fn print_record_renders_all_fields() {
        let r = rec("support-bot-3", AgentState::Active, "payments");
        print_record(&r);
    }

    #[test]
    fn resolve_tenant_uses_config_default() {
        let cfg = config::Config {
            identity_url: None,
            default_tenant: Some("acme".into()),
        };
        // Save and restore env to avoid clobbering a real WARDEN_TENANT.
        let prev = std::env::var("WARDEN_TENANT").ok();
        unsafe {
            std::env::remove_var("WARDEN_TENANT");
        }
        let resolved = resolve_tenant(None, &cfg).unwrap();
        assert_eq!(resolved, "acme");
        unsafe {
            if let Some(v) = prev {
                std::env::set_var("WARDEN_TENANT", v);
            }
        }
    }

    #[test]
    fn resolve_tenant_flag_wins() {
        let cfg = config::Config {
            identity_url: None,
            default_tenant: Some("acme".into()),
        };
        let resolved = resolve_tenant(Some("globex".into()), &cfg).unwrap();
        assert_eq!(resolved, "globex");
    }
}
