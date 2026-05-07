//! `wardenctl agents` — full read + write access to the agents table.
//!
//! Wires the lifecycle write commands on top
//! of the read-only foundation:
//!
//! ```text
//! wardenctl agents list   --tenant <T> [--state …] [--owner-team …] [--json]
//! wardenctl agents get    <ID> --tenant <T> [--json]
//! wardenctl agents create --tenant <T> --name <N> --owner-team <T>
//!                         [--scope <S>...] [--yellow-scope <S>...]
//!                         [--attestation-kind <K>...] [--description <T>]
//!                         [--if-absent] [--json]
//! wardenctl agents suspend       <ID> --tenant <T> [--reason …]
//! wardenctl agents unsuspend     <ID> --tenant <T> [--reason …]
//! wardenctl agents decommission  <ID> --tenant <T> [--reason …]
//! wardenctl agents envelope narrow <ID> --tenant <T> [--scope …]... [--yellow-scope …]...
//! wardenctl agents envelope widen  <ID> --tenant <T> [--scope …]... [--yellow-scope …]...
//! wardenctl agents transfer    <ID> --tenant <T> --to-team <T>
//! wardenctl agents description <ID> --tenant <T> --text "…"
//! ```
//!
//! All paths share the same auth, exit-code, and tenant-resolution
//! plumbing: bearer comes from the cached creds at
//! `~/.warden/credentials.json`; tenant defaults to flag → env →
//! config; exit codes follow spec §9.3 via
//! [`crate::ExitCode::from_warden_error`].
//!
//! `--if-absent` on `create` is the IaC-without-Terraform pattern: a
//! pre-fetch by `(tenant, agent_name)` decides whether to POST. On a
//! match, exit 0; on a mismatch, exit 4 (conflict) without writing.

use clap::{Args, Subcommand};
use warden_sdk::{
    create_request_matches, AgentListFilter, AgentRecord, AgentState, AgentsClient,
    CreateAgentRequest, EnvelopeRequest,
};

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
    /// Register a new agent (spec §5.2).
    Create(CreateArgs),
    /// Pause an agent — owner-team or admin (spec §5.1).
    Suspend(LifecycleArgs),
    /// Unpause a suspended agent — admin only.
    Unsuspend(LifecycleArgs),
    /// Decommission an agent (terminal). Admin only.
    Decommission(LifecycleArgs),
    /// Narrow / widen the capability envelope.
    Envelope(EnvelopeArgs),
    /// Transfer the owner team. Admin only.
    Transfer(TransferArgs),
    /// Update the free-text description.
    Description(DescriptionArgs),
    /// Bulk-enroll legacy agents onto the registry (spec §7.3).
    /// The official adoption path for the `Warn` → `Enforce` flip.
    Migrate(crate::cmd::migrate::MigrateArgs),
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

#[derive(Debug, Args)]
pub struct CreateArgs {
    #[arg(long)]
    pub tenant: Option<String>,
    /// Agent name. Must be unique within `(tenant, agent_name)` —
    /// even Decommissioned rows count, the spec forbids name reuse.
    #[arg(long)]
    pub name: String,
    /// Owner team. Must be a group the caller's `id_token` carries.
    #[arg(long = "owner-team")]
    pub owner_team: String,
    /// Capability envelope, repeatable. `--scope mcp:read:tickets
    /// --scope mcp:write:tickets`.
    #[arg(long = "scope")]
    pub scope: Vec<String>,
    /// Yellow-tier capability envelope, repeatable.
    #[arg(long = "yellow-scope")]
    pub yellow_scope: Vec<String>,
    /// Attestation kinds the platform should accept for this agent.
    /// Repeatable. Empty = inherit the global allowlist.
    #[arg(long = "attestation-kind")]
    pub attestation_kind: Vec<String>,
    /// Free-text description (≤ ~1KB recommended).
    #[arg(long)]
    pub description: Option<String>,
    /// Idempotent IaC mode: if a row at `(tenant, agent_name)`
    /// already matches the requested envelope/owner_team/kinds, exit
    /// 0 without re-POSTing. On mismatch, exit 4 without writing —
    /// the operator is expected to converge manually.
    #[arg(long = "if-absent")]
    pub if_absent: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct LifecycleArgs {
    /// Agent uuidv7.
    pub id: String,
    #[arg(long)]
    pub tenant: Option<String>,
    /// Free-text reason. Lands on the chain v3 payload and the
    /// forensic event today.
    #[arg(long)]
    pub reason: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct EnvelopeArgs {
    #[command(subcommand)]
    pub direction: EnvelopeDirection,
}

#[derive(Debug, Subcommand)]
pub enum EnvelopeDirection {
    /// Narrow the envelope (owner-team or admin). Pass the *full new
    /// envelope* — the server diffs against the current row.
    Narrow(EnvelopeChangeArgs),
    /// Widen the envelope (admin only). Same shape as narrow.
    Widen(EnvelopeChangeArgs),
}

#[derive(Debug, Args)]
pub struct EnvelopeChangeArgs {
    pub id: String,
    #[arg(long)]
    pub tenant: Option<String>,
    /// New scope envelope, repeatable. Pass *all* the scopes you
    /// want post-change; missing flags are silently the same as
    /// `[]`.
    #[arg(long = "scope")]
    pub scope: Vec<String>,
    /// New yellow-tier envelope, repeatable.
    #[arg(long = "yellow-scope")]
    pub yellow_scope: Vec<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct TransferArgs {
    pub id: String,
    #[arg(long)]
    pub tenant: Option<String>,
    /// New owning team. Spec §15 — receiving-team consent is out of
    /// scope; admin can assign to any non-empty label.
    #[arg(long = "to-team")]
    pub to_team: String,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DescriptionArgs {
    pub id: String,
    #[arg(long)]
    pub tenant: Option<String>,
    /// New description text. Empty string is rejected upstream —
    /// pass `--clear` to remove the description entirely (the body
    /// sets it to JSON null).
    #[arg(long)]
    pub text: Option<String>,
    /// Clear the description. Mutually exclusive with `--text`.
    #[arg(long, conflicts_with = "text")]
    pub clear: bool,
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
        AgentsCommand::Create(a) => create(a, &cfg, &url).await,
        AgentsCommand::Suspend(a) => lifecycle(a, &cfg, &url, LifecycleVerb::Suspend).await,
        AgentsCommand::Unsuspend(a) => lifecycle(a, &cfg, &url, LifecycleVerb::Unsuspend).await,
        AgentsCommand::Decommission(a) => {
            lifecycle(a, &cfg, &url, LifecycleVerb::Decommission).await
        }
        AgentsCommand::Envelope(a) => envelope(a, &cfg, &url).await,
        AgentsCommand::Transfer(a) => transfer(a, &cfg, &url).await,
        AgentsCommand::Description(a) => description(a, &cfg, &url).await,
        // `migrate` runs its own config/cred resolution (it needs the
        // operator's `sub` claim from the cached id_token) — pass the
        // global identity_url override through, not the resolved url
        // we already computed, so the migrate cmd can re-derive it.
        AgentsCommand::Migrate(a) => crate::cmd::migrate::run(a, Some(url.clone())).await,
    }
}

#[derive(Debug, Clone, Copy)]
enum LifecycleVerb {
    Suspend,
    Unsuspend,
    Decommission,
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

async fn create(args: CreateArgs, cfg: &config::Config, url: &str) -> ExitCode {
    let tenant = match resolve_tenant(args.tenant.clone(), cfg) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let client = match build_client(url, &tenant) {
        Ok(c) => c,
        Err(c) => return c,
    };

    let req = CreateAgentRequest {
        tenant: tenant.as_str(),
        agent_name: args.name.as_str(),
        owner_team: args.owner_team.as_str(),
        scope_envelope: args.scope.clone(),
        yellow_envelope: args.yellow_scope.clone(),
        attestation_kinds: args.attestation_kind.clone(),
        description: args.description.as_deref(),
        // `wardenctl agents create` is the hand-driven path; the
        // operator's own OIDC sub goes on the row. The migration CLI
        // path is `wardenctl agents migrate` (cmd/migrate.rs) — that
        // command sets `actor_sub` to `system:migration:<sub>` so the
        // two paths leave distinguishable rows in the audit trail.
        actor_sub: None,
    };

    if args.if_absent {
        // Pre-fetch by `(tenant, agent_name)`. If the row exists and
        // matches, exit 0; if it exists but differs, exit 4 (conflict)
        // without writing. The latter is intentional — the spec calls
        // out IaC patterns expect operator intervention on drift.
        match client.find_by_name(&tenant, &args.name).await {
            Ok(Some(existing)) => {
                if create_request_matches(&req, &existing) {
                    if args.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "status": "matched",
                                "id": existing.id,
                            }))
                            .unwrap()
                        );
                    } else {
                        println!("agent '{}' already matches (id {})", args.name, existing.id);
                    }
                    return ExitCode::Ok;
                }
                eprintln!(
                    "error: agent '{}' exists with a different envelope/owner_team/kinds; \
                     reconcile manually",
                    args.name
                );
                return ExitCode::Conflict;
            }
            Ok(None) => {
                // Fall through to the regular create path below.
            }
            Err(e) => {
                eprintln!("error: pre-fetch failed: {e}");
                return ExitCode::from_warden_error(&e);
            }
        }
    }

    match client.create(&req).await {
        Ok(created) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&created).unwrap());
            } else {
                println!(
                    "registered agent '{}' (id {}, state {})",
                    created.record.agent_name,
                    created.record.id,
                    created.record.state.as_wire()
                );
                println!("spiffe_id_pattern: {}", created.spiffe_id_pattern);
            }
            ExitCode::Ok
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from_warden_error(&e)
        }
    }
}

async fn lifecycle(
    args: LifecycleArgs,
    cfg: &config::Config,
    url: &str,
    verb: LifecycleVerb,
) -> ExitCode {
    let tenant = match resolve_tenant(args.tenant, cfg) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let client = match build_client(url, &tenant) {
        Ok(c) => c,
        Err(c) => return c,
    };
    let result = match verb {
        LifecycleVerb::Suspend => client.suspend(&args.id, &tenant, args.reason.as_deref()).await,
        LifecycleVerb::Unsuspend => {
            client.unsuspend(&args.id, &tenant, args.reason.as_deref()).await
        }
        LifecycleVerb::Decommission => {
            client
                .decommission(&args.id, &tenant, args.reason.as_deref())
                .await
        }
    };
    match result {
        Ok(resp) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&resp).unwrap());
            } else {
                println!(
                    "agent {} → {} (changed at {})",
                    args.id,
                    resp.state.as_wire(),
                    resp.state_changed_at
                );
            }
            ExitCode::Ok
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from_warden_error(&e)
        }
    }
}

async fn envelope(args: EnvelopeArgs, cfg: &config::Config, url: &str) -> ExitCode {
    let (id, tenant_arg, scope, yellow, json_out, direction) = match args.direction {
        EnvelopeDirection::Narrow(a) => (
            a.id,
            a.tenant,
            a.scope,
            a.yellow_scope,
            a.json,
            EnvelopeDirectionRaw::Narrow,
        ),
        EnvelopeDirection::Widen(a) => (
            a.id,
            a.tenant,
            a.scope,
            a.yellow_scope,
            a.json,
            EnvelopeDirectionRaw::Widen,
        ),
    };
    let tenant = match resolve_tenant(tenant_arg, cfg) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let client = match build_client(url, &tenant) {
        Ok(c) => c,
        Err(c) => return c,
    };
    let env = EnvelopeRequest {
        scope_envelope: &scope,
        yellow_envelope: &yellow,
    };
    let result = match direction {
        EnvelopeDirectionRaw::Narrow => client.envelope_narrow(&id, &tenant, env).await,
        EnvelopeDirectionRaw::Widen => client.envelope_widen(&id, &tenant, env).await,
    };
    match result {
        Ok(record) => {
            if json_out {
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

#[derive(Debug, Clone, Copy)]
enum EnvelopeDirectionRaw {
    Narrow,
    Widen,
}

async fn transfer(args: TransferArgs, cfg: &config::Config, url: &str) -> ExitCode {
    let tenant = match resolve_tenant(args.tenant, cfg) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let client = match build_client(url, &tenant) {
        Ok(c) => c,
        Err(c) => return c,
    };
    match client
        .transfer_owner_team(&args.id, &tenant, &args.to_team)
        .await
    {
        Ok(record) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&record).unwrap());
            } else {
                println!("agent {} owner_team → {}", args.id, record.owner_team);
            }
            ExitCode::Ok
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from_warden_error(&e)
        }
    }
}

async fn description(args: DescriptionArgs, cfg: &config::Config, url: &str) -> ExitCode {
    let tenant = match resolve_tenant(args.tenant, cfg) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let client = match build_client(url, &tenant) {
        Ok(c) => c,
        Err(c) => return c,
    };
    let text = if args.clear {
        None
    } else {
        match args.text.as_deref() {
            Some("") | None => {
                eprintln!("error: pass --text \"…\" or --clear to remove the description");
                return ExitCode::Validation;
            }
            Some(t) => Some(t),
        }
    };
    match client.set_description(&args.id, &tenant, text).await {
        Ok(record) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&record).unwrap());
            } else {
                println!(
                    "agent {} description: {}",
                    args.id,
                    record.description.as_deref().unwrap_or("(cleared)")
                );
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
