//! `clavenarctl agents migrate` — bulk-enroll existing SVID-only agents
//! onto the registered-agents table (clavenar-specs/TECH_SPEC.md#agent-onboarding-wao §7.3, §13.1.7).
//!
//! Migration deliverable. The migration command is the official adoption path
//! for the mode flip from `Warn` to `Enforce`: an operator runs
//! `clavenarctl agents migrate` once with default `(owner_team, scope,
//! kinds)` for the legacy fleet, identity creates one row per
//! `(tenant, agent_name)` it finds in the SVID issuance log, and from
//! that point on `/svid` and `/grant` enforce against a populated
//! registry.
//!
//! Source of "what to migrate":
//!
//! * Today, identity does NOT expose a "list orphan SVID names"
//!   endpoint (the spec calls for one but defers it). Instead the CLI
//!   takes the input list from `--names <FILE>`, one `<agent_name>` per
//!   line. The operator builds this from logs / source-of-truth IaC /
//!   `grep` over their existing SPIFFE identities. This keeps the
//!   migration tool independent of identity's internal schema.
//!
//! `actor_sub` discipline:
//!
//! * Every `POST /agents` body the migration command sends sets
//!   `actor_sub = "system:migration:<operator_oidc_sub>"`. The
//!   operator's `<sub>` is read from the cached id_token's `sub` claim
//!   (via `credentials::unverified_decode`), so audit-log readers can
//!   reconstruct who ran the migration without parsing the bearer.
//! * Identity rejects any other prefix with 403
//!   `actor_sub_prefix_not_allowed`; identity also rejects the prefix
//!   when the caller doesn't hold `agents:admin`.
//!
//! Idempotency:
//!
//! * For each name the CLI runs `find_by_name` first.
//!     * **No row** → POST /agents with the migration prefix.
//!     * **Row exists, envelope/owner_team match** → no-op (200).
//!     * **Row exists, drift** → log and skip; operator must reconcile
//!       manually before re-running.
//! * `--dry-run` prints the planned actions and exits 0 without writing.
//!
//! Exit code:
//!
//! * 0 — every name succeeded or matched-existing.
//! * Mixed (some skipped due to drift, others succeeded) → 0 with a
//!   per-row summary; the operator gets a non-zero only on a hard
//!   failure (network, 5xx, malformed input file).

use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::Args;
use clavenar_sdk::{
    create_request_matches, AgentsClient, CreateAgentRequest, MIGRATION_ACTOR_SUB_PREFIX,
};

use crate::config;
use crate::credentials;
use crate::ExitCode;

#[derive(Debug, Args)]
pub(crate) struct MigrateArgs {
    /// Tenant to migrate within. Falls back to `CLAVENAR_TENANT`, then
    /// the config's `default_tenant`.
    #[arg(long)]
    pub tenant: Option<String>,

    /// File of agent names, one per line. Lines starting with `#` are
    /// skipped (comments), as are blank lines. The CLI doesn't parse
    /// CSV or JSON — flat one-per-line is the lowest-friction shape
    /// for `find . -name '*.svid' | basename` style pipelines.
    #[arg(long, value_name = "PATH")]
    pub names: PathBuf,

    /// Default `owner_team` stamped on every created row.
    /// Per spec §3.3 the caller's id_token must carry this group; the
    /// migration command runs under one operator's OIDC token, so
    /// every row inherits the same `owner_team` (typically a sentinel
    /// team like `legacy-fleet` that the platform team owns).
    #[arg(long = "default-owner-team")]
    pub default_owner_team: String,

    /// Default scope envelope, repeatable. Empty list is allowed —
    /// the resulting agent has no /grant-able scope until a human
    /// widens the envelope.
    #[arg(long = "default-scope")]
    pub default_scope: Vec<String>,

    /// Default yellow-tier scope envelope, repeatable.
    #[arg(long = "default-yellow-scope")]
    pub default_yellow_scope: Vec<String>,

    /// Default attestation kinds, repeatable. Empty inherits the
    /// platform-wide allowlist.
    #[arg(long = "default-attestation-kind")]
    pub default_attestation_kind: Vec<String>,

    /// Print the planned create calls without executing.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Emit the per-row outcome summary as JSON instead of the human
    /// table. The summary array shape is
    /// `[{name, action, id?, error?}, ...]` where `action` is one of
    /// `created | matched | drift | failed`.
    #[arg(long)]
    pub json: bool,
}

/// Per-name outcome the CLI surfaces in its summary table / JSON.
#[derive(Debug, Clone, serde::Serialize)]
struct Outcome {
    name: String,
    action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub(crate) async fn run(args: MigrateArgs, cfg: &config::Config, url: &str) -> ExitCode {
    let tenant = match config::resolve_tenant(args.tenant.clone(), cfg) {
        Ok(t) => t,
        Err(c) => return c,
    };

    let names = match read_names_file(&args.names) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: --names {}: {}", args.names.display(), e);
            return ExitCode::Validation;
        }
    };
    if names.is_empty() {
        eprintln!("(no names in {} — nothing to migrate)", args.names.display());
        return ExitCode::Ok;
    }

    let creds = match credentials::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: load credentials: {e}");
            return ExitCode::Server;
        }
    };
    let bearer = match credentials::bearer_for(&creds, &tenant) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::Auth;
        }
    };

    // Pull the operator's `sub` claim off the cached id_token. We need
    // this to stamp `system:migration:<sub>` so the migration is
    // attributable. Server is the authoritative `sub` source — this is
    // best-effort decode for stamping only.
    let operator_sub = match credentials::unverified_decode(&bearer) {
        Ok(claims) => claims.sub.unwrap_or_else(|| "unknown".to_string()),
        Err(e) => {
            // The server-side `agents:admin` check still runs; the
            // worst case here is the audit-row prefix says `unknown`.
            eprintln!("warn: could not decode id_token sub claim: {e}");
            "unknown".to_string()
        }
    };
    let actor_sub = format!("{MIGRATION_ACTOR_SUB_PREFIX}{operator_sub}");

    let client = match AgentsClient::new(url) {
        Ok(c) => c.with_bearer(bearer.clone()),
        Err(e) => {
            eprintln!("error: invalid identity URL '{url}': {e}");
            return ExitCode::Validation;
        }
    };

    let mut outcomes: Vec<Outcome> = Vec::with_capacity(names.len());
    let mut hard_failure = false;

    for name in &names {
        // Same idempotency pattern as `agents create --if-absent`.
        let existing = match client.find_by_name(&tenant, name).await {
            Ok(v) => v,
            Err(e) => {
                outcomes.push(Outcome {
                    name: name.clone(),
                    action: "failed",
                    id: None,
                    error: Some(format!("find: {e}")),
                });
                hard_failure = true;
                continue;
            }
        };

        let req = CreateAgentRequest {
            tenant: tenant.as_str(),
            agent_name: name.as_str(),
            owner_team: args.default_owner_team.as_str(),
            scope_envelope: args.default_scope.clone(),
            yellow_envelope: args.default_yellow_scope.clone(),
            attestation_kinds: args.default_attestation_kind.clone(),
            description: None,
            actor_sub: Some(actor_sub.as_str()),
        };

        if let Some(rec) = existing.as_ref() {
            if create_request_matches(&req, rec) {
                outcomes.push(Outcome {
                    name: name.clone(),
                    action: "matched",
                    id: Some(rec.id.clone()),
                    error: None,
                });
                continue;
            }
            // Drift case — leave the row alone, surface the mismatch
            // so the operator can fix it before re-running. Spec
            // §7.3: "if it exists with a different envelope, log and
            // skip without rewriting (operator must intervene)."
            outcomes.push(Outcome {
                name: name.clone(),
                action: "drift",
                id: Some(rec.id.clone()),
                error: Some("existing row's envelope/owner_team/kinds differ from defaults".into()),
            });
            continue;
        }

        if args.dry_run {
            outcomes.push(Outcome {
                name: name.clone(),
                action: "would-create",
                id: None,
                error: None,
            });
            continue;
        }
        match client.create(&req).await {
            Ok(created) => {
                outcomes.push(Outcome {
                    name: name.clone(),
                    action: "created",
                    id: Some(created.record.id),
                    error: None,
                });
            }
            Err(e) => {
                outcomes.push(Outcome {
                    name: name.clone(),
                    action: "failed",
                    id: None,
                    error: Some(format!("{e}")),
                });
                hard_failure = true;
            }
        }
    }

    if args.json {
        match serde_json::to_string_pretty(&outcomes) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: serialize outcomes: {e}");
                return ExitCode::Server;
            }
        }
    } else {
        print_outcomes(&outcomes, args.dry_run);
    }

    if hard_failure {
        ExitCode::Server
    } else {
        ExitCode::Ok
    }
}

/// Read the `--names` file: one agent name per line, `#` comments and
/// blank lines skipped. Names are de-duplicated (a duplicate would just
/// re-trip the idempotency match) preserving first-seen order — the
/// operator's intent for ordering matters since the summary is
/// printed in the same order.
fn read_names_file(path: &std::path::Path) -> std::io::Result<Vec<String>> {
    let body = std::fs::read_to_string(path)?;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<String> = Vec::new();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if seen.insert(line.to_string()) {
            out.push(line.to_string());
        }
    }
    Ok(out)
}

/// Plain-text summary table. Columns: name, action, id, error.
fn print_outcomes(outcomes: &[Outcome], dry_run: bool) {
    if outcomes.is_empty() {
        println!("(no rows)");
        return;
    }
    let name_w = outcomes.iter().map(|o| o.name.len()).max().unwrap_or(0).max(4);
    let action_w = outcomes.iter().map(|o| o.action.len()).max().unwrap_or(0).max(6);
    println!(
        "{:<name_w$}  {:<action_w$}  ID                                   ERROR",
        "NAME",
        "ACTION",
        name_w = name_w,
        action_w = action_w,
    );
    let mut counts = std::collections::BTreeMap::<&'static str, usize>::new();
    for o in outcomes {
        *counts.entry(o.action).or_insert(0) += 1;
        println!(
            "{:<name_w$}  {:<action_w$}  {:<36}  {}",
            o.name,
            o.action,
            o.id.as_deref().unwrap_or(""),
            o.error.as_deref().unwrap_or(""),
            name_w = name_w,
            action_w = action_w,
        );
    }
    println!();
    let mut summary: Vec<String> = counts
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect();
    if dry_run {
        summary.insert(0, "DRY-RUN".into());
    }
    println!("{}", summary.join("  "));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_names_file_skips_comments_and_blanks() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "# header comment\n\nsupport-bot-3\n  legacy-bot\n# trailing\n"
        )
        .unwrap();
        let names = read_names_file(tmp.path()).unwrap();
        assert_eq!(names, vec!["support-bot-3".to_string(), "legacy-bot".into()]);
    }

    #[test]
    fn read_names_file_dedups_preserving_order() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "a\nb\na\nc\nb").unwrap();
        let names = read_names_file(tmp.path()).unwrap();
        assert_eq!(names, vec!["a".to_string(), "b".into(), "c".into()]);
    }

    /// The migration prefix constant must be stable wire-shape; if
    /// `clavenar-sdk` rewrote it the chain row's `actor_sub` field
    /// would silently shift and break audit consumers.
    #[test]
    fn migration_prefix_constant_is_stable() {
        assert_eq!(MIGRATION_ACTOR_SUB_PREFIX, "system:migration:");
    }

    /// Smoke that the `print_outcomes` formatter doesn't panic on the
    /// representative cases. Capturing stdout under cargo test is
    /// awkward; we just exercise the branches.
    #[test]
    fn print_outcomes_handles_mixed() {
        let rows = vec![
            Outcome {
                name: "support-bot-3".into(),
                action: "created",
                id: Some("01HW...A001".into()),
                error: None,
            },
            Outcome {
                name: "legacy-bot".into(),
                action: "matched",
                id: Some("01HW...A002".into()),
                error: None,
            },
            Outcome {
                name: "ghost-bot".into(),
                action: "drift",
                id: Some("01HW...A003".into()),
                error: Some("envelope differs".into()),
            },
            Outcome {
                name: "broken-bot".into(),
                action: "failed",
                id: None,
                error: Some("transport: refused".into()),
            },
        ];
        print_outcomes(&rows, false);
    }
}
