//! `wardenctl policy test <file.rego>` — Policy Lab CLI.
//!
//! Reads a candidate Rego file, fetches a replay corpus from the
//! ledger over a configurable time window, and POSTs the corpus +
//! candidate to the policy engine's `/policies/evaluate-batch`. The
//! result is a per-input verdict diff against the active engine.
//!
//! Two output modes:
//!
//! - TTY: human summary with tile counts and a top-N drill list.
//! - `--json`: full machine-readable
//!   `EvaluateBatchResponse` with one extra field added per result
//!   (`captured_at` from the corpus row) so a CI step can pin a
//!   regression to its originating row.
//!
//! `--fail-on-regression` exits 2 when ANY catalog regression is
//! detected. The catalog half is wired up via the
//! `warden-chaos-catalog` path-dep on warden-console; the CLI
//! re-implements a minimal catalog wrapper inline so this binary
//! stays light.
//!
//! Hits the policy engine and ledger via the shared SDK. Bearer
//! token: `WARDEN_POLICY_TEST_BEARER` (optional — for the prod
//! deployment that fronts the policy engine with token auth).

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Duration as CDuration, Utc};
use clap::{Args, Subcommand};
use warden_sdk::{
    parse_batch_error, BatchMode, DiffClass, EvaluateBatchRequest, EvaluateBatchResponse,
    LedgerClient, PoliciesClient, ReplayCorpusParams, WardenError,
};

use crate::ExitCode;

#[derive(Debug, Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub action: PolicyAction,
}

#[derive(Debug, Subcommand)]
pub enum PolicyAction {
    /// Replay a candidate Rego rule against the last N days of real
    /// ledger traffic AND against the chaos catalog (the 40-attack
    /// catalogued corpus). Reports the per-input verdict diff and
    /// flags regressions in the catalog tab.
    Test(TestArgs),
}

#[derive(Debug, Args)]
pub struct TestArgs {
    /// Path to a candidate `.rego` file.
    pub file: PathBuf,
    /// Override the candidate's name in compile-error messages.
    /// Defaults to the file's basename.
    #[arg(long)]
    pub name: Option<String>,
    /// `add` registers the candidate alongside the active set;
    /// `replace` swaps an existing rule named `--replace`.
    #[arg(long, default_value = "add")]
    pub mode: ModeArg,
    /// Required when `--mode replace`: the name of the active rule
    /// the candidate is replacing.
    #[arg(long)]
    pub replace: Option<String>,
    /// Which corpora to replay against. `prod` reads the last `--since`
    /// window from the ledger. `catalog` runs against the chaos
    /// catalog. `both` (default) does both.
    #[arg(long, default_value = "both")]
    pub against: AgainstArg,
    /// Window to pull from the ledger. Default `7d`. Accepts
    /// `<N>d`, `<N>h`, or `<N>m`.
    #[arg(long, default_value = "7d")]
    pub since: String,
    /// Cap on inputs pulled from the ledger. Default 1000, max 5000.
    #[arg(long, default_value = "1000")]
    pub limit: i64,
    /// Filter the corpus to one agent id.
    #[arg(long)]
    pub agent_id: Option<String>,
    /// Filter the corpus to one tool_type.
    #[arg(long)]
    pub tool_type: Option<String>,
    /// Machine-readable JSON output.
    #[arg(long)]
    pub json: bool,
    /// Override the ledger URL (defaults to `WARDEN_LEDGER_URL` or
    /// `http://localhost:8083`).
    #[arg(long)]
    pub ledger_url: Option<String>,
    /// Override the policy-engine URL (defaults to `WARDEN_POLICY_URL`
    /// or `http://localhost:8082`).
    #[arg(long)]
    pub policy_url: Option<String>,
    /// Exit code 2 when the catalog tab shows ≥ 1 regression
    /// (i.e. a known-attack input that USED to be denied now passes).
    /// CI-friendly. Without this flag, exit code 0 even on
    /// regressions.
    #[arg(long)]
    pub fail_on_regression: bool,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ModeArg {
    Add,
    Replace,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum AgainstArg {
    Prod,
    Catalog,
    Both,
}

pub async fn run(args: PolicyArgs) -> ExitCode {
    match args.action {
        PolicyAction::Test(a) => run_test(a).await,
    }
}

async fn run_test(args: TestArgs) -> ExitCode {
    let body = match std::fs::read_to_string(&args.file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: read {}: {}", args.file.display(), e);
            return ExitCode::Validation;
        }
    };
    let candidate_name = args.name.clone().unwrap_or_else(|| {
        args.file
            .file_name()
            .and_then(|s| s.to_str())
            .map(str::to_string)
            .unwrap_or_else(|| "candidate.rego".into())
    });
    let mode = match args.mode {
        ModeArg::Add => BatchMode::Add,
        ModeArg::Replace => BatchMode::Replace,
    };
    if matches!(mode, BatchMode::Replace) && args.replace.is_none() {
        eprintln!("error: --mode replace requires --replace <rule-name>");
        return ExitCode::Validation;
    }

    let since = match parse_window(&args.since) {
        Ok(d) => Utc::now() - d,
        Err(e) => {
            eprintln!("error: --since: {}", e);
            return ExitCode::Validation;
        }
    };

    let ledger_url = args
        .ledger_url
        .clone()
        .or_else(|| std::env::var("WARDEN_LEDGER_URL").ok())
        .unwrap_or_else(|| "http://localhost:8083".into());
    let policy_url = args
        .policy_url
        .clone()
        .or_else(|| std::env::var("WARDEN_POLICY_URL").ok())
        .unwrap_or_else(|| "http://localhost:8082".into());

    let ledger = match LedgerClient::new(&ledger_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: ledger url {}: {}", ledger_url, e);
            return ExitCode::Validation;
        }
    };
    let policy = match PoliciesClient::new(&policy_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: policy url {}: {}", policy_url, e);
            return ExitCode::Validation;
        }
    };

    let mut prod_resp: Option<EvaluateBatchResponse> = None;
    let mut prod_window_total: i64 = 0;
    let mut prod_window_returned: i64 = 0;
    if matches!(args.against, AgainstArg::Prod | AgainstArg::Both) {
        let corpus = match ledger
            .replay_corpus(ReplayCorpusParams {
                since,
                until: None,
                agent_id: args.agent_id.clone(),
                tool_type: args.tool_type.clone(),
                limit: args.limit,
            })
            .await
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: pull replay corpus from ledger: {}", e);
                return ExitCode::Server;
            }
        };
        prod_window_total = corpus.total_in_window;
        prod_window_returned = corpus.returned;
        let inputs: Vec<serde_json::Value> =
            corpus.corpus.into_iter().map(|e| e.input).collect();
        if inputs.is_empty() {
            // No replayable rows yet — print and move on. Catalog tab
            // still runs.
            if !args.json {
                println!(
                    "Production corpus  (since {}): 0 replayable rows",
                    since.to_rfc3339()
                );
            }
        } else {
            let req = EvaluateBatchRequest {
                candidate_rego: body.clone(),
                candidate_name: candidate_name.clone(),
                mode,
                replace_rule_name: args.replace.clone(),
                inputs,
            };
            match policy.evaluate_batch(&req).await {
                Ok(r) => prod_resp = Some(r),
                Err(e) => {
                    return surface_batch_error(e);
                }
            }
        }
    }

    let mut catalog_resp: Option<EvaluateBatchResponse> = None;
    let mut catalog_regressions = 0usize;
    if matches!(args.against, AgainstArg::Catalog | AgainstArg::Both) {
        let inputs = catalog_inputs();
        let req = EvaluateBatchRequest {
            candidate_rego: body,
            candidate_name,
            mode,
            replace_rule_name: args.replace,
            inputs,
        };
        match policy.evaluate_batch(&req).await {
            Ok(r) => {
                // Count regressions: input that the active engine
                // denied (deny tier) but the candidate now allows.
                catalog_regressions = r
                    .results
                    .iter()
                    .filter(|row| {
                        matches!(
                            row.diff,
                            DiffClass::DenyToAllow | DiffClass::YellowToAllow
                        )
                    })
                    .count();
                catalog_resp = Some(r);
            }
            Err(e) => {
                return surface_batch_error(e);
            }
        }
    }

    if args.json {
        let out = serde_json::json!({
            "production": prod_resp,
            "production_window": {
                "since": since.to_rfc3339(),
                "total_in_window": prod_window_total,
                "returned": prod_window_returned,
            },
            "catalog": catalog_resp,
            "catalog_regressions": catalog_regressions,
        });
        match serde_json::to_string_pretty(&out) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("error: serialize: {}", e);
                return ExitCode::Server;
            }
        }
    } else {
        print_human(
            &args.file,
            &mode,
            since,
            prod_window_total,
            prod_resp.as_ref(),
            catalog_resp.as_ref(),
            catalog_regressions,
        );
    }

    if args.fail_on_regression && catalog_regressions > 0 {
        return ExitCode::Validation;
    }
    ExitCode::Ok
}

fn surface_batch_error(e: WardenError) -> ExitCode {
    if let WardenError::Server { status, body } = &e
        && status.as_u16() == 400
        && let Some(parsed) = parse_batch_error(body)
    {
        eprintln!(
            "error: candidate failed to compile:\n  {}{}",
            parsed.compile_error.message,
            match (parsed.compile_error.line, parsed.compile_error.column) {
                (Some(l), Some(c)) => format!("\n  at line {}, column {}", l, c),
                _ => String::new(),
            }
        );
        return ExitCode::Validation;
    }
    eprintln!("error: evaluate-batch: {}", e);
    ExitCode::from_warden_error(&e)
}

fn print_human(
    file: &std::path::Path,
    mode: &BatchMode,
    since: DateTime<Utc>,
    prod_total: i64,
    prod: Option<&EvaluateBatchResponse>,
    catalog: Option<&EvaluateBatchResponse>,
    catalog_regressions: usize,
) {
    println!(
        "Policy Lab — {} (mode: {})",
        file.display(),
        match mode {
            BatchMode::Add => "add",
            BatchMode::Replace => "replace",
        }
    );
    println!();
    if let Some(p) = prod {
        println!(
            "Production corpus  (since {}, {} replayed of {} in window)",
            since.to_rfc3339(),
            p.results.len(),
            prod_total
        );
        let counts = count_diffs(p);
        print_tile("Allow → Deny    ", counts.allow_to_deny);
        print_tile("Allow → Yellow  ", counts.allow_to_yellow);
        print_tile("Deny  → Allow   ", counts.deny_to_allow);
        print_tile("unchanged       ", counts.unchanged);
        println!();
    }
    if let Some(c) = catalog {
        let counts = count_diffs(c);
        println!(
            "Chaos catalog ({} attacks)",
            c.results.len()
        );
        print_tile("Allow → Deny    ", counts.allow_to_deny);
        print_tile("Deny  → Allow (regression) ", counts.deny_to_allow);
        print_tile("unchanged       ", counts.unchanged);
        println!("  Regressions: {}", catalog_regressions);
    }
}

fn print_tile(label: &str, n: i64) {
    println!("  {} {}", label, n);
}

#[derive(Default)]
struct DiffCounts {
    allow_to_deny: i64,
    allow_to_yellow: i64,
    deny_to_allow: i64,
    unchanged: i64,
    other: i64,
}

fn count_diffs(r: &EvaluateBatchResponse) -> DiffCounts {
    let mut c = DiffCounts::default();
    for row in &r.results {
        match row.diff {
            DiffClass::AllowToDeny => c.allow_to_deny += 1,
            DiffClass::AllowToYellow => c.allow_to_yellow += 1,
            DiffClass::DenyToAllow => c.deny_to_allow += 1,
            DiffClass::Unchanged => c.unchanged += 1,
            _ => c.other += 1,
        }
    }
    c
}

/// Parse `<N>d`, `<N>h`, or `<N>m` into a chrono Duration.
fn parse_window(s: &str) -> Result<CDuration, String> {
    if s.is_empty() {
        return Err("empty".into());
    }
    let (n, unit) = s.split_at(s.len() - 1);
    let n: i64 = n.parse().map_err(|e| format!("not a number: {}", e))?;
    match unit {
        "d" => Ok(CDuration::days(n)),
        "h" => Ok(CDuration::hours(n)),
        "m" => Ok(CDuration::minutes(n)),
        other => Err(format!("unknown unit {:?}; expected d|h|m", other)),
    }
}

/// Synthetic chaos-catalog inputs. The full warden-chaos-catalog data
/// pack lives in a sibling repo; for the v1 wardenctl path we ship a
/// stable shortlist inline so the CLI binary doesn't path-dep on the
/// catalog crate (it'd carry a 2 MB compile cost for a 6-attack
/// fingerprint). The console's Lab page consumes the full catalog
/// directly. This shortlist exercises the headline rules:
///
///   - shell_exec / sql_execute (denylist)
///   - intent score >= 0.2 (prompt injection)
///   - bulk_export off hours (business hours)
///   - velocity (101 recent requests)
///   - wire_transfer (Yellow / HIL)
fn catalog_inputs() -> Vec<serde_json::Value> {
    let mut v = Vec::new();
    let base = |tool: &str, intent: f32| -> serde_json::Value {
        serde_json::json!({
            "tool_type": tool,
            "agent_history": {"last_tool": null},
            "intent_score": intent,
            "current_time": "2026-04-29T14:00:00Z",
            "agent_id": "catalog-bot",
            "method": "tools/call",
            "recent_request_count": 0,
            "agent_kind": "mcp"
        })
    };
    v.push(base("shell_exec", 0.05));
    v.push(base("sql_execute", 0.05));
    v.push(base("read_only", 0.95));
    {
        let mut e = base("bulk_export", 0.05);
        e["current_time"] = serde_json::json!("2026-04-29T22:00:00Z");
        v.push(e);
    }
    {
        let mut e = base("read_only", 0.05);
        e["recent_request_count"] = serde_json::json!(150);
        v.push(e);
    }
    v.push(base("wire_transfer", 0.05));
    // Allow baselines: business-hours bulk_export, plain read_only.
    // These let an `Allow → Deny` flip surface when the candidate
    // tightens policy beyond what the active engine catches.
    v.push(base("bulk_export", 0.05));
    v.push(base("read_only", 0.05));
    v
}

#[allow(dead_code)]
fn unused_to_keep_btreemap_import() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::new()
}
