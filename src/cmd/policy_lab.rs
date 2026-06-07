//! `clavenarctl policy test <file.rego>` — Policy Lab CLI.
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
//! `clavenar-chaos-catalog` path-dep on clavenar-console; the CLI
//! re-implements a minimal catalog wrapper inline so this binary
//! stays light.
//!
//! Hits the policy engine and ledger via the shared SDK. Bearer
//! token: `CLAVENAR_POLICY_TEST_BEARER` (optional — for the prod
//! deployment that fronts the policy engine with token auth).

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Duration as CDuration, Utc};
use clap::{Args, Subcommand};
use clavenar_sdk::{
    parse_batch_error, parse_mine_error, BatchMode, BatchVerdict, CreatePolicyRequest, DiffClass,
    EvaluateBatchRequest, EvaluateBatchResponse, LedgerClient, MineCandidate, MineRequest,
    MineResponse, PoliciesClient, ReplayCorpusParams, ClavenarError,
};

use crate::ExitCode;

#[derive(Debug, Args)]
pub(crate) struct PolicyArgs {
    #[command(subcommand)]
    pub action: PolicyAction,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PolicyAction {
    /// Replay a candidate Rego rule against the last N days of real
    /// ledger traffic AND against the chaos catalog (the 40-attack
    /// catalogued corpus). Reports the per-input verdict diff and
    /// flags regressions in the catalog tab.
    Test(TestArgs),
    /// Mine the last N days of ledger traffic for recurring patterns
    /// and surface candidate Rego rules. Each candidate carries a
    /// score, a diff vs. the active bundle, and (optionally) a
    /// Brain-rendered explanation. `--accept <id>` lands the named
    /// candidate as an inactive draft policy.
    Learn(LearnArgs),
    /// Emit a fresh starter Rego template with frontmatter
    /// pre-filled. Pure filesystem work — no policy-engine call.
    Scaffold(crate::cmd::policy_scaffold::ScaffoldArgs),
    /// Browse and install templates from the policy-engine's
    /// on-disk catalog (`/policies/templates*`). The console-side
    /// equivalent is the `/policies/library` page.
    Library(crate::cmd::policy_library::LibraryArgs),
    /// Sign + install signed governance packs. `exchange sign` produces
    /// a signed pack; `exchange install` verifies + backtests it against
    /// the chaos catalog before landing it in the policy-engine.
    Exchange(crate::cmd::policy_exchange::ExchangeArgs),
    /// Install (activate) a policy by name, or every policy in a
    /// category (`--category <domain>`). Disabled-by-default policies
    /// become live on the next atomic engine rebuild.
    Install(crate::cmd::policy_install::InstallArgs),
    /// Uninstall (deactivate) a policy by name, or every policy in a
    /// category. The protected baseline floor is left untouched.
    Uninstall(crate::cmd::policy_install::InstallArgs),
}

#[derive(Debug, Args)]
pub(crate) struct LearnArgs {
    /// Window to pull from the ledger. Default `7d`.
    #[arg(long, default_value = "7d")]
    pub since: String,
    /// Cap on inputs pulled from the ledger. Default 1000, max 5000.
    #[arg(long, default_value = "1000")]
    pub limit: i64,
    /// Server-side cap on candidates returned. Default 10, max 20.
    #[arg(long = "max-candidates", default_value = "10")]
    pub max_candidates: u32,
    /// Filter the corpus to one agent id.
    #[arg(long)]
    pub agent_id: Option<String>,
    /// Filter the corpus to one tool_type.
    #[arg(long)]
    pub tool_type: Option<String>,
    /// Skip the Brain enrichment call. Candidates ship with template
    /// one-liners only — useful when running under CI without an
    /// LLM provider configured.
    #[arg(long = "no-brain")]
    pub no_brain: bool,
    /// Land the named candidate id as an inactive draft policy
    /// instead of just printing. Re-runs the mine to recover the
    /// candidate, so `--accept` is a one-step terminal flow rather
    /// than a two-call dance.
    #[arg(long)]
    pub accept: Option<String>,
    /// Land every candidate that compiles and produces 0 catalog
    /// regressions. Same draft-not-active posture as `--accept`.
    /// Skipped when `--accept` is supplied.
    #[arg(long = "accept-all-safe")]
    pub accept_all_safe: bool,
    /// Machine-readable JSON output.
    #[arg(long)]
    pub json: bool,
    /// Override the ledger URL (defaults to `CLAVENAR_LEDGER_URL` or
    /// `http://localhost:8083`).
    #[arg(long)]
    pub ledger_url: Option<String>,
    /// Override the policy-engine URL (defaults to `CLAVENAR_POLICY_URL`
    /// or `http://localhost:8082`).
    #[arg(long)]
    pub policy_url: Option<String>,
    /// Client cert (PEM) for the outbound mTLS handshake. Required to
    /// reach the ledger's `/audit/replay/corpus` (operator-only) and
    /// the policy-engine's mTLS app-listener. Pair with `--client-key`
    /// and `--ca-cert`. Without these the CLI falls back to plain HTTP
    /// and gets a 404 on the corpus pull in any locked-down env.
    #[arg(long)]
    pub client_cert: Option<PathBuf>,
    /// Client key (PEM) — sibling of `--client-cert`.
    #[arg(long)]
    pub client_key: Option<PathBuf>,
    /// CA cert (PEM) used to verify the server cert on outbound mTLS
    /// hops. Should match the env's CA bundle (clavenar-proxy/certs/ca.crt
    /// for prod, certs-dev/ca.crt for dev).
    #[arg(long)]
    pub ca_cert: Option<PathBuf>,
    /// Map a docker-internal hostname to a host:port. Repeatable.
    /// Mirrors `curl --resolve NAME:PORT:ADDR`. Use this when running
    /// clavenarctl from the host against a compose stack — the cert
    /// SANs target `ledger` / `policy-engine`, but those don't resolve
    /// outside the docker network.
    ///
    /// Format: `<name>:<port>:<ip>`. Example:
    /// `--resolve ledger:18183:127.0.0.1 --resolve policy-engine:18082:127.0.0.1`.
    #[arg(long = "resolve")]
    pub resolve: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct TestArgs {
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
    /// Override the ledger URL (defaults to `CLAVENAR_LEDGER_URL` or
    /// `http://localhost:8083`).
    #[arg(long)]
    pub ledger_url: Option<String>,
    /// Override the policy-engine URL (defaults to `CLAVENAR_POLICY_URL`
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
pub(crate) enum ModeArg {
    Add,
    Replace,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum AgainstArg {
    Prod,
    Catalog,
    Both,
}

pub(crate) async fn run(args: PolicyArgs) -> ExitCode {
    match args.action {
        PolicyAction::Test(a) => run_test(a).await,
        PolicyAction::Learn(a) => run_learn(a).await,
        PolicyAction::Scaffold(a) => crate::cmd::policy_scaffold::run(a),
        PolicyAction::Library(a) => crate::cmd::policy_library::run(a).await,
        PolicyAction::Exchange(a) => crate::cmd::policy_exchange::run(a).await,
        PolicyAction::Install(a) => crate::cmd::policy_install::run(a, /*activate=*/ true).await,
        PolicyAction::Uninstall(a) => crate::cmd::policy_install::run(a, /*activate=*/ false).await,
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
        .or_else(|| std::env::var("CLAVENAR_LEDGER_URL").ok())
        .unwrap_or_else(|| "http://localhost:8083".into());
    let policy_url = args
        .policy_url
        .clone()
        .or_else(|| std::env::var("CLAVENAR_POLICY_URL").ok())
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

fn surface_batch_error(e: ClavenarError) -> ExitCode {
    if let ClavenarError::Server { status, body } = &e
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
    ExitCode::from_clavenar_error(&e)
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

/// Synthetic chaos-catalog inputs. The full clavenar-chaos-catalog data
/// pack lives in a sibling repo; for the v1 clavenarctl path we ship a
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
    // Attestation-gated SPIFFE'd delete_repo — Deny under the active
    // engine via attestation.rego. A candidate that strips
    // attestation flips it to Allow (the canonical regression demo).
    {
        let mut e = base("delete_repo", 0.05);
        e["agent_spiffe"] = serde_json::json!(
            "spiffe://clavenar.local/tenant/acme/agent/del/instance/x"
        );
        v.push(e);
    }
    // PHI export with 250-patient batch — modeled on the
    // clinical-bot persona's prod traffic. Active engine routes
    // it to HIL Yellow (review). A candidate capping
    // patient_count > 100 surfaces in the after-reasons.
    {
        let mut e = base("phi_export", 0.05);
        e["agent_spiffe"] = serde_json::json!(
            "spiffe://clavenar.local/tenant/acme/agent/clinical/instance/1"
        );
        e["arguments"] = serde_json::json!({
            "patient_count": 250,
            "fields": ["mrn", "dob", "dx_code"],
            "destination": "s3://ehr-exports/batch",
        });
        e["attestation"] = serde_json::json!({
            "kind": "dev-mock",
            "measurement": "dev-binary-hash",
            "issued_at": "2026-04-29T13:55:00Z",
            "expires_at": "2026-04-29T14:10:00Z",
            "nonce_echo": "clavenar-mock-nonce",
        });
        v.push(e);
    }
    v
}

#[allow(dead_code)]
fn unused_to_keep_btreemap_import() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::new()
}

// ── `clavenarctl policy learn` ──────────────────────────────────────────

async fn run_learn(args: LearnArgs) -> ExitCode {
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
        .or_else(|| std::env::var("CLAVENAR_LEDGER_URL").ok())
        .unwrap_or_else(|| "http://localhost:8083".into());
    let policy_url = args
        .policy_url
        .clone()
        .or_else(|| std::env::var("CLAVENAR_POLICY_URL").ok())
        .unwrap_or_else(|| "http://localhost:8082".into());

    let resolve_pairs = match parse_resolve(&args.resolve) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("error: --resolve: {}", msg);
            return ExitCode::Validation;
        }
    };

    // Build an mTLS reqwest::Client if all three cert paths are
    // supplied. Operator routes (`/audit/replay/corpus`,
    // `/policies/mine`) are mTLS-only in any locked-down env; without
    // the certs the CLI runs against plain-HTTP test envs only.
    let mtls_client = match build_mtls_client(
        args.client_cert.as_deref(),
        args.client_key.as_deref(),
        args.ca_cert.as_deref(),
        &resolve_pairs,
    ) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("error: {}", msg);
            return ExitCode::Validation;
        }
    };

    let ledger = match LedgerClient::new(&ledger_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: ledger url {}: {}", ledger_url, e);
            return ExitCode::Validation;
        }
    };
    let ledger = if let Some(c) = mtls_client.clone() {
        ledger.with_http_client(c)
    } else {
        ledger
    };
    let policy = match PoliciesClient::new(&policy_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: policy url {}: {}", policy_url, e);
            return ExitCode::Validation;
        }
    };
    let policy = if let Some(c) = mtls_client {
        policy.with_http_client(c)
    } else {
        policy
    };

    // Pull the corpus first — the miner only sees what the ledger
    // hands over.
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

    if corpus.corpus.is_empty() {
        if args.json {
            let stub = serde_json::json!({
                "candidates": [],
                "corpus_size": 0,
                "candidates_dropped": 0,
                "evaluated_in_ms": 0,
                "note": "no replayable corpus in window",
            });
            println!("{}", serde_json::to_string_pretty(&stub).unwrap());
        } else {
            println!(
                "No replayable corpus in the last {} (since {}).",
                args.since,
                since.to_rfc3339()
            );
            println!("Widen the window or generate traffic before mining.");
        }
        return ExitCode::Ok;
    }

    let inputs: Vec<serde_json::Value> = corpus
        .corpus
        .iter()
        .map(|e| e.input.clone())
        .collect();
    // Historical verdicts come back from the ledger as opaque JSON;
    // the miner only needs `allow` to bucket into Allow tier, but pass
    // the reason vectors through too so the wire shape matches a
    // future stricter consumer.
    let historical: Vec<BatchVerdict> = corpus
        .corpus
        .iter()
        .map(|e| BatchVerdict {
            allow: e
                .historical_verdict
                .get("allow")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            reasons: extract_string_array(&e.historical_verdict, "reasons"),
            review_reasons: extract_string_array(&e.historical_verdict, "review_reasons"),
        })
        .collect();

    let req = MineRequest {
        corpus: inputs,
        historical_verdicts: historical,
        max_candidates: args.max_candidates,
        ask_brain: !args.no_brain,
    };

    let resp = match policy.mine(&req).await {
        Ok(r) => r,
        Err(e) => return surface_mine_error(e),
    };

    // Optional accept stage. `--accept <id>` takes priority over
    // `--accept-all-safe` so a CI dry-run + targeted accept stays
    // possible.
    if let Some(target) = args.accept.as_deref() {
        return accept_candidate(&policy, &resp, target).await;
    }
    if args.accept_all_safe {
        return accept_all_safe(&policy, &resp).await;
    }

    if args.json {
        let body = serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".into());
        println!("{}", body);
        return ExitCode::Ok;
    }

    render_learn_summary(&resp, corpus.returned, &args.since);
    ExitCode::Ok
}

fn render_learn_summary(resp: &MineResponse, corpus_returned: i64, window: &str) {
    println!(
        "Mining {} corpus rows (last {}) — {} candidate(s) in {} ms",
        corpus_returned, window, resp.candidates.len(), resp.evaluated_in_ms
    );
    if resp.candidates_dropped > 0 {
        println!(
            "  ({} candidate(s) dropped: compile-fail or catalog regression)",
            resp.candidates_dropped
        );
    }
    println!();
    for (idx, c) in resp.candidates.iter().enumerate() {
        let badge = if c.brain_enriched { "brain" } else { "template" };
        println!(
            "[{}] {:<36} score {:.1}  ({})",
            idx + 1,
            c.rule_name,
            c.score,
            badge
        );
        println!("    id: {}", c.id);
        println!("    {}", c.one_liner);
        if let Some(r) = c.rationale.as_ref() {
            println!("    {}", r);
        }
        let lr = &c.lab_replay;
        println!(
            "    Allow→Yellow {:<4} Allow→Deny {:<4} Deny→Yellow {:<4} Catalog {}",
            lr.allow_to_yellow,
            lr.allow_to_deny,
            lr.deny_to_yellow,
            if lr.catalog_regressions == 0 { "✓" } else { "✗" }
        );
        println!();
    }
    println!("To land a candidate:  clavenarctl policy learn --accept <id>");
}

async fn accept_candidate(
    policy: &PoliciesClient,
    resp: &MineResponse,
    target: &str,
) -> ExitCode {
    // Match against rule_name OR ephemeral id. Rule_name is the
    // stable surface — ids regenerate per mine run, so a script that
    // pipes `--json | jq .id` into `--accept` only works if both
    // calls happen in the same run. Rule_name avoids that footgun.
    let Some(c) = resp
        .candidates
        .iter()
        .find(|c| c.rule_name == target || c.id == target)
    else {
        eprintln!(
            "error: candidate {} not found in this mine result. \
             Re-run with `--json` to see this run's rule names + ids, \
             then pass either to --accept.",
            target
        );
        return ExitCode::Validation;
    };
    create_draft(policy, c).await
}

async fn accept_all_safe(policy: &PoliciesClient, resp: &MineResponse) -> ExitCode {
    let mut last_err: Option<ExitCode> = None;
    let mut accepted = 0;
    for c in &resp.candidates {
        if c.lab_replay.catalog_regressions > 0 {
            continue;
        }
        match create_draft(policy, c).await {
            ExitCode::Ok => accepted += 1,
            other => {
                eprintln!("error: failed to land {}: exit {}", c.rule_name, other.code());
                last_err = Some(other);
            }
        }
    }
    println!("accepted {} candidate(s) as inactive drafts", accepted);
    last_err.unwrap_or(ExitCode::Ok)
}

async fn create_draft(policy: &PoliciesClient, c: &MineCandidate) -> ExitCode {
    let reason = format!(
        "Self-Learn miner (candidate {}, kind={}, evidence={})",
        c.id, c.kind, c.evidence_count
    );
    // clavenarctl runs operator-side, no OIDC session — stamp the
    // actor as `clavenarctl` so the audit trail still has a value.
    let req = CreatePolicyRequest {
        name: &c.rule_name,
        content_type: "rego",
        body: &c.rego_body,
        reason: &reason,
        actor_sub: "clavenarctl",
        actor_idp: "clavenarctl",
        active: Some(false),
    };
    match policy.create(&req).await {
        Ok(_) => {
            println!("draft created: {} (active=false)", c.rule_name);
            ExitCode::Ok
        }
        Err(e) => {
            eprintln!("error: create draft {}: {}", c.rule_name, e);
            ExitCode::from_clavenar_error(&e)
        }
    }
}

/// Parse `--resolve NAME:PORT:ADDR` flags into a vector the reqwest
/// builder can fold into `resolve_to_addrs`. Mirrors curl's syntax.
pub(crate) fn parse_resolve(raw: &[String]) -> Result<Vec<(String, std::net::SocketAddr)>, String> {
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        // Split from the right twice — the name itself can't contain
        // a colon, but the IPv4 form is unambiguous.
        let mut parts = r.rsplitn(3, ':');
        let ip = parts.next().ok_or_else(|| format!("malformed: {}", r))?;
        let port = parts.next().ok_or_else(|| format!("malformed: {}", r))?;
        let name = parts.next().ok_or_else(|| format!("malformed: {}", r))?;
        let port: u16 = port
            .parse()
            .map_err(|e| format!("malformed port in {}: {}", r, e))?;
        let ip: std::net::IpAddr = ip
            .parse()
            .map_err(|e| format!("malformed ip in {}: {}", r, e))?;
        out.push((name.to_string(), std::net::SocketAddr::new(ip, port)));
    }
    Ok(out)
}

/// Construct a `reqwest::Client` configured for outbound mTLS when
/// all three cert paths are supplied. Returns `Ok(None)` when none
/// are supplied (CLI runs against plain-HTTP test envs). Any partial
/// combo (e.g. cert without key) is rejected at the boundary so we
/// don't silently fall back to plain HTTP in a locked-down env.
pub(crate) fn build_mtls_client(
    cert: Option<&std::path::Path>,
    key: Option<&std::path::Path>,
    ca: Option<&std::path::Path>,
    resolve: &[(String, std::net::SocketAddr)],
) -> Result<Option<reqwest::Client>, String> {
    match (cert, key, ca) {
        (None, None, None) => Ok(None),
        (Some(cert), Some(key), Some(ca)) => {
            let cert_pem = std::fs::read(cert)
                .map_err(|e| format!("read client cert {}: {}", cert.display(), e))?;
            let key_pem = std::fs::read(key)
                .map_err(|e| format!("read client key {}: {}", key.display(), e))?;
            let ca_pem = std::fs::read(ca)
                .map_err(|e| format!("read ca cert {}: {}", ca.display(), e))?;
            let mut combined = cert_pem.clone();
            if !combined.ends_with(b"\n") {
                combined.push(b'\n');
            }
            combined.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&combined)
                .map_err(|e| format!("invalid client identity PEM: {}", e))?;
            let ca_cert = reqwest::Certificate::from_pem(&ca_pem)
                .map_err(|e| format!("invalid CA cert PEM: {}", e))?;
            let mut builder = reqwest::Client::builder()
                .use_rustls_tls()
                .identity(identity)
                .add_root_certificate(ca_cert);
            for (name, addr) in resolve {
                builder = builder.resolve_to_addrs(name, &[*addr]);
            }
            let client = builder
                .build()
                .map_err(|e| format!("build mtls client: {}", e))?;
            Ok(Some(client))
        }
        _ => Err(
            "--client-cert, --client-key, and --ca-cert must all be supplied together"
                .to_string(),
        ),
    }
}

fn extract_string_array(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn surface_mine_error(err: ClavenarError) -> ExitCode {
    if let ClavenarError::Server { ref body, .. } = err
        && let Some(parsed) = parse_mine_error(body)
    {
        eprintln!("error: miner rejected request: {}", parsed.message);
        return ExitCode::Validation;
    }
    eprintln!("error: miner request failed: {}", err);
    ExitCode::from_clavenar_error(&err)
}
