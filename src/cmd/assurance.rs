//! `clavenarctl assurance diff` — per-release coverage diff.
//!
//! Reads the on-chain `assurance_run` rows the scheduled chaos daemon
//! lands (one per run, carrying a per-category detection rollup in
//! `policy_decision`), groups them by the Clavenar version each run was
//! stamped with, picks the latest run per version, and diffs the
//! per-category detection % between two versions.
//!
//! This is the chain-anchored auditor artifact: every number traces to
//! an on-chain row (the report carries each version's run `seq`), so an
//! auditor re-verifies the underlying evidence with `clavenarctl
//! regulatory verify` / `GET /verify`. The grouping + diff algorithm is
//! mirrored by the console's `/assurance?from=&to=` view so the two
//! surfaces produce the same numbers.

use clap::{Args, Subcommand};
use clavenar_sdk::{LedgerClient, LedgerEntry};
use serde::Serialize;

use crate::ExitCode;

/// Fleet agent the scheduled daemon publishes under.
const FLEET_AGENT: &str = "assurance-monkey";
/// How many recent rows to scan when grouping by version.
const FETCH_CAP: usize = 1000;

#[derive(Debug, Args)]
pub(crate) struct AssuranceArgs {
    #[command(subcommand)]
    pub command: AssuranceCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AssuranceCommand {
    /// Diff per-category detection coverage between two release versions.
    Diff(DiffArgs),
}

#[derive(Debug, Args)]
pub(crate) struct DiffArgs {
    /// Baseline version (the `version` stamped into each assurance_run).
    #[arg(long)]
    pub from_version: String,

    /// Comparison version.
    #[arg(long)]
    pub to_version: String,

    /// Agent lane to read. Defaults to the fleet lane.
    #[arg(long, default_value = FLEET_AGENT)]
    pub agent: String,

    /// Override the ledger base URL. Falls back to `CLAVENAR_LEDGER_URL`
    /// env, then `http://localhost:8083`.
    #[arg(long)]
    pub ledger_url: Option<String>,

    /// Emit JSON instead of the human-readable table.
    #[arg(long)]
    pub json: bool,

    /// Write the report to a file. Use `-` (default) for stdout.
    #[arg(long, default_value = "-")]
    pub output: String,
}

#[derive(Debug, Serialize, PartialEq)]
struct CategoryDelta {
    key: String,
    from_pct: Option<f64>,
    to_pct: Option<f64>,
    delta: Option<f64>,
    regressed: bool,
}

#[derive(Debug, Serialize)]
struct DiffReport {
    agent: String,
    from_version: String,
    to_version: String,
    from_seq: i64,
    to_seq: i64,
    from_run_at: Option<String>,
    to_run_at: Option<String>,
    any_regression: bool,
    categories: Vec<CategoryDelta>,
}

/// One parsed `assurance_run` row, reduced to what the diff needs.
struct Run {
    seq: i64,
    at: Option<String>,
    version: String,
    cats: Vec<(String, f64)>,
}

fn parse_run(entry: &LedgerEntry) -> Option<Run> {
    if entry.method != "assurance_run" {
        return None;
    }
    let pd = entry.policy_decision.as_ref()?;
    let version = pd.get("version").and_then(|v| v.as_str())?.to_string();
    let cats = pd
        .get("categories")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    let name = c.get("category").and_then(|v| v.as_str())?;
                    let pct = c.get("pct").and_then(|v| v.as_f64())?;
                    Some((name.to_string(), pct))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Some(Run {
        seq: entry.seq,
        at: Some(entry.timestamp.to_rfc3339()),
        version,
        cats,
    })
}

/// Pick the latest run (highest seq) for `version` from the row set.
fn latest_for_version<'a>(runs: &'a [Run], version: &str) -> Option<&'a Run> {
    runs.iter()
        .filter(|r| r.version == version)
        .max_by_key(|r| r.seq)
}

fn compute_diff(runs: &[Run], agent: &str, from_v: &str, to_v: &str) -> Result<DiffReport, String> {
    let from = latest_for_version(runs, from_v)
        .ok_or_else(|| format!("no assurance_run found for version {from_v:?}"))?;
    let to = latest_for_version(runs, to_v)
        .ok_or_else(|| format!("no assurance_run found for version {to_v:?}"))?;

    // Union of categories present in either run, in stable sorted order.
    let mut keys: Vec<String> = from
        .cats
        .iter()
        .chain(to.cats.iter())
        .map(|(k, _)| k.clone())
        .collect();
    keys.sort();
    keys.dedup();

    let mut categories = Vec::with_capacity(keys.len());
    let mut any_regression = false;
    for key in keys {
        let from_pct = from.cats.iter().find(|(k, _)| *k == key).map(|(_, p)| *p);
        let to_pct = to.cats.iter().find(|(k, _)| *k == key).map(|(_, p)| *p);
        let delta = match (from_pct, to_pct) {
            (Some(f), Some(t)) => Some(t - f),
            _ => None,
        };
        // Regression only when both runs measured the category and the
        // newer one detects strictly less (epsilon guards float noise).
        let regressed = matches!((from_pct, to_pct), (Some(f), Some(t)) if t + 1e-9 < f);
        any_regression |= regressed;
        categories.push(CategoryDelta {
            key,
            from_pct,
            to_pct,
            delta,
            regressed,
        });
    }

    Ok(DiffReport {
        agent: agent.to_string(),
        from_version: from_v.to_string(),
        to_version: to_v.to_string(),
        from_seq: from.seq,
        to_seq: to.seq,
        from_run_at: from.at.clone(),
        to_run_at: to.at.clone(),
        any_regression,
        categories,
    })
}

fn render_table(r: &DiffReport) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "assurance coverage diff: {}", r.agent);
    let _ = writeln!(
        out,
        "  from v{} (seq {}, {})",
        r.from_version,
        r.from_seq,
        r.from_run_at.as_deref().unwrap_or("-")
    );
    let _ = writeln!(
        out,
        "  to   v{} (seq {}, {})",
        r.to_version,
        r.to_seq,
        r.to_run_at.as_deref().unwrap_or("-")
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  {:<16}{:>8}{:>8}{:>8}",
        "category", "from", "to", "Δ"
    );
    for c in &r.categories {
        let fp = c.from_pct.map(pct).unwrap_or_else(|| "—".to_string());
        let tp = c.to_pct.map(pct).unwrap_or_else(|| "—".to_string());
        let d = match c.delta {
            Some(d) => format!("{:+}", (d * 100.0).round() as i64),
            None => "—".to_string(),
        };
        let flag = if c.regressed { "  REGRESSED" } else { "" };
        let _ = writeln!(out, "  {:<16}{fp:>8}{tp:>8}{d:>8}{flag}", c.key);
    }
    if r.any_regression {
        let _ = writeln!(
            out,
            "\n  result: REGRESSION — a category detects less than the baseline"
        );
    } else {
        let _ = writeln!(out, "\n  result: no regression");
    }
    out
}

fn pct(p: f64) -> String {
    format!("{}%", (p * 100.0).round() as i64)
}

pub(crate) async fn run(args: AssuranceArgs) -> ExitCode {
    match args.command {
        AssuranceCommand::Diff(a) => diff(a).await,
    }
}

async fn diff(args: DiffArgs) -> ExitCode {
    let ledger_url = args
        .ledger_url
        .or_else(|| std::env::var("CLAVENAR_LEDGER_URL").ok())
        .unwrap_or_else(|| "http://localhost:8083".to_string());

    let client = match LedgerClient::new(&ledger_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: invalid ledger URL '{ledger_url}': {e}");
            return ExitCode::Validation;
        }
    };

    let entries = match client.audit_agent_paged(&args.agent, FETCH_CAP, 0).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: read {}: {e}", args.agent);
            return ExitCode::from_clavenar_error(&e);
        }
    };

    let runs: Vec<Run> = entries.iter().filter_map(parse_run).collect();
    let report = match compute_diff(&runs, &args.agent, &args.from_version, &args.to_version) {
        Ok(r) => r,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::Validation;
        }
    };

    let rendered = if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: encode report: {e}");
                return ExitCode::Server;
            }
        }
    } else {
        render_table(&report)
    };

    if args.output == "-" {
        print!("{rendered}");
        if !rendered.ends_with('\n') {
            println!();
        }
    } else if let Err(e) = std::fs::write(&args.output, &rendered) {
        eprintln!("error: write {}: {e}", args.output);
        return ExitCode::Server;
    } else {
        eprintln!("wrote {}", args.output);
    }

    // A coverage regression is operator-actionable — exit non-zero so a
    // CI gate on `assurance diff` fails the release.
    if report.any_regression {
        ExitCode::Server
    } else {
        ExitCode::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_fixture(seq: i64, version: &str, cats: &[(&str, f64)]) -> Run {
        Run {
            seq,
            at: Some("2026-06-10T00:00:00Z".into()),
            version: version.into(),
            cats: cats.iter().map(|(k, p)| (k.to_string(), *p)).collect(),
        }
    }

    #[test]
    fn latest_run_per_version_wins() {
        let runs = vec![
            run_fixture(1, "1.20.0", &[("denylist", 1.0)]),
            run_fixture(5, "1.20.0", &[("denylist", 0.5)]),
        ];
        let latest = latest_for_version(&runs, "1.20.0").unwrap();
        assert_eq!(latest.seq, 5);
    }

    #[test]
    fn diff_flags_regression_and_improvement() {
        let runs = vec![
            run_fixture(10, "1.20.0", &[("denylist", 1.0), ("injection", 1.0)]),
            run_fixture(20, "1.21.0", &[("denylist", 1.0), ("injection", 0.5)]),
        ];
        let r = compute_diff(&runs, "assurance-monkey", "1.20.0", "1.21.0").unwrap();
        assert!(r.any_regression);
        let inj = r.categories.iter().find(|c| c.key == "injection").unwrap();
        assert_eq!(inj.delta, Some(-0.5));
        assert!(inj.regressed);
        let den = r.categories.iter().find(|c| c.key == "denylist").unwrap();
        assert!(!den.regressed);
        assert_eq!(den.delta, Some(0.0));
    }

    #[test]
    fn diff_errors_on_missing_version() {
        let runs = vec![run_fixture(1, "1.20.0", &[("denylist", 1.0)])];
        assert!(compute_diff(&runs, "a", "1.20.0", "9.9.9").is_err());
    }

    #[test]
    fn new_category_has_no_delta_and_no_regression() {
        let runs = vec![
            run_fixture(10, "1.20.0", &[("denylist", 1.0)]),
            run_fixture(20, "1.21.0", &[("denylist", 1.0), ("supply_chain", 1.0)]),
        ];
        let r = compute_diff(&runs, "a", "1.20.0", "1.21.0").unwrap();
        let sc = r
            .categories
            .iter()
            .find(|c| c.key == "supply_chain")
            .unwrap();
        assert_eq!(sc.from_pct, None);
        assert_eq!(sc.delta, None);
        assert!(!sc.regressed);
        assert!(!r.any_regression);
    }
}
