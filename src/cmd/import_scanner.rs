//! `clavenarctl agents import-from-scanner` — bridge shadow-scanner
//! output into the `agents migrate` bulk-enroll path.
//!
//! shadow-scanner finds unmanaged provider credentials but stops at a
//! report. This converts that report into a names file (one candidate
//! `agent_name` per line) that `agents migrate --names` consumes, so
//! discovery → inventory → enrollment is one pipeline instead of a
//! manual copy. Each distinct finding location becomes a slugified
//! agent name; the operator reviews the file, then runs `migrate`.

use std::collections::BTreeSet;
use std::path::PathBuf;
use crate::ExitCode;

use clap::Args;
use serde::Deserialize;

#[derive(Debug, Args)]
pub(crate) struct ImportScannerArgs {
    /// shadow-scanner JSON report (the output of `clavenar-shadow-scanner
    /// --json`). `-` reads from stdin.
    pub report: PathBuf,

    /// Where to write the names file. Defaults to stdout. The file is
    /// the input to `agents migrate --names`.
    #[arg(long, short = 'o')]
    pub out: Option<PathBuf>,

    /// Only import findings at or above this severity
    /// (`critical`/`high`/`medium`/`low`). Default: all.
    #[arg(long)]
    pub min_severity: Option<String>,
}

/// Subset of the shadow-scanner report we need. Mirrors
/// `clavenar_shadow_scanner::output::{Report,Aggregate,Location}` by
/// shape — kept as a local mirror so clavenarctl doesn't take a
/// dependency on the scanner crate just to read its JSON.
#[derive(Debug, Deserialize)]
struct ScanReport {
    #[serde(default)]
    aggregates: Vec<ScanAggregate>,
}

#[derive(Debug, Deserialize)]
struct ScanAggregate {
    detector: String,
    severity: String,
    #[serde(default)]
    locations: Vec<ScanLocation>,
}

#[derive(Debug, Deserialize)]
struct ScanLocation {
    location: String,
}

const SEVERITY_RANK: &[&str] = &["low", "medium", "high", "critical"];

fn severity_rank(s: &str) -> usize {
    SEVERITY_RANK
        .iter()
        .position(|r| r.eq_ignore_ascii_case(s))
        .unwrap_or(0)
}

/// Derive a stable, predictable agent name from a finding location.
/// Locations are source-specific: `owner/repo:path@ref`,
/// `slack://channel/ts`, or a filesystem path. We slug the
/// human-meaningful prefix (drop the `@ref` / line / timestamp tail)
/// so the same credential location always maps to the same agent name.
fn agent_name_from_location(location: &str) -> String {
    // Drop a trailing `@ref` (GitHub) or `#Lnn`.
    let head = location.split('@').next().unwrap_or(location);
    let head = head.split('#').next().unwrap_or(head);
    // Strip a known scheme prefix.
    let head = head
        .strip_prefix("slack://")
        .or_else(|| head.strip_prefix("file://"))
        .unwrap_or(head);
    let slug: String = head
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    let slug = slug.trim_matches('-').to_string();
    // Collapse runs of '-'.
    let mut out = String::with_capacity(slug.len());
    let mut prev_dash = false;
    for c in slug.chars() {
        if c == '-' {
            if !prev_dash {
                out.push('-');
            }
            prev_dash = true;
        } else {
            out.push(c);
            prev_dash = false;
        }
    }
    let out = out.trim_matches('-');
    if out.is_empty() {
        "unknown-agent".to_string()
    } else {
        format!("scanner-{out}")
    }
}

pub(crate) fn run(args: ImportScannerArgs) -> ExitCode {
    let raw = if args.report.as_os_str() == "-" {
        use std::io::Read;
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("error: read stdin: {e}");
            return ExitCode::Validation;
        }
        buf
    } else {
        match std::fs::read_to_string(&args.report) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: read {}: {e}", args.report.display());
                return ExitCode::Validation;
            }
        }
    };

    let report: ScanReport = match serde_json::from_str(&raw) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: not a shadow-scanner JSON report: {e}");
            return ExitCode::Validation;
        }
    };

    let floor = args.min_severity.as_deref().map(severity_rank);
    // BTreeSet → sorted + deduped, so re-running on the same report is
    // stable and a credential found in two places enrolls once.
    let mut names: BTreeSet<String> = BTreeSet::new();
    for agg in &report.aggregates {
        if let Some(f) = floor {
            if severity_rank(&agg.severity) < f {
                continue;
            }
        }
        let _ = &agg.detector; // detector is retained for future scope hints
        for loc in &agg.locations {
            names.insert(agent_name_from_location(&loc.location));
        }
    }

    if names.is_empty() {
        eprintln!("no findings matched — nothing to import");
        return ExitCode::Ok;
    }

    let body: String = names.iter().map(|n| format!("{n}\n")).collect();
    match &args.out {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &body) {
                eprintln!("error: write {}: {e}", path.display());
                return ExitCode::Validation;
            }
            eprintln!(
                "wrote {} candidate agent name(s) to {} — review, then: \
                 clavenarctl agents migrate --names {} --default-owner-team <team>",
                names.len(),
                path.display(),
                path.display()
            );
        }
        None => print!("{body}"),
    }
    ExitCode::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_github_location() {
        assert_eq!(
            agent_name_from_location("acme/api:src/config.ts@main"),
            "scanner-acme-api-src-config-ts"
        );
    }

    #[test]
    fn slugs_slack_and_collapses_dashes() {
        assert_eq!(
            agent_name_from_location("slack://eng-alerts/1699999999.001"),
            "scanner-eng-alerts-1699999999-001"
        );
    }

    #[test]
    fn parses_report_and_dedups() {
        let json = r#"{
            "aggregates": [
                {"detector":"aws","severity":"critical","locations":[
                    {"location":"acme/api:a.ts@main"},
                    {"location":"acme/api:a.ts@main"}
                ]},
                {"detector":"slack","severity":"low","locations":[
                    {"location":"acme/web:b.ts@main"}
                ]}
            ]
        }"#;
        let report: ScanReport = serde_json::from_str(json).unwrap();
        let mut names: BTreeSet<String> = BTreeSet::new();
        for agg in &report.aggregates {
            if severity_rank(&agg.severity) < severity_rank("high") {
                continue;
            }
            for loc in &agg.locations {
                names.insert(agent_name_from_location(&loc.location));
            }
        }
        // Only the critical one survives the `high` floor, deduped to 1.
        assert_eq!(names.len(), 1);
        assert!(names.contains("scanner-acme-api-a-ts"));
    }
}
