//! `clavenarctl agents import-from-workloads` — the workload-discovery
//! half of the onboarding funnel.
//!
//! Three discovery sources, one register-if-absent engine:
//!
//!   * a SPIRE `entry show -output json` file,
//!   * a flat list of `spiffe://…` IDs / paths / bare names (one per line),
//!   * `--from-identity`, which pulls identity's `GET /agents/orphans`
//!     feed (names that minted an SVID but were never registered).
//!
//! Each discovered SPIFFE id resolves to a candidate `agent_name`. By
//! default the command writes a names file (review-first, exactly like
//! `import-from-scanner`); `--enroll --default-owner-team …` instead
//! registers the unenrolled names directly with a default envelope,
//! reusing the same idempotent engine `agents migrate` drives.

use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::Args;
use serde::Deserialize;

use crate::cmd::migrate::{build_migration_client, enroll_names, print_outcomes, EnrollDefaults};
use crate::config;
use crate::ExitCode;

#[derive(Debug, Args)]
pub(crate) struct ImportWorkloadsArgs {
    /// SPIRE `entry show -output json` file, a flat list of `spiffe://…`
    /// IDs / paths / names (one per line, `#` comments skipped), or `-`
    /// for stdin. Omit when `--from-identity` is set.
    pub source: Option<PathBuf>,

    #[arg(long)]
    pub tenant: Option<String>,

    /// Discover from identity's own SVID log (`GET /agents/orphans`)
    /// instead of a file — names that authenticated but were never
    /// registered. Mutually exclusive with a positional source.
    #[arg(long = "from-identity", conflicts_with = "source")]
    pub from_identity: bool,

    /// Register the discovered names directly (register-if-absent) with
    /// the default envelope below, instead of writing a names file.
    /// Requires `--default-owner-team`.
    #[arg(long)]
    pub enroll: bool,

    /// Where to write the names file (default: stdout). Ignored with
    /// `--enroll`. The file is the input to `agents migrate --names`.
    #[arg(long, short = 'o')]
    pub out: Option<PathBuf>,

    /// `--enroll` default owner team stamped on every created row.
    #[arg(long = "default-owner-team")]
    pub default_owner_team: Option<String>,
    #[arg(long = "default-scope")]
    pub default_scope: Vec<String>,
    #[arg(long = "default-yellow-scope")]
    pub default_yellow_scope: Vec<String>,
    #[arg(long = "default-attestation-kind")]
    pub default_attestation_kind: Vec<String>,

    /// With `--enroll`, print the planned creates without executing.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// With `--enroll`, emit the per-row outcome summary as JSON.
    #[arg(long)]
    pub json: bool,
}

// ── SPIRE `entry show -output json` (subset) ───────────────────────────
#[derive(Debug, Deserialize)]
struct SpireEntries {
    #[serde(default)]
    entries: Vec<SpireEntry>,
}

#[derive(Debug, Deserialize)]
struct SpireEntry {
    spiffe_id: SpireId,
}

#[derive(Debug, Deserialize)]
struct SpireId {
    #[serde(default)]
    path: String,
}

pub(crate) async fn run(args: ImportWorkloadsArgs, cfg: &config::Config, url: &str) -> ExitCode {
    let tenant = match config::resolve_tenant(args.tenant.clone(), cfg) {
        Ok(t) => t,
        Err(c) => return c,
    };
    if !args.from_identity && args.source.is_none() {
        eprintln!("error: pass a SPIRE/workload list source (or `-`), or --from-identity");
        return ExitCode::Validation;
    }

    // A client is needed for the identity feed and for --enroll; both
    // share the migration actor-sub stamp.
    let client_actor = if args.from_identity || args.enroll {
        match build_migration_client(&tenant, url) {
            Ok(v) => Some(v),
            Err(c) => return c,
        }
    } else {
        None
    };

    let names: Vec<String> = if args.from_identity {
        let (client, _) = client_actor.as_ref().expect("client built when from_identity");
        match client.list_orphans(&tenant).await {
            Ok(orphans) => {
                // The orphans feed is server-sorted by recency; re-sort
                // lexicographically + dedup so both discovery sources
                // produce the same stable, diffable order in the names
                // file and the enrollment summary.
                let mut names: Vec<String> =
                    orphans.into_iter().map(|o| o.agent_name).collect();
                names.sort();
                names.dedup();
                names
            }
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from_clavenar_error(&e);
            }
        }
    } else {
        let raw = match read_source(args.source.as_deref()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: read source: {e}");
                return ExitCode::Validation;
            }
        };
        parse_workload_names(&raw, &tenant)
    };

    if names.is_empty() {
        eprintln!("no workloads discovered — nothing to import");
        return ExitCode::Ok;
    }

    if !args.enroll {
        // Review-first: write a names file (or stdout) for `agents migrate`.
        let body: String = names.iter().map(|n| format!("{n}\n")).collect();
        match &args.out {
            Some(path) => {
                if let Err(e) = std::fs::write(path, &body) {
                    eprintln!("error: write {}: {e}", path.display());
                    return ExitCode::Validation;
                }
                eprintln!(
                    "wrote {} candidate agent name(s) to {} — review, then: \
                     clavenarctl agents migrate --names {} --default-owner-team <team>\n\
                     (or re-run with --enroll --default-owner-team <team> to register now)",
                    names.len(),
                    path.display(),
                    path.display()
                );
            }
            None => print!("{body}"),
        }
        return ExitCode::Ok;
    }

    // --enroll: register-if-absent directly with a default envelope.
    let Some(owner_team) = args.default_owner_team.as_deref() else {
        eprintln!("error: --enroll requires --default-owner-team <team>");
        return ExitCode::Validation;
    };
    let (client, actor_sub) = client_actor.as_ref().expect("client built when enroll");
    let defaults = EnrollDefaults {
        owner_team,
        scope: &args.default_scope,
        yellow_scope: &args.default_yellow_scope,
        attestation_kinds: &args.default_attestation_kind,
    };
    let (outcomes, hard_failure) =
        enroll_names(client, &tenant, actor_sub, &names, &defaults, args.dry_run).await;

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

/// Read the source file (`-` = stdin).
fn read_source(source: Option<&std::path::Path>) -> std::io::Result<String> {
    match source {
        Some(p) if p.as_os_str() == "-" => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            Ok(buf)
        }
        Some(p) => std::fs::read_to_string(p),
        None => Ok(String::new()),
    }
}

/// Parse a workload-list blob into candidate agent names, scoped to
/// `tenant`. Tries SPIRE `entry show -output json` first; on a non-match
/// falls back to flat per-line parsing (`spiffe://…`, bare paths, or
/// plain names; `#` comments and blanks skipped). Names are deduped,
/// sorted for stable re-runs.
fn parse_workload_names(raw: &str, tenant: &str) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();

    if let Ok(spire) = serde_json::from_str::<SpireEntries>(raw)
        && !spire.entries.is_empty()
    {
        for e in &spire.entries {
            consider_path(&e.spiffe_id.path, tenant, &mut names);
        }
        return names.into_iter().collect();
    }

    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        consider_path(line, tenant, &mut names);
    }
    names.into_iter().collect()
}

/// Resolve one SPIFFE id / path / name into a candidate agent name and
/// insert it — unless it carries a `/tenant/<t>/` segment naming a
/// *different* tenant (cross-tenant entries are skipped).
fn consider_path(spiffe: &str, tenant: &str, out: &mut BTreeSet<String>) {
    if let Some(t) = tenant_from_spiffe(spiffe)
        && t != tenant
    {
        return; // belongs to another tenant
    }
    if let Some(name) = agent_name_from_spiffe(spiffe) {
        out.insert(name);
    }
}

/// Strip `spiffe://<trust_domain>` and return the path segments.
fn path_segments(spiffe: &str) -> Vec<&str> {
    let path = match spiffe.strip_prefix("spiffe://") {
        Some(rest) => match rest.find('/') {
            Some(i) => &rest[i..],
            None => "",
        },
        None => spiffe,
    };
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// The value following a `key` segment, if present (`…/ns/payments/…`
/// → `seg_after("ns") = "payments"`).
fn seg_after<'a>(segs: &[&'a str], key: &str) -> Option<&'a str> {
    segs.iter().position(|s| *s == key).and_then(|i| segs.get(i + 1).copied())
}

/// Tenant named by a clavenar-shaped SPIFFE path (`/tenant/<t>/…`), if any.
fn tenant_from_spiffe(spiffe: &str) -> Option<String> {
    seg_after(&path_segments(spiffe), "tenant").map(str::to_string)
}

/// Derive a stable agent name from a SPIFFE id / path / bare name.
/// Returns `None` only for an empty path. Resolution order:
///
///   * clavenar shape `…/agent/<name>/…` → `<name>` (the clean case),
///   * SPIRE k8s shape `…/ns/<ns>/sa/<sa>` → `<ns>-<sa>`,
///   * otherwise the last path segment, slugified.
fn agent_name_from_spiffe(spiffe: &str) -> Option<String> {
    let segs = path_segments(spiffe);
    if segs.is_empty() {
        return None;
    }
    if let Some(name) = seg_after(&segs, "agent") {
        return Some(slugify(name));
    }
    if let (Some(ns), Some(sa)) = (seg_after(&segs, "ns"), seg_after(&segs, "sa")) {
        return Some(slugify(&format!("{ns}-{sa}")));
    }
    segs.last().map(|s| slugify(s))
}

/// Lowercase, collapse non-alphanumerics to single `-`, trim. Mirrors
/// `import_scanner`'s slug rules (minus the `scanner-` prefix) so a
/// reviewed names file reads the same across both discovery sources.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_clavenar_agent_segment() {
        assert_eq!(
            agent_name_from_spiffe("spiffe://clavenar.local/tenant/acme/agent/support-bot-3/instance/abc"),
            Some("support-bot-3".to_string())
        );
    }

    #[test]
    fn extracts_spire_k8s_ns_sa() {
        assert_eq!(
            agent_name_from_spiffe("spiffe://prod.example.org/ns/payments/sa/billing-bot"),
            Some("payments-billing-bot".to_string())
        );
    }

    #[test]
    fn slugifies_fallback_last_segment() {
        assert_eq!(
            agent_name_from_spiffe("spiffe://td/workload/Weird_Name.v2"),
            Some("weird-name-v2".to_string())
        );
    }

    #[test]
    fn skips_cross_tenant_clavenar_paths() {
        let mut names: BTreeSet<String> = BTreeSet::new();
        consider_path(
            "spiffe://clavenar.local/tenant/globex/agent/sales-bot/instance/x",
            "acme",
            &mut names,
        );
        assert!(names.is_empty(), "globex path must not enroll into acme");
        consider_path(
            "spiffe://clavenar.local/tenant/acme/agent/acme-bot/instance/x",
            "acme",
            &mut names,
        );
        assert_eq!(names.len(), 1);
        assert!(names.contains("acme-bot"));
    }

    #[test]
    fn parses_spire_entry_json() {
        let json = r#"{"entries":[
            {"spiffe_id":{"trust_domain":"prod","path":"/ns/web/sa/frontend"}},
            {"spiffe_id":{"trust_domain":"prod","path":"/ns/web/sa/frontend"}},
            {"spiffe_id":{"trust_domain":"prod","path":"/ns/api/sa/orders"}}
        ]}"#;
        let names = parse_workload_names(json, "acme");
        // Deduped to two distinct ns-sa pairs.
        assert_eq!(names, vec!["api-orders".to_string(), "web-frontend".to_string()]);
    }

    #[test]
    fn parses_flat_list_skipping_comments() {
        let blob = "# discovered workloads\n\
                    spiffe://td/ns/team/sa/bot-a\n\
                    \n\
                    bot-b\n\
                    # trailing comment\n";
        let names = parse_workload_names(blob, "acme");
        assert_eq!(names, vec!["bot-b".to_string(), "team-bot-a".to_string()]);
    }
}
