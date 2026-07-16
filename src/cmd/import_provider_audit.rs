//! `clavenarctl import-provider-audit` — Shadow-Agent-Radar provider
//! audit-log correlation.
//!
//! A compromised or unmanaged agent that skips the proxy still shows up
//! in the *provider's* own usage export (CloudTrail, the Anthropic/OpenAI
//! usage API, a cloud billing export). This bridges that export against
//! the forensic chain: per agent, the provider's call count vs the
//! agent's on-chain verdict count in the same window. Present at the
//! provider but absent (or undercounted) on the chain = **bypass
//! evidence** — traffic that never crossed the control plane.
//!
//! Integration boundary: provider exports differ by vendor, so this
//! consumes a *normalized* JSON array (`[{agent_id, usage_count}]`) that a
//! per-provider adapter produces. The correlation against the chain is
//! provider-agnostic.

use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::Args;
use clavenar_sdk::LedgerClient;
use serde::{Deserialize, Serialize};

use crate::ExitCode;

/// Cap on chain rows fetched per agent. The bypass signal is "chain has
/// FEWER than the provider" — agents at or above this cap are clearly not
/// bypassing, so an exact count past it adds nothing.
const CHAIN_FETCH_CAP: usize = 5000;

#[derive(Debug, Args)]
pub(crate) struct ImportProviderAuditArgs {
    /// Normalized provider usage export: a JSON array of
    /// `{"agent_id": "...", "usage_count": N}` (a per-provider adapter
    /// produces this from CloudTrail / a usage API / a billing export).
    /// `-` reads from stdin.
    pub export: PathBuf,

    /// Label for the provider the export came from (e.g. `aws`,
    /// `anthropic`). Surfaced in the report only.
    #[arg(long, default_value = "provider")]
    pub provider: String,

    /// Ledger base URL (public read port). Defaults to
    /// `CLAVENAR_LEDGER_URL` or `http://localhost:8083`.
    #[arg(long)]
    pub ledger_url: Option<String>,

    /// Correlation window in hours back from now; the chain count covers
    /// `[now − window, now)`. Match it to the provider export's window.
    #[arg(long, default_value_t = 24)]
    pub window_hours: i64,

    /// Emit the bypass report as JSON instead of a table.
    #[arg(long)]
    pub json: bool,
}

/// One agent's usage as the provider's export reports it.
#[derive(Debug, Deserialize)]
struct ProviderUsage {
    agent_id: String,
    #[serde(alias = "count")]
    usage_count: u64,
}

/// One agent with provider activity that the chain doesn't fully account
/// for — bypass evidence.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct BypassRow {
    pub agent_id: String,
    pub provider_count: u64,
    pub chain_count: u64,
    pub delta: u64,
    /// `no_chain` (zero on-chain traffic) or `undercount` (some, but
    /// fewer than the provider).
    pub kind: &'static str,
}

/// Pure correlation: provider counts vs on-chain counts. Emits a row for
/// every agent whose provider activity exceeds its chain activity,
/// strongest gap first. `no_chain` (the agent never touched the control
/// plane) sorts ahead of an equal-delta `undercount`.
pub(crate) fn correlate(
    provider: &BTreeMap<String, u64>,
    chain: &BTreeMap<String, u64>,
) -> Vec<BypassRow> {
    let mut rows: Vec<BypassRow> = provider
        .iter()
        .filter_map(|(agent_id, &provider_count)| {
            let chain_count = chain.get(agent_id).copied().unwrap_or(0);
            if provider_count <= chain_count {
                return None;
            }
            Some(BypassRow {
                agent_id: agent_id.clone(),
                provider_count,
                chain_count,
                delta: provider_count - chain_count,
                kind: if chain_count == 0 {
                    "no_chain"
                } else {
                    "undercount"
                },
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        // no_chain ahead of undercount, then by delta desc, then by id.
        let rank = |r: &BypassRow| u8::from(r.kind == "undercount");
        rank(a)
            .cmp(&rank(b))
            .then(b.delta.cmp(&a.delta))
            .then(a.agent_id.cmp(&b.agent_id))
    });
    rows
}

pub(crate) async fn run(args: ImportProviderAuditArgs) -> ExitCode {
    let raw = if args.export.as_os_str() == "-" {
        use std::io::Read;
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("error: read stdin: {e}");
            return ExitCode::Validation;
        }
        buf
    } else {
        match std::fs::read_to_string(&args.export) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: read {}: {e}", args.export.display());
                return ExitCode::Validation;
            }
        }
    };

    let usage: Vec<ProviderUsage> = match serde_json::from_str(&raw) {
        Ok(u) => u,
        Err(e) => {
            eprintln!(
                "error: not a normalized provider export (expected [{{agent_id, usage_count}}]): {e}"
            );
            return ExitCode::Validation;
        }
    };
    if usage.is_empty() {
        eprintln!("export has no agents — nothing to correlate");
        return ExitCode::Ok;
    }

    let mut provider: BTreeMap<String, u64> = BTreeMap::new();
    for u in usage {
        // A provider that lists an agent twice (paged export) sums.
        *provider.entry(u.agent_id).or_insert(0) += u.usage_count;
    }

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
    let since = chrono::Utc::now() - chrono::Duration::hours(args.window_hours.max(1));

    let mut chain: BTreeMap<String, u64> = BTreeMap::new();
    for agent_id in provider.keys() {
        match client
            .audit_agent_paged_since(agent_id, CHAIN_FETCH_CAP, 0, since)
            .await
        {
            Ok(rows) => {
                chain.insert(agent_id.clone(), rows.len() as u64);
            }
            Err(e) => {
                eprintln!("error: chain read for {agent_id}: {e}");
                return ExitCode::from_clavenar_error(&e);
            }
        }
    }

    let bypass = correlate(&provider, &chain);

    if args.json {
        match serde_json::to_string_pretty(&bypass) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: serialize report: {e}");
                return ExitCode::Validation;
            }
        }
        return ExitCode::Ok;
    }

    if bypass.is_empty() {
        println!(
            "no bypass evidence: every agent in the {} export is fully accounted for on the chain ({}h window)",
            args.provider, args.window_hours
        );
        return ExitCode::Ok;
    }
    println!(
        "BYPASS EVIDENCE ({} agent(s) — provider activity exceeds on-chain, {}h window, provider={}):",
        bypass.len(),
        args.window_hours,
        args.provider
    );
    for r in &bypass {
        println!(
            "  {:<40} provider={:<8} chain={:<8} gap={:<8} [{}]",
            r.agent_id, r.provider_count, r.chain_count, r.delta, r.kind
        );
    }
    ExitCode::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn flags_no_chain_and_undercount_skips_accounted() {
        let provider = m(&[("ghost", 50), ("leaky", 100), ("clean", 30), ("quiet", 5)]);
        let chain = m(&[("leaky", 60), ("clean", 30), ("quiet", 40)]);
        let rows = correlate(&provider, &chain);
        // ghost: no chain rows → bypass; leaky: 100>60 → undercount;
        // clean: 30==30 → accounted; quiet: 5<40 → accounted.
        assert_eq!(rows.len(), 2);
        // no_chain sorts first.
        assert_eq!(rows[0].agent_id, "ghost");
        assert_eq!(rows[0].kind, "no_chain");
        assert_eq!(rows[0].delta, 50);
        assert_eq!(rows[1].agent_id, "leaky");
        assert_eq!(rows[1].kind, "undercount");
        assert_eq!(rows[1].delta, 40);
    }

    #[test]
    fn no_bypass_when_chain_covers_everything() {
        let provider = m(&[("a", 10), ("b", 20)]);
        let chain = m(&[("a", 10), ("b", 25)]);
        assert!(correlate(&provider, &chain).is_empty());
    }
}
