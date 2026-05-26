//! `wardenctl policy library {list,install}` — engine-talking CLI
//! over the `/policies/templates*` surface.
//!
//! Counterpart to the console's `/policies/library` page. List filters
//! the catalog client-side (the engine returns the unfiltered set, the
//! CLI applies the operator's flags) so a single SDK call covers any
//! filter combination. Install thin-wraps the SDK call and surfaces
//! the resulting [`MutationResponse`].
//!
//! Default `--policy-url` resolution mirrors the existing
//! `policy test` / `policy learn` subcommands: flag → `WARDEN_POLICY_URL`
//! env → `http://localhost:8082`.

use clap::{Args, Subcommand};
use warden_sdk::{InstallTemplateRequest, PoliciesClient, PolicyTemplate, WardenError};

use crate::ExitCode;

#[derive(Debug, Args)]
pub(crate) struct LibraryArgs {
    #[command(subcommand)]
    pub action: LibraryAction,
}

#[derive(Debug, Subcommand)]
pub(crate) enum LibraryAction {
    /// Print the catalog of on-disk starter templates available on
    /// the policy engine. Filter via repeated `--domain`,
    /// `--severity`, `--framework`, `--tier` flags; the result is the
    /// AND across facets.
    List(LibraryListArgs),
    /// Install one template into the active policy set. The reason
    /// lands in the ledger alongside `policy.installed_from_template`.
    Install(LibraryInstallArgs),
}

#[derive(Debug, Args)]
pub(crate) struct LibraryListArgs {
    /// Filter by domain. Repeatable (multi-value AND across facets,
    /// OR within a facet — `--domain healthcare --domain finance`
    /// shows templates in either domain).
    #[arg(long)]
    pub domain: Vec<String>,
    /// Filter by severity (`low`, `medium`, `high`, `critical`).
    #[arg(long)]
    pub severity: Vec<String>,
    /// Filter by compliance framework (`HIPAA`, `SOC2`, …).
    #[arg(long)]
    pub framework: Vec<String>,
    /// Filter by tier (`deny`, `review`, `mixed`).
    #[arg(long)]
    pub tier: Vec<String>,
    /// Restrict to templates already installed in the active set.
    #[arg(long = "installed-only")]
    pub installed_only: bool,
    /// Restrict to templates not yet installed.
    #[arg(long = "not-installed")]
    pub not_installed: bool,
    /// Machine-readable JSON output (an array of PolicyTemplate
    /// envelopes).
    #[arg(long)]
    pub json: bool,
    /// Override the policy-engine URL.
    #[arg(long)]
    pub policy_url: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct LibraryInstallArgs {
    /// Template name (filename, e.g. `phi_egress.rego`).
    pub name: String,
    /// Why this install is happening. Persisted on the ledger row.
    #[arg(long)]
    pub reason: String,
    /// Actor sub claim. Defaults to `wardenctl` to match the existing
    /// CLI write paths; override for a CI-attributable identity.
    #[arg(long = "actor-sub", default_value = "wardenctl")]
    pub actor_sub: String,
    /// Actor identity-provider id. Defaults to `wardenctl`.
    #[arg(long = "actor-idp", default_value = "wardenctl")]
    pub actor_idp: String,
    /// Override the policy-engine URL.
    #[arg(long)]
    pub policy_url: Option<String>,
}

pub(crate) async fn run(args: LibraryArgs) -> ExitCode {
    match args.action {
        LibraryAction::List(a) => list(a).await,
        LibraryAction::Install(a) => install(a).await,
    }
}

async fn list(args: LibraryListArgs) -> ExitCode {
    if args.installed_only && args.not_installed {
        eprintln!("error: --installed-only and --not-installed are mutually exclusive.");
        return ExitCode::Validation;
    }
    let policy_url = resolve_policy_url(args.policy_url.as_deref());
    let client = match PoliciesClient::new(&policy_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: policy url {}: {}", policy_url, e);
            return ExitCode::Validation;
        }
    };
    let templates = match client.list_templates().await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: list templates: {}", e);
            return ExitCode::from_warden_error(&e);
        }
    };
    let filters = LibraryFilters {
        domain: args.domain,
        severity: args.severity,
        framework: args.framework,
        tier: args.tier,
        installed_only: args.installed_only,
        not_installed: args.not_installed,
    };
    let filtered = apply_filters(templates, &filters);

    if args.json {
        match serde_json::to_string_pretty(&filtered) {
            Ok(s) => {
                println!("{}", s);
                ExitCode::Ok
            }
            Err(e) => {
                eprintln!("error: serialize: {}", e);
                ExitCode::Server
            }
        }
    } else {
        print_table(&filtered);
        ExitCode::Ok
    }
}

async fn install(args: LibraryInstallArgs) -> ExitCode {
    if args.reason.trim().is_empty() {
        eprintln!("error: --reason must be non-empty.");
        return ExitCode::Validation;
    }
    let policy_url = resolve_policy_url(args.policy_url.as_deref());
    let client = match PoliciesClient::new(&policy_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: policy url {}: {}", policy_url, e);
            return ExitCode::Validation;
        }
    };
    let req = InstallTemplateRequest {
        reason: &args.reason,
        actor_sub: &args.actor_sub,
        actor_idp: &args.actor_idp,
    };
    match client.install_template(&args.name, &req).await {
        Ok(resp) => {
            println!(
                "installed {} (v{}, sha256 {})",
                resp.name, resp.version, resp.body_sha256
            );
            ExitCode::Ok
        }
        Err(WardenError::Server { status, body }) if status.as_u16() == 404 => {
            eprintln!("error: template {:?} not found on engine: {}", args.name, body);
            ExitCode::Validation
        }
        Err(WardenError::Server { status, body }) if status.as_u16() == 409 => {
            eprintln!("error: template {:?} already installed: {}", args.name, body);
            ExitCode::Conflict
        }
        Err(e) => {
            eprintln!("error: install {}: {}", args.name, e);
            ExitCode::from_warden_error(&e)
        }
    }
}

// ── Filter helpers ────────────────────────────────────────────────────

struct LibraryFilters {
    domain: Vec<String>,
    severity: Vec<String>,
    framework: Vec<String>,
    tier: Vec<String>,
    installed_only: bool,
    not_installed: bool,
}

fn apply_filters(
    templates: Vec<PolicyTemplate>,
    filters: &LibraryFilters,
) -> Vec<PolicyTemplate> {
    templates
        .into_iter()
        .filter(|t| {
            if filters.installed_only && !t.installed {
                return false;
            }
            if filters.not_installed && t.installed {
                return false;
            }
            if !filters.domain.is_empty() {
                match t.domain.as_ref() {
                    Some(d) if filters.domain.iter().any(|f| f == d) => {}
                    _ => return false,
                }
            }
            if !filters.severity.is_empty() {
                match t.severity.as_ref() {
                    Some(s) if filters.severity.iter().any(|f| f == s) => {}
                    _ => return false,
                }
            }
            if !filters.framework.is_empty() {
                let any = t.frameworks.iter().any(|f| filters.framework.contains(f));
                if !any {
                    return false;
                }
            }
            if !filters.tier.is_empty() {
                match t.tier.as_ref() {
                    Some(tier) if filters.tier.iter().any(|f| f == tier) => {}
                    _ => return false,
                }
            }
            true
        })
        .collect()
}

fn print_table(rows: &[PolicyTemplate]) {
    if rows.is_empty() {
        println!("(no templates match the current filters)");
        return;
    }
    println!(
        "{:<32} {:<14} {:<10} {:<8} STATE",
        "NAME", "DOMAIN", "SEVERITY", "TIER"
    );
    for t in rows {
        let state = if t.installed { "installed" } else { "available" };
        println!(
            "{:<32} {:<14} {:<10} {:<8} {}",
            t.name,
            t.domain.as_deref().unwrap_or("—"),
            t.severity.as_deref().unwrap_or("—"),
            t.tier.as_deref().unwrap_or("—"),
            state,
        );
    }
}

fn resolve_policy_url(flag: Option<&str>) -> String {
    if let Some(s) = flag {
        return s.to_string();
    }
    if let Ok(env) = std::env::var("WARDEN_POLICY_URL") {
        return env;
    }
    "http://localhost:8082".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(name: &str, domain: &str, severity: &str, tier: &str, installed: bool) -> PolicyTemplate {
        PolicyTemplate {
            name: name.into(),
            content_type: "rego".into(),
            domain: Some(domain.into()),
            severity: Some(severity.into()),
            frameworks: vec!["HIPAA".into()],
            tags: vec!["pii".into()],
            tier: Some(tier.into()),
            tool_surface: vec!["phi_export".into()],
            summary: Some("test".into()),
            installed,
        }
    }

    fn fixtures() -> Vec<PolicyTemplate> {
        vec![
            t("phi_egress.rego", "healthcare", "high", "deny", false),
            t("money_moves.rego", "finance", "critical", "mixed", true),
            t("repo_scope.rego", "coding", "medium", "review", false),
        ]
    }

    fn empty_filters() -> LibraryFilters {
        LibraryFilters {
            domain: Vec::new(),
            severity: Vec::new(),
            framework: Vec::new(),
            tier: Vec::new(),
            installed_only: false,
            not_installed: false,
        }
    }

    #[test]
    fn no_filters_returns_everything() {
        let out = apply_filters(fixtures(), &empty_filters());
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn domain_filter_keeps_matches() {
        let mut f = empty_filters();
        f.domain = vec!["healthcare".into()];
        let out = apply_filters(fixtures(), &f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "phi_egress.rego");
    }

    #[test]
    fn multi_value_domain_is_or_within_facet() {
        let mut f = empty_filters();
        f.domain = vec!["healthcare".into(), "finance".into()];
        let out = apply_filters(fixtures(), &f);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn installed_only_drops_uninstalled() {
        let mut f = empty_filters();
        f.installed_only = true;
        let out = apply_filters(fixtures(), &f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "money_moves.rego");
    }

    #[test]
    fn not_installed_drops_installed() {
        let mut f = empty_filters();
        f.not_installed = true;
        let out = apply_filters(fixtures(), &f);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|t| !t.installed));
    }

    #[test]
    fn severity_and_tier_compose_as_and() {
        let mut f = empty_filters();
        f.severity = vec!["high".into()];
        f.tier = vec!["deny".into()];
        let out = apply_filters(fixtures(), &f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "phi_egress.rego");
    }

    #[test]
    fn resolve_policy_url_flag_wins() {
        // Flag short-circuits the env + default fallbacks. The
        // env-only path is left untested because Rust 2024's
        // `remove_var`/`set_var` are `unsafe` (process-wide env
        // is shared with every other test).
        let flag = resolve_policy_url(Some("http://flag.example.test"));
        assert_eq!(flag, "http://flag.example.test");
    }
}
