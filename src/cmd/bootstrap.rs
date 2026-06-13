//! `clavenarctl agents bootstrap` — guided first-agent wizard for
//! greenfield operators.
//!
//! Walks an interactive operator through tenant / name / owner-team /
//! envelope-template / description, shows a summary, and registers the
//! agent (idempotent register-if-absent, so re-running is safe). It is a
//! convenience front-end over `agents create`; the same flags-driven
//! path stays available for scripts and CI. Refuses to run on a
//! non-interactive stdin (points the caller at `agents create`).

use std::io::{self, IsTerminal, Write};

use clap::Args;
use clavenar_sdk::{create_request_matches, CreateAgentRequest};

use crate::cmd::agents::build_client;
use crate::config;
use crate::ExitCode;

#[derive(Debug, Args)]
pub(crate) struct BootstrapArgs {
    /// Pre-seed the tenant (otherwise the wizard prompts, defaulting to
    /// `CLAVENAR_TENANT` / the config's `default_tenant`).
    #[arg(long)]
    pub tenant: Option<String>,
}

/// Named capability-envelope starting points the wizard offers. Returns
/// `(scope_envelope, yellow_envelope)`. Generic prefixes the operator
/// narrows/widens later via `agents envelope`; `minimal` is the
/// spec-safe default (no /grant-able scope until a human widens).
fn envelope_for_template(name: &str) -> Option<(Vec<String>, Vec<String>)> {
    match name {
        "minimal" => Some((vec![], vec![])),
        "read-only" => Some((vec!["mcp:read".to_string()], vec![])),
        "read-write" => Some((
            vec!["mcp:read".to_string(), "mcp:write".to_string()],
            vec!["mcp:write".to_string()],
        )),
        _ => None,
    }
}

const TEMPLATES: &[&str] = &["minimal", "read-only", "read-write", "custom"];

/// Split a comma/space-separated scope list into trimmed, non-empty,
/// deduped (first-seen order) tokens.
fn parse_scope_list(input: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for tok in input.split([',', ' ', '\t']).map(str::trim).filter(|t| !t.is_empty()) {
        if seen.insert(tok.to_string()) {
            out.push(tok.to_string());
        }
    }
    out
}

/// Read a line; return the trimmed value, or `default` when the operator
/// just hits enter.
fn prompt(label: &str, default: Option<&str>) -> io::Result<String> {
    match default {
        Some(d) => print!("{label} [{d}]: "),
        None => print!("{label}: "),
    }
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let val = buf.trim().to_string();
    Ok(if val.is_empty() {
        default.unwrap_or("").to_string()
    } else {
        val
    })
}

/// Prompt until a non-empty value is entered.
fn prompt_required(label: &str) -> io::Result<String> {
    loop {
        let v = prompt(label, None)?;
        if !v.is_empty() {
            return Ok(v);
        }
        eprintln!("  (required)");
    }
}

pub(crate) async fn run(args: BootstrapArgs, cfg: &config::Config, url: &str) -> ExitCode {
    if !io::stdin().is_terminal() {
        eprintln!(
            "error: `agents bootstrap` is interactive and needs a terminal.\n\
             For scripts/CI use: clavenarctl agents create --tenant <T> --name <N> \
             --owner-team <T> [--scope …]"
        );
        return ExitCode::Validation;
    }

    let default_tenant = config::resolve_tenant(args.tenant.clone(), cfg).ok();

    println!("clavenar agent bootstrap — register your first agent.\n");
    let result: io::Result<_> = (|| {
        let tenant = match default_tenant.as_deref() {
            Some(d) => prompt("Tenant", Some(d))?,
            None => prompt_required("Tenant")?,
        };
        let name = prompt_required("Agent name")?;
        let owner_team = prompt_required("Owner team")?;
        let template = loop {
            let t = prompt(
                "Envelope template (minimal/read-only/read-write/custom)",
                Some("minimal"),
            )?;
            if TEMPLATES.contains(&t.as_str()) {
                break t;
            }
            eprintln!("  (choose one of: {})", TEMPLATES.join(", "));
        };
        let (scope, yellow) = if template == "custom" {
            let scope = parse_scope_list(&prompt("Scopes (comma-separated, blank = none)", Some(""))?);
            let yellow =
                parse_scope_list(&prompt("Yellow-tier scopes (comma-separated, blank = none)", Some(""))?);
            (scope, yellow)
        } else {
            envelope_for_template(&template).expect("validated template")
        };
        let description = {
            let d = prompt("Description (optional)", Some(""))?;
            if d.is_empty() { None } else { Some(d) }
        };
        Ok((tenant, name, owner_team, scope, yellow, description))
    })();

    let (tenant, name, owner_team, scope, yellow, description) = match result {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: read input: {e}");
            return ExitCode::Validation;
        }
    };

    println!("\nAbout to register:");
    println!("  tenant:      {tenant}");
    println!("  agent_name:  {name}");
    println!("  owner_team:  {owner_team}");
    println!("  scopes:      [{}]", scope.join(", "));
    println!("  yellow:      [{}]", yellow.join(", "));
    if let Some(d) = &description {
        println!("  description: {d}");
    }
    let confirm = match prompt("\nCreate this agent? (y/N)", Some("N")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: read input: {e}");
            return ExitCode::Validation;
        }
    };
    if !matches!(confirm.to_ascii_lowercase().as_str(), "y" | "yes") {
        println!("aborted — nothing was created.");
        return ExitCode::Ok;
    }

    let client = match build_client(url, &tenant) {
        Ok(c) => c,
        Err(c) => return c,
    };
    let req = CreateAgentRequest {
        tenant: tenant.as_str(),
        agent_name: name.as_str(),
        owner_team: owner_team.as_str(),
        scope_envelope: scope.clone(),
        yellow_envelope: yellow.clone(),
        attestation_kinds: vec![],
        description: description.as_deref(),
        actor_sub: None,
    };

    // Idempotent: a re-run that exactly matches is a no-op success;
    // a drift is surfaced rather than silently rewritten.
    match client.find_by_name(&tenant, &name).await {
        Ok(Some(existing)) => {
            if create_request_matches(&req, &existing) {
                println!("agent '{name}' already registered (id {}) — nothing to do.", existing.id);
                return ExitCode::Ok;
            }
            eprintln!(
                "error: agent '{name}' already exists with a different envelope/owner_team; \
                 reconcile with `agents envelope` / `agents get {}`",
                existing.id
            );
            return ExitCode::Conflict;
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("error: pre-check failed: {e}");
            return ExitCode::from_clavenar_error(&e);
        }
    }

    match client.create(&req).await {
        Ok(created) => {
            println!(
                "\n✓ registered '{}' (id {}, state {})",
                created.record.agent_name,
                created.record.id,
                created.record.state.as_wire()
            );
            println!("  spiffe_id_pattern: {}", created.spiffe_id_pattern);
            println!(
                "\nNext: mint an SVID for an instance, or widen scope with\n  \
                 clavenarctl agents envelope widen {} --tenant {} --scope …",
                created.record.id, tenant
            );
            ExitCode::Ok
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from_clavenar_error(&e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_envelopes_are_well_formed() {
        assert_eq!(envelope_for_template("minimal"), Some((vec![], vec![])));
        let (scope, yellow) = envelope_for_template("read-write").unwrap();
        assert!(scope.contains(&"mcp:read".to_string()));
        assert!(scope.contains(&"mcp:write".to_string()));
        assert_eq!(yellow, vec!["mcp:write".to_string()]);
        assert!(envelope_for_template("bogus").is_none());
    }

    #[test]
    fn scope_list_splits_dedups_and_trims() {
        assert_eq!(
            parse_scope_list("mcp:read, mcp:write  mcp:read"),
            vec!["mcp:read".to_string(), "mcp:write".to_string()]
        );
        assert!(parse_scope_list("   ").is_empty());
    }
}
