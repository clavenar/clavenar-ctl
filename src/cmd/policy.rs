//! `clavenarctl generate-policy` — emit a Rego template from the
//! clavenar-policy-engine starter pack. Templates are embedded at
//! compile time via `include_str!` against the sibling repo, so the
//! shipped binary carries the rules without an FS dependency.
//!
//! `clavenarctl generate-policy list` shows what's available;
//! `clavenarctl generate-policy <name>` writes to stdout by default
//! (so operators can pipe into a file), or to `--output FILE` when
//! pinning into a policy directory.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::ExitCode;

/// `(name, one-line summary, body)`. Public so `cmd::init` can write
/// the full set into a scaffolded `policies/templates/` directory
/// without duplicating the table.
pub(crate) const TEMPLATES: &[(&str, &str, &str)] = &[
    (
        "pii_egress",
        "Deny PII-carrying egress tools (send_email, http_post, upload_file, webhook_send).",
        include_str!(
            "../../../clavenar-policy-engine/policies/templates/cross-cutting/pii_egress.rego"
        ),
    ),
    (
        "prod_db_writes",
        "Deny write-shaped database tools against production.",
        include_str!(
            "../../../clavenar-policy-engine/policies/templates/cross-cutting/prod_db_writes.rego"
        ),
    ),
    (
        "money_moves",
        "Review small transfers, deny bulk-money tool variants.",
        include_str!("../../../clavenar-policy-engine/policies/templates/finance/money_moves.rego"),
    ),
    (
        "agent_impersonation",
        "Deny identity-modifying tools without attestation.",
        include_str!(
            "../../../clavenar-policy-engine/policies/templates/cross-cutting/agent_impersonation.rego"
        ),
    ),
    (
        "prompt_injection",
        "Hard-deny when Brain reports high intent_score, regardless of tool.",
        include_str!(
            "../../../clavenar-policy-engine/policies/templates/cross-cutting/prompt_injection.rego"
        ),
    ),
    (
        "off_hours_actions",
        "Review high-impact tools outside business hours (Mon-Fri 09-17 UTC).",
        include_str!(
            "../../../clavenar-policy-engine/policies/templates/cross-cutting/off_hours_actions.rego"
        ),
    ),
    (
        "rate_limit_review",
        "Softer rate-limit threshold that parks for review before hard-denying.",
        include_str!(
            "../../../clavenar-policy-engine/policies/templates/cross-cutting/rate_limit_review.rego"
        ),
    ),
];

#[derive(Debug, Args)]
pub(crate) struct PolicyArgs {
    #[command(subcommand)]
    pub action: PolicyAction,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PolicyAction {
    /// List every available template and its one-line summary.
    List {
        /// JSON output (`[{name, summary}, …]`) for scripting.
        #[arg(long)]
        json: bool,
    },
    /// Emit the named template. Defaults to stdout; `--output PATH`
    /// writes to a file.
    Generate {
        /// Template name (e.g. `pii_egress`). Run `clavenarctl
        /// generate-policy list` to see the available set.
        name: String,
        /// Destination file. Omit to print to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Overwrite an existing output file. Default is non-destructive.
        #[arg(long)]
        force: bool,
    },
}

pub(crate) async fn run(args: PolicyArgs) -> ExitCode {
    match args.action {
        PolicyAction::List { json } => list(json),
        PolicyAction::Generate {
            name,
            output,
            force,
        } => generate(&name, output, force),
    }
}

fn list(json: bool) -> ExitCode {
    if json {
        let rows: Vec<serde_json::Value> = TEMPLATES
            .iter()
            .map(|(n, s, _)| serde_json::json!({ "name": n, "summary": s }))
            .collect();
        match serde_json::to_string_pretty(&rows) {
            Ok(s) => {
                println!("{}", s);
                ExitCode::Ok
            }
            Err(e) => {
                eprintln!("error: serialize list: {}", e);
                ExitCode::Server
            }
        }
    } else {
        println!("{:<22} SUMMARY", "NAME");
        for (name, summary, _) in TEMPLATES {
            println!("{:<22} {}", name, summary);
        }
        ExitCode::Ok
    }
}

fn generate(name: &str, output: Option<PathBuf>, force: bool) -> ExitCode {
    let body = match TEMPLATES.iter().find(|(n, _, _)| *n == name) {
        Some((_, _, b)) => *b,
        None => {
            eprintln!(
                "error: unknown template {:?}. Run `clavenarctl generate-policy list`.",
                name
            );
            return ExitCode::Validation;
        }
    };
    match output {
        None => {
            print!("{}", body);
            ExitCode::Ok
        }
        Some(path) => {
            if path.exists() && !force {
                eprintln!(
                    "error: {} already exists. Pass --force to overwrite.",
                    path.display()
                );
                return ExitCode::Conflict;
            }
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                eprintln!("error: create {}: {}", parent.display(), e);
                return ExitCode::Server;
            }
            if let Err(e) = std::fs::write(&path, body) {
                eprintln!("error: write {}: {}", path.display(), e);
                return ExitCode::Server;
            }
            eprintln!("wrote {}", path.display());
            ExitCode::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_is_resolvable_by_name() {
        for (name, _summary, body) in TEMPLATES {
            assert!(!body.is_empty(), "template {} is empty", name);
            assert!(
                body.contains("package clavenar.authz"),
                "template {} missing package declaration",
                name
            );
        }
    }

    #[test]
    fn template_set_size_matches_starter_pack() {
        // Pinned at 7 — matches the policy starter pack documented in
        // the policy-engine README. A drift here means a template
        // was added or removed; update both surfaces in lock-step.
        assert_eq!(TEMPLATES.len(), 7);
    }

    #[test]
    fn generate_unknown_template_is_validation_error() {
        let exit = generate("not_a_real_template", None, false);
        assert_eq!(exit, ExitCode::Validation);
    }

    #[test]
    fn generate_writes_file_when_output_set() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("pii.rego");
        let exit = generate("pii_egress", Some(out.clone()), false);
        assert_eq!(exit, ExitCode::Ok);
        let body = std::fs::read_to_string(&out).unwrap();
        assert!(body.contains("egress_tool_types"));
    }

    #[test]
    fn generate_refuses_to_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("pii.rego");
        std::fs::write(&out, "pre-existing").unwrap();
        let exit = generate("pii_egress", Some(out.clone()), false);
        assert_eq!(exit, ExitCode::Conflict);
        // File is untouched.
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "pre-existing");
    }

    #[test]
    fn generate_overwrites_when_force() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("pii.rego");
        std::fs::write(&out, "pre-existing").unwrap();
        let exit = generate("pii_egress", Some(out.clone()), true);
        assert_eq!(exit, ExitCode::Ok);
        let body = std::fs::read_to_string(&out).unwrap();
        assert!(body.contains("egress_tool_types"));
    }
}
