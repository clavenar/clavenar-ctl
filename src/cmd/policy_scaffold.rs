//! `wardenctl policy scaffold` — emit a fresh starter Rego template
//! with frontmatter pre-filled.
//!
//! Pure filesystem work, no policy-engine call. The output is a
//! syntactically-valid `.rego` file that compiles cleanly against
//! the warden.authz package; operators tighten the gated tool set
//! and rule body in-place before installing.
//!
//! Frontmatter shape matches the seeder's parser in
//! `warden-policy-engine/src/frontmatter.rs` — Domain / Severity /
//! Frameworks / Tags / Tier / Tool surface / Summary, all keyed off
//! the same column-aligned header convention the bundled templates
//! use.

use std::path::PathBuf;

use clap::Args;

use crate::ExitCode;

#[derive(Debug, Args)]
pub(crate) struct ScaffoldArgs {
    /// Template name (filename slug without `.rego`).
    #[arg(long)]
    pub name: String,
    /// Domain slug: healthcare, finance, telecom, …. Matches the
    /// `Domain:` frontmatter field the engine catalog filters on.
    #[arg(long)]
    pub domain: String,
    /// Default verdict tier the rule emits.
    #[arg(long, value_parser = ["deny", "review", "mixed"])]
    pub tier: String,
    /// Risk severity. Drives the catalog UI's color coding.
    #[arg(long, value_parser = ["low", "medium", "high", "critical"])]
    pub severity: String,
    /// Comma-separated compliance frameworks (e.g. `HIPAA,SOC2`).
    #[arg(long, default_value = "")]
    pub frameworks: String,
    /// Comma-separated keyword tags (e.g. `pii,egress`).
    #[arg(long, default_value = "")]
    pub tags: String,
    /// Comma-separated MCP tool names the rule gates on. These
    /// become the body of the named tool set + populate the
    /// `Tool surface:` frontmatter field. At least one required.
    #[arg(long = "tool-surface", default_value = "")]
    pub tool_surface: String,
    /// One-line summary. Appears as the card subtitle in the
    /// console's `/policies/library` view.
    #[arg(long, default_value = "")]
    pub summary: String,
    /// Output path. Defaults to `policies/templates/<name>.rego`
    /// relative to the current working directory.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Overwrite an existing file at the output path.
    #[arg(long)]
    pub force: bool,
    /// Print the body to stdout instead of writing a file.
    #[arg(long)]
    pub stdout: bool,
}

pub(crate) fn run(args: ScaffoldArgs) -> ExitCode {
    let tools: Vec<String> = split_csv(&args.tool_surface);
    if tools.is_empty() {
        eprintln!("error: --tool-surface must list at least one MCP tool name.");
        return ExitCode::Validation;
    }
    if !is_safe_slug(&args.name) {
        eprintln!(
            "error: --name must be lower-case alphanumeric + underscore (got {:?}).",
            args.name
        );
        return ExitCode::Validation;
    }

    let body = render_template(&args, &tools);

    if args.stdout {
        print!("{}", body);
        return ExitCode::Ok;
    }

    let path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("policies/templates/{}.rego", args.name)));

    if path.exists() && !args.force {
        eprintln!(
            "error: {} already exists. Pass --force to overwrite, or pick a different --name.",
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
    if let Err(e) = std::fs::write(&path, &body) {
        eprintln!("error: write {}: {}", path.display(), e);
        return ExitCode::Server;
    }
    eprintln!("wrote {} ({} lines)", path.display(), body.lines().count());
    ExitCode::Ok
}

fn render_template(args: &ScaffoldArgs, tools: &[String]) -> String {
    let frameworks = split_csv(&args.frameworks);
    let tags = split_csv(&args.tags);

    let summary = if args.summary.is_empty() {
        format!("Starter policy for {} domain.", args.domain)
    } else {
        args.summary.clone()
    };

    let mut out = String::new();
    // Column-aligned frontmatter — 16-char key column matches the
    // bundled templates so a future linter can enforce one shape.
    out.push_str(&format!("# Template:     {}\n", args.name));
    out.push_str(&format!("# Domain:       {}\n", args.domain));
    out.push_str(&format!("# Severity:     {}\n", args.severity));
    out.push_str(&format!("# Frameworks:   {}\n", frameworks.join(", ")));
    out.push_str(&format!("# Tags:         {}\n", tags.join(", ")));
    out.push_str(&format!("# Tier:         {}\n", args.tier));
    out.push_str(&format!("# Tool surface: {}\n", tools.join(", ")));
    out.push_str(&format!("# Summary:      {}\n", summary));
    out.push_str("# Purpose:      TODO — describe the rule's intent in one or two lines.\n");
    out.push_str("# Inputs:       input.tool_type\n");
    out.push_str("# Edit:         The named tool set below is the load-bearing knob — tighten\n");
    out.push_str("#               the list to match the tools your agent stack exposes.\n");
    out.push('\n');
    out.push_str("package warden.authz\n\n");
    out.push_str("import rego.v1\n\n");

    // Single shared tool set keeps the starter compact. The
    // `mixed` tier still uses it — both deny and review fire on
    // the same tool, which is rarely what you want long-term, but
    // it forces operators to read the file and split into separate
    // sets before deploying.
    out.push_str("gated_tools := {\n");
    for t in tools {
        out.push_str(&format!("\t\"{}\",\n", t));
    }
    out.push_str("}\n\n");

    if args.tier == "deny" || args.tier == "mixed" {
        out.push_str(&format!(
            "deny contains msg if {{\n\
             \tsome t in gated_tools\n\
             \tinput.tool_type == t\n\
             \tmsg := sprintf(\n\
             \t\t\"Violation: \\\"%s\\\" is denied by {}.\",\n\
             \t\t[input.tool_type],\n\
             \t)\n\
             }}\n\n",
            args.name
        ));
    }
    if args.tier == "review" || args.tier == "mixed" {
        out.push_str(&format!(
            "review contains msg if {{\n\
             \tsome t in gated_tools\n\
             \tinput.tool_type == t\n\
             \tmsg := sprintf(\n\
             \t\t\"Review: \\\"%s\\\" requires operator approval per {}.\",\n\
             \t\t[input.tool_type],\n\
             \t)\n\
             }}\n",
            args.name
        ));
    }

    out
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// `lower_alpha + underscore + digits`. Refuses anything that would
/// produce a confusing filename (`/`, `\`, `..`, spaces, etc.); same
/// posture as the engine's path-traversal rejection in
/// `library::read_template`.
fn is_safe_slug(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(tier: &str) -> ScaffoldArgs {
        ScaffoldArgs {
            name: "phi_egress_starter".into(),
            domain: "healthcare".into(),
            tier: tier.into(),
            severity: "high".into(),
            frameworks: "HIPAA,HITRUST".into(),
            tags: "phi,egress".into(),
            tool_surface: "phi_export,send_email".into(),
            summary: "Deny PHI exports.".into(),
            output: None,
            force: false,
            stdout: false,
        }
    }

    #[test]
    fn output_carries_full_frontmatter_block() {
        let a = args("deny");
        let body = render_template(&a, &split_csv(&a.tool_surface));
        assert!(body.contains("# Template:     phi_egress_starter"));
        assert!(body.contains("# Domain:       healthcare"));
        assert!(body.contains("# Severity:     high"));
        assert!(body.contains("# Frameworks:   HIPAA, HITRUST"));
        assert!(body.contains("# Tags:         phi, egress"));
        assert!(body.contains("# Tier:         deny"));
        assert!(body.contains("# Tool surface: phi_export, send_email"));
        assert!(body.contains("# Summary:      Deny PHI exports."));
    }

    #[test]
    fn deny_tier_emits_only_deny_block() {
        let a = args("deny");
        let body = render_template(&a, &split_csv(&a.tool_surface));
        assert!(body.contains("deny contains msg if"));
        assert!(!body.contains("review contains msg if"));
    }

    #[test]
    fn review_tier_emits_only_review_block() {
        let a = args("review");
        let body = render_template(&a, &split_csv(&a.tool_surface));
        assert!(!body.contains("deny contains msg if"));
        assert!(body.contains("review contains msg if"));
    }

    #[test]
    fn mixed_tier_emits_both_blocks() {
        let a = args("mixed");
        let body = render_template(&a, &split_csv(&a.tool_surface));
        assert!(body.contains("deny contains msg if"));
        assert!(body.contains("review contains msg if"));
    }

    #[test]
    fn missing_tool_surface_returns_validation_error() {
        let mut a = args("deny");
        a.tool_surface.clear();
        a.stdout = true;
        let code = run(a);
        assert_eq!(code, ExitCode::Validation);
    }

    #[test]
    fn unsafe_slug_returns_validation_error() {
        let mut a = args("deny");
        a.name = "phi/../etc".into();
        a.stdout = true;
        let code = run(a);
        assert_eq!(code, ExitCode::Validation);
    }

    #[test]
    fn writes_file_at_explicit_output_path() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("custom.rego");
        let mut a = args("mixed");
        a.output = Some(out.clone());
        let code = run(a);
        assert_eq!(code, ExitCode::Ok);
        let body = std::fs::read_to_string(&out).unwrap();
        assert!(body.contains("phi_egress_starter"));
        assert!(body.contains("gated_tools"));
    }

    #[test]
    fn refuses_to_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("custom.rego");
        std::fs::write(&out, "pre-existing").unwrap();
        let mut a = args("deny");
        a.output = Some(out.clone());
        let code = run(a);
        assert_eq!(code, ExitCode::Conflict);
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "pre-existing");
    }

    #[test]
    fn force_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("custom.rego");
        std::fs::write(&out, "pre-existing").unwrap();
        let mut a = args("deny");
        a.output = Some(out.clone());
        a.force = true;
        let code = run(a);
        assert_eq!(code, ExitCode::Ok);
        let body = std::fs::read_to_string(&out).unwrap();
        assert!(body.contains("phi_egress_starter"));
        assert!(!body.contains("pre-existing"));
    }

    #[test]
    fn default_output_path_under_policies_templates() {
        // We can't easily test the default path in run() without
        // chdir'ing the test (which is process-wide), so we only
        // verify the value resolves correctly.
        let a = args("deny");
        let default = a
            .output
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("policies/templates/{}.rego", a.name)));
        assert_eq!(
            default,
            PathBuf::from("policies/templates/phi_egress_starter.rego")
        );
    }
}
