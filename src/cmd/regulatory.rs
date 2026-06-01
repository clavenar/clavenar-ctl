//! `clavenarctl regulatory export` — operator-side regulatory bundle
//! export.
//!
//! Wraps the SDK's `LedgerClient::regulatory_export` with file IO + a
//! human-friendly progress story:
//!
//! ```text
//! clavenarctl regulatory export
//!     --from <RFC3339> --to <RFC3339>
//!     [--readme path/to/file.md]
//!     [--include-exports]
//!     [--ledger-url <URL>]
//!     --output bundle.tar.gz
//! ```
//!
//! Exit codes follow spec §9.3 via [`crate::ExitCode::from_clavenar_error`].
//! Local file IO failures (readme read, output write) collapse to
//! `Validation` (path / permission) or `Server` (e.g. disk full).
//!
//! ## Why a separate top-level verb (`regulatory`)?
//!
//! Bundling under `clavenarctl agents` would conflate "operate on the
//! agent registry" with "produce an EU-AI-Act artefact." Different
//! audiences (compliance officer vs. agent-platform owner), different
//! auth (this surface doesn't talk to identity at all today — the
//! ledger doesn't gate `/export/regulatory`), different exit
//! semantics. Keeping it separate also leaves room for follow-up
//! verbs (`regulatory verify`, `regulatory validate-bundle`) without
//! polluting the agents tree.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
use clavenar_sdk::{LedgerClient, RegulatoryExportOptions};

use crate::ExitCode;

#[derive(Debug, Args)]
pub(crate) struct RegulatoryArgs {
    #[command(subcommand)]
    pub command: RegulatoryCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RegulatoryCommand {
    /// Build a regulatory `.tar.gz` for the time window `[from, to)`.
    Export(ExportArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ExportArgs {
    /// Lower window bound, inclusive. RFC 3339, e.g.
    /// `2026-04-01T00:00:00Z`.
    #[arg(long)]
    pub from: String,

    /// Upper window bound, exclusive. RFC 3339.
    #[arg(long)]
    pub to: String,

    /// Path to operator-supplied technical-documentation prose
    /// (markdown). Embedded as `technical_documentation.md` inside
    /// the bundle. The ledger commits to its sha256 + size in the
    /// manifest. Capped at 1 MiB.
    #[arg(long)]
    pub readme: Option<PathBuf>,

    /// When set, the ledger scans its `exports` table and embeds
    /// Parquet pointers whose seq range overlaps the regulatory
    /// window into `manifest.parquet_pointers`.
    #[arg(long)]
    pub include_exports: bool,

    /// Override the ledger base URL. Falls back to
    /// `CLAVENAR_LEDGER_URL` env, then `http://localhost:8083`.
    /// Distinct from `--identity-url` (the latter targets the
    /// identity service, which this command does not call).
    #[arg(long)]
    pub ledger_url: Option<String>,

    /// Where to write the resulting `.tar.gz`. Use `-` to write to
    /// stdout (handy for piping into `tar -tz` for a quick listing
    /// without leaving a file on disk).
    #[arg(long)]
    pub output: PathBuf,
}

pub(crate) async fn run(args: RegulatoryArgs) -> ExitCode {
    match args.command {
        RegulatoryCommand::Export(a) => export(a).await,
    }
}

async fn export(args: ExportArgs) -> ExitCode {
    // Parse window bounds first so a typo costs no network round-trip.
    let from = match DateTime::parse_from_rfc3339(&args.from) {
        Ok(t) => t.with_timezone(&Utc),
        Err(e) => {
            eprintln!("error: --from must be RFC 3339: {e}");
            return ExitCode::Validation;
        }
    };
    let to = match DateTime::parse_from_rfc3339(&args.to) {
        Ok(t) => t.with_timezone(&Utc),
        Err(e) => {
            eprintln!("error: --to must be RFC 3339: {e}");
            return ExitCode::Validation;
        }
    };
    if from >= to {
        eprintln!("error: --from must be strictly less than --to");
        return ExitCode::Validation;
    }

    // Slurp readme if requested. We hold it in memory; the SDK does
    // the same and the ledger caps at 1 MiB anyway.
    let readme = match args.readme.as_ref() {
        Some(path) => match std::fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                eprintln!("error: read --readme {}: {e}", path.display());
                return ExitCode::Validation;
            }
        },
        None => None,
    };

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

    let opts = RegulatoryExportOptions {
        readme,
        include_exports: args.include_exports,
    };
    let bytes = match client.regulatory_export(&from, &to, opts).await {
        Ok(b) => b,
        Err(e) => {
            // Surface the body for 4xx — the ledger's error messages
            // are operator-actionable ("readme too big",
            // "from must be < to").
            if let clavenar_sdk::ClavenarError::Server { status, body } = &e {
                eprintln!("error: ledger {status}: {body}");
            } else {
                eprintln!("error: regulatory export: {e}");
            }
            return ExitCode::from_clavenar_error(&e);
        }
    };

    // Stdout sentinel — useful for `clavenarctl … --output - | tar -tz`
    // type pipelines without leaving a file on disk. Otherwise write
    // to the named path.
    if args.output.as_os_str() == "-" {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        if let Err(e) = handle.write_all(&bytes) {
            eprintln!("error: write stdout: {e}");
            return ExitCode::Server;
        }
    } else if let Err(e) = std::fs::write(&args.output, &bytes) {
        eprintln!("error: write {}: {e}", args.output.display());
        return ExitCode::Server;
    } else {
        // Mirror the agents commands' tone: a single-line "what
        // happened" trailer to stderr (so stdout stays clean for
        // bundle bytes when --output is `-`). Bundle size in MiB is
        // a useful at-a-glance — operators eyeball this before
        // emailing a regulator.
        eprintln!(
            "wrote {} ({:.2} MiB)",
            args.output.display(),
            bytes.len() as f64 / 1024.0 / 1024.0,
        );
    }
    ExitCode::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct CliFixture {
        #[command(subcommand)]
        command: TopLevel,
    }

    #[derive(Debug, clap::Subcommand)]
    enum TopLevel {
        Regulatory(RegulatoryArgs),
    }

    #[test]
    fn parses_minimal_export_invocation() {
        // The shape we promise in the spec: --from, --to, --output
        // are mandatory; readme + include-exports are optional.
        let cli = CliFixture::try_parse_from([
            "clavenarctl",
            "regulatory",
            "export",
            "--from",
            "2026-04-01T00:00:00Z",
            "--to",
            "2026-05-01T00:00:00Z",
            "--output",
            "/tmp/bundle.tar.gz",
        ])
        .expect("minimal export must parse");
        match cli.command {
            TopLevel::Regulatory(reg) => match reg.command {
                RegulatoryCommand::Export(args) => {
                    assert_eq!(args.from, "2026-04-01T00:00:00Z");
                    assert_eq!(args.to, "2026-05-01T00:00:00Z");
                    assert!(args.readme.is_none());
                    assert!(!args.include_exports);
                    assert_eq!(args.output, PathBuf::from("/tmp/bundle.tar.gz"));
                }
            },
        }
    }

    #[test]
    fn parses_full_export_invocation_with_readme_and_pointers() {
        let cli = CliFixture::try_parse_from([
            "clavenarctl",
            "regulatory",
            "export",
            "--from",
            "2026-04-01T00:00:00Z",
            "--to",
            "2026-05-01T00:00:00Z",
            "--readme",
            "/tmp/prose.md",
            "--include-exports",
            "--ledger-url",
            "http://ledger.test:8083",
            "--output",
            "/tmp/bundle.tar.gz",
        ])
        .expect("full export must parse");
        match cli.command {
            TopLevel::Regulatory(reg) => match reg.command {
                RegulatoryCommand::Export(args) => {
                    assert_eq!(args.readme, Some(PathBuf::from("/tmp/prose.md")));
                    assert!(args.include_exports);
                    assert_eq!(
                        args.ledger_url.as_deref(),
                        Some("http://ledger.test:8083"),
                    );
                }
            },
        }
    }

    #[test]
    fn rejects_missing_required_args() {
        // --output is required.
        let err = CliFixture::try_parse_from([
            "clavenarctl",
            "regulatory",
            "export",
            "--from",
            "2026-04-01T00:00:00Z",
            "--to",
            "2026-05-01T00:00:00Z",
        ])
        .expect_err("missing --output must error");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }
}
