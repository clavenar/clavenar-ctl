//! `config.toml` — operator-level CLI defaults.
//!
//! Optional file at the OS-correct config dir (`directories` crate
//! resolves it: `~/.config/clavenar/config.toml` on Linux,
//! `~/Library/Application Support/dev.agent-clavenar.clavenar/config.toml`
//! on macOS, `%APPDATA%\agent-clavenar\clavenar\config\config.toml` on
//! Windows). Carries a default identity URL and tenant so `clavenarctl
//! agents list` doesn't need to repeat them on every call. Per-call
//! CLI flags and env vars override the file.
//!
//! This is *not* a place for sensitive data — bearer tokens live in the
//! companion [`crate::credentials`] file, which is `0600` on Unix.
//! `config.toml` can be group-readable.
//!
//! Resolution order for `identity_url` and `default_tenant` (highest
//! priority first):
//!
//! 1. Per-call `--identity-url` / `--tenant` flag.
//! 2. `CLAVENAR_IDENTITY_URL` / `CLAVENAR_TENANT` env var.
//! 3. `config.toml`.
//! 4. Built-in default (`identity_url` only — `http://localhost:8086`).
//! 5. Boot failure (no `default_tenant` and none on the call site).

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::ExitCode;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct Config {
    /// Identity service base URL. Defaults to
    /// `http://localhost:8086` if unset everywhere.
    pub identity_url: Option<String>,
    /// Default tenant for `--tenant`-taking commands. The CLI prefers
    /// to fail loudly on missing tenant rather than silently picking
    /// one — this entry is opt-in.
    pub default_tenant: Option<String>,
}

/// Resolve the on-disk config-file path. Idempotent — does NOT touch
/// the filesystem (creation is the caller's job, on save).
pub(crate) fn config_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("dev", "agent-clavenar", "clavenar")
        .context("could not resolve OS config dir for clavenar")?;
    Ok(dirs.config_dir().join("config.toml"))
}

/// Load the config file, returning [`Config::default`] if it doesn't
/// exist. A malformed file errors loudly (we'd rather surface the
/// operator's typo than silently fall through to defaults).
pub(crate) fn load() -> Result<Config> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(Config::default());
    }
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    let cfg: Config = toml::from_str(&body)
        .with_context(|| format!("parse {}", path.display()))?;
    Ok(cfg)
}

/// Resolve the identity URL using the spec'd precedence chain.
/// `cli_override` is the per-call `--identity-url` flag; `env_override`
/// is the captured `CLAVENAR_IDENTITY_URL` value.
pub(crate) fn resolve_identity_url(
    cli_override: Option<&str>,
    env_override: Option<&str>,
    cfg: &Config,
) -> String {
    cli_override
        .map(str::to_string)
        .or_else(|| env_override.map(str::to_string))
        .or_else(|| cfg.identity_url.clone())
        .unwrap_or_else(|| "http://localhost:8086".to_string())
}

/// Resolve `--tenant` against the precedence chain: flag → env →
/// config file's `default_tenant`. Returns `Validation` on missing
/// after emitting the operator-actionable error message — keeps the
/// "where's tenant supposed to come from?" hint in one place.
pub(crate) fn resolve_tenant(arg: Option<String>, cfg: &Config) -> Result<String, ExitCode> {
    arg.or_else(|| std::env::var("CLAVENAR_TENANT").ok())
        .or_else(|| cfg.default_tenant.clone())
        .ok_or_else(|| {
            eprintln!(
                "error: --tenant required (or set CLAVENAR_TENANT or default_tenant in config.toml)"
            );
            ExitCode::Validation
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(url: Option<&str>) -> Config {
        Config {
            identity_url: url.map(str::to_string),
            default_tenant: None,
        }
    }

    #[test]
    fn cli_override_wins_over_env_and_file() {
        let cfg = cfg_with(Some("http://from-file:8086"));
        assert_eq!(
            resolve_identity_url(
                Some("http://from-cli:9999"),
                Some("http://from-env:7777"),
                &cfg
            ),
            "http://from-cli:9999"
        );
    }

    #[test]
    fn env_override_wins_over_file() {
        let cfg = cfg_with(Some("http://from-file:8086"));
        assert_eq!(
            resolve_identity_url(None, Some("http://from-env:7777"), &cfg),
            "http://from-env:7777"
        );
    }

    #[test]
    fn file_used_when_no_cli_or_env() {
        let cfg = cfg_with(Some("http://from-file:8086"));
        assert_eq!(
            resolve_identity_url(None, None, &cfg),
            "http://from-file:8086"
        );
    }

    #[test]
    fn falls_back_to_localhost_default() {
        let cfg = cfg_with(None);
        assert_eq!(
            resolve_identity_url(None, None, &cfg),
            "http://localhost:8086"
        );
    }

    #[test]
    fn resolve_tenant_uses_config_default() {
        let cfg = Config {
            identity_url: None,
            default_tenant: Some("acme".into()),
        };
        let prev = std::env::var("CLAVENAR_TENANT").ok();
        unsafe {
            std::env::remove_var("CLAVENAR_TENANT");
        }
        let resolved = resolve_tenant(None, &cfg).unwrap();
        assert_eq!(resolved, "acme");
        unsafe {
            if let Some(v) = prev {
                std::env::set_var("CLAVENAR_TENANT", v);
            }
        }
    }

    #[test]
    fn resolve_tenant_flag_wins() {
        let cfg = Config {
            identity_url: None,
            default_tenant: Some("acme".into()),
        };
        let resolved = resolve_tenant(Some("globex".into()), &cfg).unwrap();
        assert_eq!(resolved, "globex");
    }

    #[test]
    fn parses_complete_toml() {
        let s = r#"
            identity_url = "http://identity.test:8086"
            default_tenant = "acme"
        "#;
        let cfg: Config = toml::from_str(s).unwrap();
        assert_eq!(cfg.identity_url.as_deref(), Some("http://identity.test:8086"));
        assert_eq!(cfg.default_tenant.as_deref(), Some("acme"));
    }
}
