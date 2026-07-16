//! CLI integration smokes covering the three subcommand families
//! operators hit first day-of: `doctor`, `auth`, and the top-level
//! `--help`. Uses `assert_cmd` (already declared as a dev-dep) to
//! spawn the `clavenarctl` binary as cargo built it.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// `clavenarctl doctor --only-configured --json` skips every probe (no
/// URL overrides → falls through the `--only-configured` gate) and
/// emits a JSON array. Exit code 0 because nothing went `down`.
#[test]
fn doctor_with_only_configured_emits_skipped_json_and_exits_zero() {
    let assert = Command::cargo_bin("clavenarctl")
        .unwrap()
        .args(["doctor", "--only-configured", "--json"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .assert()
        .success();
    let output = assert.get_output();
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stdout).expect("doctor --json parses");
    let arr = parsed.as_array().expect("doctor --json returns an array");
    assert!(!arr.is_empty(), "doctor must probe at least one service");
    for entry in arr {
        let status = entry["status"].as_str().unwrap();
        assert!(
            status == "skipped" || status == "up" || status == "down",
            "unexpected doctor status {status}"
        );
    }
}

/// `clavenarctl auth whoami` with no cached creds must exit non-zero and
/// print an actionable "run clavenarctl auth login" hint to stderr.
/// `CLAVENAR_CREDENTIALS_PATH` points at a non-existent file so the test
/// can't accidentally pick up the developer's real cred bag.
#[test]
fn auth_whoami_without_credentials_exits_nonzero_with_login_hint() {
    let tmp = TempDir::new().unwrap();
    let cred_path = tmp.path().join("does-not-exist.json");
    Command::cargo_bin("clavenarctl")
        .unwrap()
        .args(["auth", "whoami", "--tenant", "no-such-tenant"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("CLAVENAR_CREDENTIALS_PATH", &cred_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no cached credentials"))
        .stderr(predicate::str::contains("clavenarctl auth login"));
}

/// `clavenarctl --help` lists every subcommand the binary advertises.
/// Catches a `clap::Subcommand` derive going missing — a regression
/// that would otherwise silently strip a command from the operator's
/// surface.
#[test]
fn top_level_help_lists_every_subcommand() {
    let assert = Command::cargo_bin("clavenarctl")
        .unwrap()
        .arg("--help")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    for sub in [
        "init",
        "doctor",
        "generate-policy",
        "auth",
        "agents",
        "regulatory",
        "assurance",
    ] {
        assert!(
            stdout.contains(sub),
            "--help missing subcommand `{sub}`:\n{stdout}"
        );
    }
}
