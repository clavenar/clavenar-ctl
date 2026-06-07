//! `clavenarctl policy {install,uninstall}` — flip a policy's `active`
//! flag by name, or sweep a whole category (`--category <domain>`).
//!
//! "Install" == activate; "uninstall" == deactivate. A single policy
//! reuses the engine's optimistic-concurrency `activate`/`deactivate`
//! (so we read the current version first); a category sweep posts to
//! the batch endpoint, which flips every matching row in one engine
//! rebuild and skips the protected baseline floor.
//!
//! `--policy-url` resolution mirrors `policy library`: flag →
//! `CLAVENAR_POLICY_URL` env → `http://localhost:8082`.

use clap::Args;
use clavenar_sdk::{
    BatchStateChangeRequest, ClavenarError, PoliciesClient, StateChangeRequest,
};

use crate::ExitCode;

#[derive(Debug, Args)]
pub(crate) struct InstallArgs {
    /// Policy name (filename, e.g. `money_moves.rego`). Mutually
    /// exclusive with `--category`.
    pub name: Option<String>,
    /// Install / uninstall every policy in this category (the `domain`
    /// frontmatter value). Mutually exclusive with a name.
    #[arg(long)]
    pub category: Option<String>,
    /// Why this is happening. Persisted on the ledger row(s).
    #[arg(long)]
    pub reason: String,
    /// Actor sub claim. Defaults to `clavenarctl`.
    #[arg(long = "actor-sub", default_value = "clavenarctl")]
    pub actor_sub: String,
    /// Actor identity-provider id. Defaults to `clavenarctl`.
    #[arg(long = "actor-idp", default_value = "clavenarctl")]
    pub actor_idp: String,
    /// Override the policy-engine URL.
    #[arg(long)]
    pub policy_url: Option<String>,
}

/// What the operator targeted — exactly one of a single policy or a
/// whole category.
enum Target {
    Name(String),
    Category(String),
}

/// Resolve the name/category flags into a single [`Target`], rejecting
/// the both-set and neither-set cases.
fn resolve_target(name: Option<String>, category: Option<String>) -> Result<Target, String> {
    match (name, category) {
        (Some(_), Some(_)) => Err("pass either a policy name or --category, not both".into()),
        (None, None) => Err("pass a policy name or --category <domain>".into()),
        (Some(n), None) => Ok(Target::Name(n)),
        (None, Some(c)) => Ok(Target::Category(c)),
    }
}

pub(crate) async fn run(args: InstallArgs, activate: bool) -> ExitCode {
    if args.reason.trim().is_empty() {
        eprintln!("error: --reason must be non-empty.");
        return ExitCode::Validation;
    }
    let target = match resolve_target(args.name.clone(), args.category.clone()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::Validation;
        }
    };
    let policy_url = resolve_policy_url(args.policy_url.as_deref());
    let client = match PoliciesClient::new(&policy_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: policy url {}: {}", policy_url, e);
            return ExitCode::Validation;
        }
    };
    let verb = if activate { "install" } else { "uninstall" };
    match target {
        Target::Name(name) => single(&client, &name, &args, activate, verb).await,
        Target::Category(domain) => category(&client, &domain, &args, activate, verb).await,
    }
}

async fn single(
    client: &PoliciesClient,
    name: &str,
    args: &InstallArgs,
    activate: bool,
    verb: &str,
) -> ExitCode {
    // Read the current version for the optimistic-concurrency token.
    let current = match client.get(name).await {
        Ok(d) => d.policy.current_version,
        Err(ClavenarError::Server { status, .. }) if status.as_u16() == 404 => {
            eprintln!("error: policy {:?} not found", name);
            return ExitCode::Validation;
        }
        Err(e) => {
            eprintln!("error: read {}: {}", name, e);
            return ExitCode::from_clavenar_error(&e);
        }
    };
    let req = StateChangeRequest {
        reason: &args.reason,
        actor_sub: &args.actor_sub,
        actor_idp: &args.actor_idp,
        expected_current_version: current,
    };
    let result = if activate {
        client.activate(name, &req).await
    } else {
        client.deactivate(name, &req).await
    };
    match result {
        Ok(resp) => {
            println!("{}ed {} (v{}, active={})", verb, resp.name, resp.version, resp.active);
            ExitCode::Ok
        }
        Err(ClavenarError::Server { status, body }) if status.as_u16() == 409 => {
            eprintln!("error: cannot {} {:?}: {}", verb, name, body);
            ExitCode::Conflict
        }
        Err(e) => {
            eprintln!("error: {} {}: {}", verb, name, e);
            ExitCode::from_clavenar_error(&e)
        }
    }
}

async fn category(
    client: &PoliciesClient,
    domain: &str,
    args: &InstallArgs,
    activate: bool,
    verb: &str,
) -> ExitCode {
    let req = BatchStateChangeRequest {
        reason: &args.reason,
        actor_sub: &args.actor_sub,
        actor_idp: &args.actor_idp,
    };
    let result = if activate {
        client.activate_category(domain, &req).await
    } else {
        client.deactivate_category(domain, &req).await
    };
    match result {
        Ok(resp) => {
            println!(
                "{}ed category {:?}: {} changed, {} skipped",
                verb, domain, resp.changed, resp.skipped
            );
            ExitCode::Ok
        }
        Err(e) => {
            eprintln!("error: {} category {}: {}", verb, domain, e);
            ExitCode::from_clavenar_error(&e)
        }
    }
}

fn resolve_policy_url(flag: Option<&str>) -> String {
    if let Some(s) = flag {
        return s.to_string();
    }
    if let Ok(env) = std::env::var("CLAVENAR_POLICY_URL") {
        return env;
    }
    "http://localhost:8082".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_target_accepts_name_only() {
        assert!(matches!(
            resolve_target(Some("a.rego".into()), None),
            Ok(Target::Name(n)) if n == "a.rego"
        ));
    }

    #[test]
    fn resolve_target_accepts_category_only() {
        assert!(matches!(
            resolve_target(None, Some("finance".into())),
            Ok(Target::Category(c)) if c == "finance"
        ));
    }

    #[test]
    fn resolve_target_rejects_both() {
        assert!(resolve_target(Some("a.rego".into()), Some("finance".into())).is_err());
    }

    #[test]
    fn resolve_target_rejects_neither() {
        assert!(resolve_target(None, None).is_err());
    }

    #[test]
    fn resolve_policy_url_flag_wins() {
        assert_eq!(
            resolve_policy_url(Some("http://flag.example.test")),
            "http://flag.example.test"
        );
    }
}
