//! `wardenctl auth` — login / logout / whoami.
//!
//! Initial surface: a "manual paste" login that reads a pre-minted
//! `id_token` from a file or stdin and caches it in the OS-correct
//! credentials file (Linux: `~/.config/warden/credentials.json`).
//! The full RFC 8628 device-authorization grant lands later with the
//! dex mock.
//!
//! Why "manual paste" first: the e2e runner (`run-onboarding.sh`)
//! mints id_tokens directly via `dex /token` (password grant) and
//! stuffs the credentials file before invoking other `wardenctl`
//! commands — that's the same path the operator uses today (mint a
//! token via the IdP CLI, paste it in). Device-flow ships when we
//! actually have an IdP that implements RFC 8628.

use clap::{Args, Subcommand};
use std::io::Read;

use crate::credentials::{self, TenantCredential};
use crate::ExitCode;

#[derive(Debug, Args)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Cache an OIDC id_token for a tenant.
    Login(LoginArgs),
    /// Drop the cached entry for a tenant.
    Logout(LogoutArgs),
    /// Print the cached `sub` and `iss` for a tenant.
    Whoami(WhoamiArgs),
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Tenant identifier as configured in the identity service.
    #[arg(long)]
    pub tenant: String,
    /// Path to a file whose contents are the OIDC id_token. Mutually
    /// exclusive with `--token-stdin`.
    #[arg(long, conflicts_with = "token_stdin")]
    pub token_file: Option<std::path::PathBuf>,
    /// Read the token from stdin (`cat token | wardenctl auth login
    /// --tenant acme --token-stdin`).
    #[arg(long, conflicts_with = "token_file")]
    pub token_stdin: bool,
}

#[derive(Debug, Args)]
pub struct LogoutArgs {
    #[arg(long)]
    pub tenant: String,
}

#[derive(Debug, Args)]
pub struct WhoamiArgs {
    #[arg(long)]
    pub tenant: String,
    /// Emit JSON instead of `sub <iss>`.
    #[arg(long)]
    pub json: bool,
}

pub async fn run(args: AuthArgs, _identity_url: Option<String>) -> ExitCode {
    match args.command {
        AuthCommand::Login(a) => login(a).await,
        AuthCommand::Logout(a) => logout(a),
        AuthCommand::Whoami(a) => whoami(a),
    }
}

async fn login(args: LoginArgs) -> ExitCode {
    if args.token_file.is_none() && !args.token_stdin {
        eprintln!(
            "error: provide --token-file <PATH> or --token-stdin (device-flow is a follow-up)"
        );
        return ExitCode::Validation;
    }
    let token = match args.token_file {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                eprintln!("error: read {}: {e}", path.display());
                return ExitCode::Validation;
            }
        },
        None => {
            let mut buf = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                eprintln!("error: read stdin: {e}");
                return ExitCode::Validation;
            }
            buf.trim().to_string()
        }
    };
    if token.is_empty() {
        eprintln!("error: token is empty");
        return ExitCode::Validation;
    }

    // Best-effort decode for the bookkeeping fields. A malformed token
    // is allowed through with sub/iss=None — the server will reject it
    // on the first call, which surfaces a clearer error than an
    // up-front rejection here would.
    let claims = crate::credentials::unverified_decode(&token).unwrap_or_default();

    let mut creds = match credentials::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: load credentials: {e}");
            return ExitCode::Server;
        }
    };
    let sub_for_print = claims.sub.clone();
    creds.tenants.insert(
        args.tenant.clone(),
        TenantCredential {
            id_token: token,
            refresh_token: None,
            expires_at: claims.exp,
            sub: claims.sub,
            issuer: claims.issuer,
        },
    );
    if let Err(e) = credentials::save(&creds) {
        eprintln!("error: save credentials: {e}");
        return ExitCode::Server;
    }
    let path = credentials::credentials_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unknown>".into());
    println!(
        "logged in to tenant '{}' as {} (cached at {})",
        args.tenant,
        sub_for_print.as_deref().unwrap_or("<unknown sub>"),
        path
    );
    ExitCode::Ok
}

fn logout(args: LogoutArgs) -> ExitCode {
    let mut creds = match credentials::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: load credentials: {e}");
            return ExitCode::Server;
        }
    };
    if creds.tenants.remove(&args.tenant).is_none() {
        eprintln!("no cached credentials for tenant '{}' (no-op)", args.tenant);
        return ExitCode::Ok;
    }
    if let Err(e) = credentials::save(&creds) {
        eprintln!("error: save credentials: {e}");
        return ExitCode::Server;
    }
    println!("logged out of tenant '{}'", args.tenant);
    ExitCode::Ok
}

fn whoami(args: WhoamiArgs) -> ExitCode {
    let creds = match credentials::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: load credentials: {e}");
            return ExitCode::Server;
        }
    };
    let entry = match creds.tenants.get(&args.tenant) {
        Some(e) => e,
        None => {
            eprintln!(
                "no cached credentials for tenant '{}' — run `wardenctl auth login`",
                args.tenant
            );
            return ExitCode::Auth;
        }
    };
    if args.json {
        let body = serde_json::json!({
            "tenant": args.tenant,
            "sub": entry.sub,
            "issuer": entry.issuer,
            "expires_at": entry.expires_at,
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
    } else {
        let sub = entry.sub.as_deref().unwrap_or("<unknown sub>");
        let iss = entry.issuer.as_deref().unwrap_or("<unknown iss>");
        println!("{sub} <{iss}>");
    }
    ExitCode::Ok
}
