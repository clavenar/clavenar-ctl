//! `clavenarctl policy exchange {sign,install}` — signed governance
//! packs with a mandatory local backtest gate.
//!
//! `sign` walks a directory of `*.rego` files, builds a `pack.json`
//! manifest committing to each file's sha256, signs the manifest digest
//! via clavenar-identity's `/sign/blob` (audience `policy-pack`), and
//! writes `pack.json` + `pack.sig`.
//!
//! `install` is fail-closed: it (1) re-hashes each file against the
//! manifest, (2) verifies the detached Ed25519 signature against the
//! issuer JWKS (or an operator-pinned SPKI PEM), (3) **backtests** every
//! candidate policy against the Rego-decidable chaos catalog and refuses
//! to install if any policy fails to compile or *weakens* a known-attack
//! verdict (Deny/Yellow → Allow), and only then (4) lands each policy in
//! the policy-engine with pack provenance recorded in the version
//! `reason`. Name collisions are refused (no in-place replace in v1).

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use clavenar_chaos_catalog::catalog_policy_inputs;
use clavenar_sdk::{
    BatchMode, CreatePolicyRequest, DiffClass, EvaluateBatchRequest, PackEntry, PackManifest,
    PackSignatureRef, PackSigner, PackVerifyOutcome, PoliciesClient, VerifyingKey,
    PACK_MANIFEST_FILENAME, PACK_MANIFEST_SCHEMA_VERSION, PACK_SIGNATURE_SIDECAR, verify_pack,
    verifying_key_from_jwks, verifying_key_from_pem,
};
use sha2::{Digest, Sha256};

use super::policy_lab::{build_mtls_client, parse_resolve};
use crate::ExitCode;

#[derive(Debug, Args)]
pub(crate) struct ExchangeArgs {
    #[command(subcommand)]
    pub action: ExchangeAction,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ExchangeAction {
    /// Sign a pack directory: hash each `.rego`, build `pack.json`, sign
    /// the manifest via identity, write `pack.json` + `pack.sig`.
    Sign(SignArgs),
    /// Verify + backtest + install a signed pack into the policy-engine.
    Install(InstallArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SignArgs {
    /// Pack directory containing the `*.rego` files to sign.
    pub pack_dir: PathBuf,
    /// Pack name. Defaults to the directory's file name.
    #[arg(long)]
    pub name: Option<String>,
    /// Pack version string (opaque). Default `1`.
    #[arg(long, default_value = "1")]
    pub version: String,
    /// clavenar-identity base URL.
    #[arg(long)]
    pub identity_url: String,
    /// SPIFFE id presented to identity's `/sign/blob` caller allowlist.
    #[arg(long)]
    pub caller_spiffe: String,
}

#[derive(Debug, Args)]
pub(crate) struct InstallArgs {
    /// Signed pack directory (contains `pack.json` + `pack.sig`).
    pub pack_dir: PathBuf,
    /// policy-engine base URL. Falls back to `CLAVENAR_POLICY_URL`, then
    /// `http://localhost:8082`.
    #[arg(long)]
    pub policy_url: Option<String>,
    /// Issuer JWKS URL to resolve the signing key by `kid`.
    #[arg(long)]
    pub jwks_url: Option<String>,
    /// SPKI PEM public key to verify against, instead of fetching JWKS.
    #[arg(long)]
    pub pubkey: Option<PathBuf>,
    /// Version `reason` recorded on each landed policy.
    #[arg(long)]
    pub reason: String,
    #[arg(long)]
    pub actor_sub: String,
    #[arg(long)]
    pub actor_idp: String,
    /// Client cert for the mTLS call to the policy-engine.
    #[arg(long)]
    pub client_cert: Option<PathBuf>,
    #[arg(long)]
    pub client_key: Option<PathBuf>,
    #[arg(long)]
    pub ca_cert: Option<PathBuf>,
    /// `--resolve NAME:PORT:ADDR`, like curl's. See `policy test`.
    #[arg(long = "resolve")]
    pub resolve: Vec<String>,
}

pub(crate) async fn run(args: ExchangeArgs) -> ExitCode {
    match args.action {
        ExchangeAction::Sign(a) => sign(a).await,
        ExchangeAction::Install(a) => install(a).await,
    }
}

/// Read the `*.rego` files under `dir`, sorted by filename for a stable
/// manifest. Returns `(entries, bodies)` where `bodies[i]` is the source
/// of `entries[i]`.
fn read_pack_dir(dir: &Path) -> Result<(Vec<PackEntry>, Vec<String>), String> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("read {}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("rego"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("no .rego files in {}", dir.display()));
    }
    let mut entries = Vec::with_capacity(files.len());
    let mut bodies = Vec::with_capacity(files.len());
    for path in files {
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("bad filename: {}", path.display()))?
            .to_string();
        entries.push(PackEntry {
            path: name,
            content_type: "rego".to_string(),
            body_sha256: hex::encode(Sha256::digest(body.as_bytes())),
        });
        bodies.push(body);
    }
    Ok((entries, bodies))
}

async fn sign(args: SignArgs) -> ExitCode {
    let (entries, _bodies) = match read_pack_dir(&args.pack_dir) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::Validation;
        }
    };
    let name = args.name.unwrap_or_else(|| {
        args.pack_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("pack")
            .to_string()
    });

    let mut manifest = PackManifest {
        schema_version: PACK_MANIFEST_SCHEMA_VERSION.to_string(),
        name,
        version: args.version,
        entries,
        generated_at: chrono::Utc::now(),
        signature: None,
    };

    let digest = match manifest.digest_hex() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: canonicalize manifest: {e}");
            return ExitCode::Server;
        }
    };

    let signer = PackSigner::new(args.identity_url, args.caller_spiffe);
    let sig = match signer.sign(&digest).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: sign via identity: {e}");
            return ExitCode::Server;
        }
    };
    if sig.algorithm != "ed25519" || sig.signature_hex.len() != 128 {
        eprintln!(
            "error: identity returned unexpected signature (alg={}, {} hex chars)",
            sig.algorithm,
            sig.signature_hex.len()
        );
        return ExitCode::Server;
    }
    manifest.signature = Some(PackSignatureRef {
        sidecar: PACK_SIGNATURE_SIDECAR.to_string(),
        algorithm: "ed25519".to_string(),
        digest_alg: "sha256".to_string(),
        key_id: sig.key_id,
        signed_at: sig.signed_at,
    });

    let manifest_bytes = match serde_json::to_vec_pretty(&manifest) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: serialize manifest: {e}");
            return ExitCode::Server;
        }
    };
    let manifest_path = args.pack_dir.join(PACK_MANIFEST_FILENAME);
    let sig_path = args.pack_dir.join(PACK_SIGNATURE_SIDECAR);
    if let Err(e) = std::fs::write(&manifest_path, &manifest_bytes) {
        eprintln!("error: write {}: {e}", manifest_path.display());
        return ExitCode::Server;
    }
    if let Err(e) = std::fs::write(&sig_path, format!("{}\n", sig.signature_hex)) {
        eprintln!("error: write {}: {e}", sig_path.display());
        return ExitCode::Server;
    }
    eprintln!("signed pack '{}' v{}", manifest.name, manifest.version);
    eprintln!("wrote {}", manifest_path.display());
    eprintln!("wrote {}", sig_path.display());
    ExitCode::Ok
}

async fn install(args: InstallArgs) -> ExitCode {
    // 1. Load manifest + sidecar.
    let manifest_path = args.pack_dir.join(PACK_MANIFEST_FILENAME);
    let sig_path = args.pack_dir.join(PACK_SIGNATURE_SIDECAR);
    let manifest_raw = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: read {}: {e}", manifest_path.display());
            return ExitCode::Validation;
        }
    };
    let manifest: PackManifest = match serde_json::from_str(&manifest_raw) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: parse {}: {e}", manifest_path.display());
            return ExitCode::Validation;
        }
    };
    let sig_hex = match std::fs::read_to_string(&sig_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: read {}: {e}", sig_path.display());
            return ExitCode::Validation;
        }
    };

    // 2. Each file's bytes must match its committed sha256.
    for entry in &manifest.entries {
        let path = args.pack_dir.join(&entry.path);
        let body = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: read {}: {e}", path.display());
                return ExitCode::Validation;
            }
        };
        let got = hex::encode(Sha256::digest(&body));
        if got != entry.body_sha256 {
            eprintln!(
                "error: {} sha256 mismatch (manifest {}, on-disk {})",
                entry.path, entry.body_sha256, got
            );
            return ExitCode::Validation;
        }
    }

    // 3. Verify the detached signature against the resolved key.
    let key_id = match manifest.signature.as_ref() {
        Some(s) => s.key_id.clone(),
        None => {
            eprintln!("error: pack is unsigned; refusing to install");
            return ExitCode::Validation;
        }
    };
    let key = match resolve_key(&args, &key_id).await {
        Ok(k) => k,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::Validation;
        }
    };
    match verify_pack(&manifest, &sig_hex, &key) {
        PackVerifyOutcome::Valid => {}
        PackVerifyOutcome::Unsigned => {
            eprintln!("error: pack is unsigned; refusing to install");
            return ExitCode::Validation;
        }
        PackVerifyOutcome::Forged(m) => {
            eprintln!("error: signature verification FAILED: {m}");
            return ExitCode::Validation;
        }
        PackVerifyOutcome::Malformed(m) => {
            eprintln!("error: signature malformed: {m}");
            return ExitCode::Validation;
        }
    }
    eprintln!("signature OK (kid={key_id})");

    // 4. Build the policy-engine client (mTLS when certs supplied).
    let policy_url = args
        .policy_url
        .clone()
        .or_else(|| std::env::var("CLAVENAR_POLICY_URL").ok())
        .unwrap_or_else(|| "http://localhost:8082".into());
    let resolve_pairs = match parse_resolve(&args.resolve) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("error: --resolve: {msg}");
            return ExitCode::Validation;
        }
    };
    let mtls = match build_mtls_client(
        args.client_cert.as_deref(),
        args.client_key.as_deref(),
        args.ca_cert.as_deref(),
        &resolve_pairs,
    ) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::Validation;
        }
    };
    let mut policy = match PoliciesClient::new(&policy_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: policy url {policy_url}: {e}");
            return ExitCode::Validation;
        }
    };
    if let Some(c) = mtls {
        policy = policy.with_http_client(c);
    }

    // 5. Name-collision check (refuse rather than silently replace).
    let existing: Vec<String> = match policy.list(false).await {
        Ok(rows) => rows.into_iter().map(|p| p.name).collect(),
        Err(e) => {
            eprintln!("error: list policies: {e}");
            return ExitCode::Server;
        }
    };
    let bodies: Vec<(String, String)> = match read_pack_dir(&args.pack_dir) {
        Ok((entries, bodies)) => entries
            .into_iter()
            .map(|e| policy_name(&e.path))
            .zip(bodies)
            .collect(),
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::Validation;
        }
    };
    for (name, _) in &bodies {
        if existing.iter().any(|n| n == name) {
            eprintln!("error: policy '{name}' already exists; refusing to overwrite");
            return ExitCode::Conflict;
        }
    }

    // 6. Mandatory backtest gate: every candidate must compile and must
    //    not weaken a known-attack verdict.
    let inputs = catalog_policy_inputs();
    eprintln!(
        "backtest: {} candidate policy(ies) against {} Rego-decidable attacks",
        bodies.len(),
        inputs.len()
    );
    for (name, body) in &bodies {
        let req = EvaluateBatchRequest {
            candidate_rego: body.clone(),
            candidate_name: name.clone(),
            mode: BatchMode::Add,
            replace_rule_name: None,
            inputs: inputs.clone(),
        };
        let resp = match policy.evaluate_batch(&req).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: backtest '{name}': {e}");
                return ExitCode::Server;
            }
        };
        if !resp.candidate_compile_ok {
            eprintln!("REFUSED — '{name}' does not compile");
            return ExitCode::Validation;
        }
        let regressions = resp
            .results
            .iter()
            .filter(|r| matches!(r.diff, DiffClass::DenyToAllow | DiffClass::YellowToAllow))
            .count();
        if regressions > 0 {
            eprintln!("REFUSED — '{name}' weakens {regressions} known-attack verdict(s)");
            return ExitCode::Validation;
        }
        eprintln!("  ok: {name} (compiles, 0 regressions)");
    }

    // 7. Land each policy with pack provenance.
    let provenance = format!(
        " [pack {}@{} key={}]",
        manifest.name, manifest.version, key_id
    );
    for (name, body) in &bodies {
        let reason = format!("{}{}", args.reason, provenance);
        let req = CreatePolicyRequest {
            name,
            content_type: "rego",
            body,
            reason: &reason,
            actor_sub: &args.actor_sub,
            actor_idp: &args.actor_idp,
            active: Some(true),
        };
        match policy.create(&req).await {
            Ok(_) => eprintln!("installed {name}"),
            Err(e) => {
                eprintln!("error: install '{name}': {e} (pack partially applied)");
                return ExitCode::Server;
            }
        }
    }
    eprintln!(
        "pack '{}' v{} installed ({} policy/ies)",
        manifest.name,
        manifest.version,
        bodies.len()
    );
    ExitCode::Ok
}

/// Policy name from a `.rego` filename (`money_moves.rego` → `money_moves`).
fn policy_name(filename: &str) -> String {
    filename.strip_suffix(".rego").unwrap_or(filename).to_string()
}

/// Resolve the Ed25519 verifying key: a pinned SPKI PEM if `--pubkey`,
/// else the issuer JWKS fetched from `--jwks-url`.
async fn resolve_key(args: &InstallArgs, key_id: &str) -> Result<VerifyingKey, String> {
    if let Some(pem_path) = &args.pubkey {
        let pem = std::fs::read_to_string(pem_path)
            .map_err(|e| format!("read --pubkey {}: {e}", pem_path.display()))?;
        return verifying_key_from_pem(&pem).map_err(|e| e.to_string());
    }
    let jwks_url = args
        .jwks_url
        .as_ref()
        .ok_or_else(|| "supply --jwks-url or --pubkey to verify the pack".to_string())?;
    let body = reqwest::get(jwks_url)
        .await
        .map_err(|e| format!("fetch jwks {jwks_url}: {e}"))?
        .text()
        .await
        .map_err(|e| format!("read jwks body: {e}"))?;
    let doc: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("parse jwks: {e}"))?;
    verifying_key_from_jwks(&doc, key_id).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_name_strips_rego_suffix() {
        assert_eq!(policy_name("money_moves.rego"), "money_moves");
        assert_eq!(policy_name("no_ext"), "no_ext");
    }

    #[test]
    fn read_pack_dir_hashes_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.rego"), "package clavenar.authz\n").unwrap();
        std::fs::write(dir.path().join("a.rego"), "package clavenar.authz\n").unwrap();
        std::fs::write(dir.path().join("ignore.txt"), "nope").unwrap();
        let (entries, bodies) = read_pack_dir(dir.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "a.rego"); // sorted
        assert_eq!(entries[1].path, "b.rego");
        assert_eq!(entries[0].body_sha256.len(), 64);
        assert_eq!(bodies.len(), 2);
    }

    #[test]
    fn read_pack_dir_rejects_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_pack_dir(dir.path()).is_err());
    }
}
