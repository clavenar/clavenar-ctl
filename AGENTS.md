<!-- public repo — do not add internal topology, secrets, deploy/runbook, strategy, or absolute host paths -->
# clavenar-ctl — operator CLI (binary: `clavenarctl`), thin client over `clavenar-sdk`

The crate/repo is `clavenar-ctl`; the shipped binary is `clavenarctl`
(kubectl pattern). Every subcommand calls into a `clavenar-sdk` client —
the SDK is the typed library, this is the human-facing CLI.

## Build, test, lint
- Build: `cargo build` (release: `cargo build --release`).
  Host caveat: this repo's `target/` may be root-owned from prior docker
  builds — build on the host with `CARGO_TARGET_DIR=/tmp/clavenar-ctl-target`.
- Test: `cargo test` (integration tests spawn the binary via `assert_cmd`).
- Lint: `cargo clippy --all-targets -- -D warnings` (the floor — no `#[allow]`
  to silence). Supply-chain gate: `cargo deny check all` + `cargo cyclonedx`
  (SBOM), run host-side.
- Sibling path-deps: this crate is **not** in a Cargo workspace. It depends
  on `../clavenar-sdk` and `../clavenar-chaos-catalog` by path, and
  `include_str!`s Rego templates from
  `../clavenar-policy-engine/policies/templates/`. CI clones those siblings
  into the same relative location via the `CLAVENAR_REPO_TOKEN` secret
  before building.

Run: `clavenarctl <verb>` (e.g. `clavenarctl doctor`, `clavenarctl agents list
--tenant <T>`). No listener — it's a client; it talks to identity (`:8086`),
ledger (`:8083`), and hil (`:8084`) over HTTP/HTTPS, and the proxy over mTLS.
After `cargo install --path .` the binary lands as `~/.cargo/bin/clavenarctl`.

## Layout
- `src/main.rs` — entrypoint. `Cli` / `Command` clap-derive tree, global
  `--identity-url`, and the `ExitCode` mapping.
- `src/cmd/` — one module per verb, each exporting an `Args` struct + `run()`
  returning `ExitCode`. Top-level verbs: `auth`, `agents`, `regulatory`,
  `doctor`, `init`, `generate-policy` (`policy`), `pending`, `mcp-bridge`.
  Supporting modules: `import_scanner`, `import_workloads`,
  `import_provider_audit`, `migrate`, `bootstrap`, `agents_certify`,
  `assurance`, and the `policy_*` Exchange/library/lab/scaffold helpers.
- `src/config.rs` — `config.toml` parse + flag→env→file→default resolution.
- `src/credentials.rs` — per-tenant OIDC `id_token` cache.
- `tests/cli_integration.rs` — `assert_cmd` exit-code / stdout contract.
- `docs/SEQUENCES.md` — sequence diagrams for the primary subcommands.
- `docs/clients/` — per-MCP-client `mcp-bridge` setup recipes.
- `deny.toml` — supply-chain policy (advisories / licenses / bans / sources).

## Conventions & invariants
- **Exit codes are a wire contract** (spec §9.3), deterministic and
  machine-checkable: `0` success · `2` validation (bad args, 400/404/422) ·
  `3` auth/capability (401/403) · `4` conflict (409, already-in-desired-state) ·
  `5` server (5xx, transport, decode). CI treats `4` as "continue", other
  non-zero as "fail loudly". Don't repurpose these.
- **Config resolution, highest first:** per-call flag → env var
  (`CLAVENAR_IDENTITY_URL` / `CLAVENAR_TENANT` / `CLAVENAR_LEDGER_URL`) →
  `config.toml` (next to the credentials file) → built-in default
  (`identity_url` = `http://localhost:8086`). No default tenant — missing
  fails loudly.
- **Credentials file is mode `0600` on Unix**, opened atomically with that
  mode on create (ACL-restricted on Windows). Path follows the `directories`
  crate `config_dir()` (`~/.config/clavenar/credentials.json` on Linux).
  Tests/e2e override with `CLAVENAR_CREDENTIALS_PATH` — never touch the
  operator's real file from a test.
- **`auth whoami` decodes JWT claims without verifying the signature** —
  display only. Server-side validation on every request stays authoritative.
- **`pending decide <token>` token is a pointer + action claim, never a
  credential.** Deciding still requires the operator's own standing
  authority: an mTLS client cert in HIL's allowlist plus the decide-token
  bearer (`CLAVENAR_HIL_DECIDE_TOKEN` / `--decide-token`). `--as` stamps the
  operator into the chain; rows are marked `decided_via=terminal`. Nothing is
  decided without `--yes`.
- **`generate-policy` templates are embedded at build time** via
  `include_str!` from the policy-engine sibling — no runtime FS dependency,
  but the sibling must be present at compile time (hence the CI clone).
- **`agents certify` exits non-zero writing nothing** if any chaos probe
  reaches the candidate; it proves the enforcement boundary held for the
  asserted `--sdk-version`, not that agent code is correct.

Rust house rules (the ones that bite here):
- clippy `-D warnings` is the floor; fix the code, don't `#[allow]` (only for
  a documented false positive, with the reason in the attribute). This crate
  also sets `unreachable_pub = "warn"` — keep visibility tight; use
  `pub(crate)` for module-internal items.
- A type in a `pub` fn signature must itself be `pub` (`private_interfaces`).
- Tests at file bottom in `#[cfg(test)] mod tests` (after all other items).
- `writeln!` over `write!(…, "…\n")`; prefer let-chains over nested `if let`.
- Doc comments: no `+ ` line-start continuations (clippy reads them as
  misindented list items).
- `deny.toml` is synced verbatim across the Rust family — edit the public
  source repo first, then mirror; don't drift it locally.

## Pointers
README.md · SECURITY.md · docs/SEQUENCES.md · docs/clients/
