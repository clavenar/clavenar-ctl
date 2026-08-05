# clavenar-ctl

Operator CLI for [Clavenar](https://github.com/clavenar).
Single artifact built on top of [`clavenar-sdk`](https://github.com/clavenar/clavenar-sdk):
the SDK is the typed Rust library (also consumed by `clavenar-console` and
external integrators), this binary is the human-facing CLI.

Naming follows the kubectl pattern: the **crate / repo** is `clavenar-ctl`
(matches the `clavenar-*` family — `clavenar-identity`, `clavenar-sdk`,
`clavenar-hil`, …); the **binary** is `clavenarctl` (single word,
typed-on-the-command-line every day). Install the exact protected release
binary below, then run `clavenarctl ...`.

Sequence diagrams for the five primary subcommands — `auth login`,
`agents <lifecycle-verb>`, `agents create --if-absent`,
`policy test`, and `mcp-bridge` — live in
[`docs/SEQUENCES.md`](docs/SEQUENCES.md).

## Status

Onboarding read + write surfaces and the RFC 8628 operator device-
authorization grant are shipped. The device client has a fixed
least-privilege operator scope distinct from agent workload authority.
Manual `id_token` input remains available for offline bootstrap.

Every network command accepts one reusable secure transport profile:

```sh
clavenarctl --transport-profile ./transport.json doctor
# or: CLAVENAR_TRANSPORT_PROFILE=./transport.json clavenarctl agents list
```

The deny-unknown `clavenar.secure-transport-profile/v1` document selects the
CA bundle, client certificate and private key, token source, connect/request
deadlines, proxy policy, and explicit reload behavior. The same provider is
installed before dispatch for SDK-backed and direct HTTP command paths.

First-run surface (scaffold + probe + Rego templates):

```sh
clavenarctl init                          # scaffold ~/.config/clavenar/config.toml
clavenarctl init --with-policies          # also drop the 7 templates into ./policies/templates/
clavenarctl doctor                        # probe /health on every clavenar service URL
clavenarctl doctor --json                 # JSON output for CI smoke
clavenarctl generate-policy list          # browse the starter pack
clavenarctl generate-policy pii_egress    # emit a template to stdout
clavenarctl generate-policy pii_egress --output policies/pii_egress.rego
```

`doctor` reports up/down/latency for identity, ledger, hil, console,
brain, and policy-engine. Proxy is opt-in via `--proxy-url` because
its mTLS gate looks like "down" to a no-cert probe. Exit code is 0
when every probed service is up, 5 otherwise — safe to wire into
`docker compose` healthcheck loops or CI smoke scripts.

`generate-policy` templates are embedded in the binary at build time
from `clavenar-policy-engine/policies/templates/` — no FS dependency
at runtime.

Read surface:

```sh
clavenarctl auth login   --tenant <T> --issuer <OIDC_ISSUER>
clavenarctl auth login   --tenant <T> --token-file <PATH>
clavenarctl auth login   --tenant <T> --token-stdin
clavenarctl auth logout  --tenant <T>
clavenarctl auth whoami  --tenant <T> [--json]
clavenarctl agents list  --tenant <T> [--state ...] [--owner-team ...] [--json]
clavenarctl agents get   <ID> --tenant <T> [--json]
```

Write surface (lifecycle, all wired through the SDK):

```sh
clavenarctl agents create        --tenant <T> --name <N> --owner-team <T> \
                               --scope <S>... --yellow-scope <S>... \
                               --attestation-kind <K>... [--description <D>] [--if-absent]
clavenarctl agents suspend       <ID> --tenant <T> [--reason <R>]
clavenarctl agents unsuspend     <ID> --tenant <T> [--reason <R>]
clavenarctl agents decommission  <ID> --tenant <T> [--reason <R>]
clavenarctl agents envelope narrow <ID> --tenant <T> --scope <S>... --yellow-scope <S>...
clavenarctl agents envelope widen  <ID> --tenant <T> --scope <S>... --yellow-scope <S>...
clavenarctl agents transfer      <ID> --tenant <T> --to-team <T>
clavenarctl agents description   <ID> --tenant <T> --text <D>
clavenarctl agents certify       <ID> --tenant <T> --proxy-url <URL> \
                               --cert-dir <DIR> --sdk-version <V> [--out <F>]
```

`agents certify` drives the candidate through the pre-flight gauntlet —
fires the chaos catalog's `agent_cert` family at the proxy as the
candidate's own mTLS traffic (`--cert-dir` holds its
`client.crt`/`client.key`/`ca.crt`), asserts every probe is denied at the
boundary, then records a signed survival certificate via identity's
`/agents/{id}/certification`. Writes `<id>.cert.json`; exits non-zero
(writing nothing) if any probe reaches the agent. Honest scope: it proves
the enforcement boundary held for the asserted `--sdk-version`, not that
the agent's own code is correct.

Migration:

```sh
clavenarctl agents migrate \
  --tenant <T> \
  --names path/to/agent-names.txt \
  --default-owner-team legacy-fleet \
  [--default-scope <S>...] [--default-yellow-scope <S>...] \
  [--default-attestation-kind <K>...] \
  [--dry-run] [--json]
```

`--names` takes a flat list of agent names — one per line, blank lines
and `# comment` rows skipped. The CLI doesn't reach into identity's
SQLite directly; the operator builds the list from their own source
of truth (logs, IaC, `grep` over existing SPIFFE identities).

The migration command anchors `agent.registered` chain v3 rows with
`actor_sub = system:migration:<operator_oidc_sub>` so the chain
records the human who ran the bulk enrollment.

Onboarding funnel (discovery → enrollment):

```sh
# Greenfield: interactive first-agent wizard.
clavenarctl agents bootstrap [--tenant <T>]

# Bridge a shadow-scanner report to a names file.
clavenarctl agents import-from-scanner report.json -o names.txt [--min-severity high]

# Or emit expected-silent allowlist seeds ({agent_id,reason,source}) to apply
# to the ledger's POST /silence-allowlist, so scanner-surfaced credentials
# don't also trip the silence watchdog.
clavenarctl agents import-from-scanner report.json --silence-allowlist -o seeds.json

# Shadow-Agent-Radar provider audit-log correlation: diff a normalized
# provider usage export ([{agent_id, usage_count}]) against on-chain verdict
# counts. Present at the provider but absent/undercounted on-chain = bypass.
clavenarctl import-provider-audit usage.json --provider aws --window-hours 24 [--json]

# Bridge SPIRE/workload identities to enrollment.
clavenarctl agents import-from-workloads spire-entries.json -o names.txt
clavenarctl agents import-from-workloads --from-identity --enroll \
  --tenant <T> --default-owner-team legacy-fleet [--dry-run] [--json]
```

`import-from-workloads` takes a SPIRE `entry show -output json` file, a
flat list of `spiffe://…` IDs/paths/names (`-` = stdin), or
`--from-identity` (which pulls identity's `GET /agents/orphans` feed —
names that minted an SVID but were never registered). Each SPIFFE id
maps to a candidate name (clavenar `…/agent/<name>/…`, SPIRE k8s
`…/ns/<ns>/sa/<sa>` → `<ns>-<sa>`, else the slugified last segment); a
clavenar-shaped path naming a different tenant is skipped. Default
writes a names file for review; `--enroll --default-owner-team <t>`
registers the unenrolled names directly, reusing `migrate`'s idempotent
register-if-absent engine and `system:migration:` attribution.

Regulatory exports:

```sh
clavenarctl regulatory export \
  --tenant acme \
  --from 2026-04-01T00:00:00Z --to 2026-05-01T00:00:00Z \
  [--readme path/to/technical_documentation.md] \
  [--include-exports] \
  [--ledger-url http://ledger.test:8083] \
  --output bundle.tar.gz   # or '-' for stdout
```

Tenant resolves through flag → environment → config and is required before
network access. Window is half-open `[from, to)`. `--readme` (≤ 1 MiB) embeds operator
prose under `technical_documentation.md` inside the bundle; the
ledger commits to its sha256 in the manifest. `--include-exports`
asks the ledger to splice in `manifest.parquet_pointers` for any
cold-tier snapshot whose seq range overlaps the window.

Ledger URL precedence: flag → `CLAVENAR_LEDGER_URL` env → `http://localhost:8083`.

## Install

The release archive naming template is
`clavenarctl-${V}-x86_64-linux-musl` with `V=0.3.2`. The expanded,
copy-pasteable install is:

```sh
mkdir clavenar-source && cd clavenar-source
curl -fsSLO https://github.com/clavenar/clavenar-ctl/releases/download/v0.3.2/clavenarctl-0.3.2-x86_64-linux-musl.tar.gz
curl -fsSLO https://github.com/clavenar/clavenar-ctl/releases/download/v0.3.2/clavenarctl-0.3.2-x86_64-linux-musl.tar.gz.sha256
sha256sum -c clavenarctl-0.3.2-x86_64-linux-musl.tar.gz.sha256
tar -xzf clavenarctl-0.3.2-x86_64-linux-musl.tar.gz
install -m 0755 clavenarctl "$HOME/.local/bin/clavenarctl"
```

The exact released source graph includes the CLI's sibling Rust crates, so the
workspace checkout is required. The binary lands as
`~/.cargo/bin/clavenarctl`.

## Auth

`clavenarctl auth login` caches an OIDC `id_token` per tenant in the
OS-correct credentials file (mode `0600` on Unix, opened with that
mode atomically on create so a stolen-laptop attacker without root
can't read another user's token; ACL-restricted on Windows by
default).

The on-disk path follows the `directories` crate's `config_dir()`:

| Platform | Path |
|---|---|
| Linux | `~/.config/clavenar/credentials.json` (or `$XDG_CONFIG_HOME/clavenar/...`) |
| macOS | `~/Library/Application Support/dev.agent-clavenar.clavenar/credentials.json` |
| Windows | `%APPDATA%\agent-clavenar\clavenar\config\credentials.json` |

Tests and the e2e runner override the path with `CLAVENAR_CREDENTIALS_PATH`
so they don't pollute the operator's real file.

Use the production IdP's exact issuer for the primary device flow:

```sh
clavenarctl auth login \
  --tenant acme \
  --issuer https://idp.example/realms/acme

# Follow the displayed verification URL and approve the fixed
# `openid clavenar.operator` authority. Manual input remains explicit:
mint-offline-token | clavenarctl auth login --tenant acme --token-stdin

# Subsequent reads pick up the cached bearer.
clavenarctl agents list --tenant acme --json
clavenarctl auth whoami --tenant acme
```

Discovery and token endpoints must share the issuer origin. The CLI bounds
response sizes, device lifetime, polling interval, poll count, redirects,
connect time, and request time; it never persists device or user codes. It
requires the returned ID token to carry the exact requested
`clavenar_tenant` and operator scope without agent authority before saving
the ID and optional refresh tokens. `auth logout --tenant <T>` drops the
cached entry. `auth whoami` displays locally decoded bookkeeping fields;
server-side validation on every request remains authoritative.

## Configuration

A `config.toml` next to the credentials file (e.g.
`~/.config/clavenar/config.toml` on Linux) holds CLI defaults — optional:

```toml
identity_url = "https://identity.acme.com:8086"
default_tenant = "acme"
```

Resolution order, highest priority first:

1. Per-call `--identity-url` / `--tenant` flag.
2. `CLAVENAR_IDENTITY_URL` / `CLAVENAR_TENANT` env vars.
3. `~/.config/clavenar/config.toml`.
4. Built-in default for `identity_url`: `http://localhost:8086`.
   No built-in default for `--tenant` — missing fails loudly.

## Exit codes

Per `clavenar-specs/TECH_SPEC.md#agent-onboarding-wao` §9.3, deterministic and machine-checkable:

| Code | Meaning | Examples |
|------|---------|----------|
| `0`  | Success | the request succeeded |
| `2`  | Validation error | bad CLI args, malformed body, server 400 / 404 / 422 |
| `3`  | Auth / capability error | server 401 / 403 |
| `4`  | Conflict | server 409 (`agent_name_taken`, `agent_name_retired`) |
| `5`  | Server error | server 5xx, transport error, response decode failure |

CI scripts can treat `0` as "do nothing", `4` as "already in the
desired state, continue", and any other non-zero as "fail loudly".

## Examples

List active agents in a tenant, JSON for piping into `jq`:

```sh
clavenarctl agents list --tenant acme --state active --json | jq '.[].agent_name'
```

Get a single agent, human-readable:

```sh
clavenarctl agents get 01HW...A001 --tenant acme
```

## Inspect a decision link from the terminal

`clavenarctl pending decide <token>` verifies and previews a signed decision link —
the same `approve`/`deny` token carried in HIL notifier cards (Slack,
Teams, PagerDuty, webhook, SMTP) or minted via
`GET /pending/{id}/decision-link` — from a shell, for terminal-resident
operators.

```sh
# Verify the link and preview the pending it points at.
clavenarctl pending decide <token> \
  --hil-url https://hil.internal:8084 \
  --cert ops.crt --key ops.key --ca ca.crt
```

The token is a *pointer plus an action claim, never a credential*:
the CLI deliberately has no decision authority. HIL derives decision
principals from authenticated server state, so apply the link through the
Console redemption page and its normal operator session. The retained hidden
`--yes` compatibility flag returns exit `3` and sends no mutation. A link whose
pending already settled exits `4` (conflict) during inspection.

## Connect an MCP client

`clavenarctl mcp-bridge` is the stdio shim every MCP client uses to
ride the proxy. The same bridge serves Claude Code, Cursor, Cline,
Continue, the Codex CLI, and any generic stdio MCP client — only
the per-client config-file shape differs.

Recipes for each supported client live in [`docs/clients/`](docs/clients/):

- [Claude Code](docs/clients/claude-code.md)
- [Cursor](docs/clients/cursor.md)
- [Cline (VS Code)](docs/clients/cline.md)
- [Continue.dev](docs/clients/continue.md)
- [OpenAI Codex CLI](docs/clients/codex.md)
- [Generic stdio MCP](docs/clients/generic-stdio.md)

The bridge accepts `--client-hint <name>` for diagnostics and to
reserve the surface for future per-client behavior — recipes pass it
for forward-compat.

The bridge leaves MCP negotiation and enumeration methods unselected. For
every effect-capable method it selects `clavenar.server-execution/v1` and
allocates a durable idempotency UUID before the network request, so the proxy
cannot interpret an inspection frame as authorization to execute.

## Development

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

The crate is **not** part of a Cargo workspace — it sits next to its
sibling repos under `claude/repos/` and depends on `clavenar-sdk` via a
`path = "../clavenar-sdk"` dep. See the parent repo layout for the
multi-repo layout.

## License

Apache-2.0.
