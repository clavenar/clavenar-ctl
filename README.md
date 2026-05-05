# warden-ctl

Operator CLI for [Agent Warden](https://github.com/vanteguardlabs).
Single artifact built on top of [`warden-sdk`](https://github.com/vanteguardlabs/warden-sdk):
the SDK is the typed Rust library (also consumed by `warden-console` and
external integrators), this binary is the human-facing CLI.

Naming follows the kubectl pattern: the **crate / repo** is `warden-ctl`
(matches the `warden-*` family — `warden-identity`, `warden-sdk`,
`warden-hil`, …); the **binary** is `wardenctl` (single word,
typed-on-the-command-line every day). After `cargo install warden-ctl`
you run `wardenctl ...`.

## Status

Currently shipping the read-only surface from
[`ONBOARDING.md`](https://github.com/vanteguardlabs/warden-specs/blob/main/ONBOARDING.md)
P1:

```sh
wardenctl auth login   --tenant <T> --token-file <PATH>
wardenctl auth login   --tenant <T> --token-stdin
wardenctl auth logout  --tenant <T>
wardenctl auth whoami  --tenant <T> [--json]
wardenctl agents list  --tenant <T> [--state ...] [--owner-team ...] [--json]
wardenctl agents get   <ID> --tenant <T> [--json]
```

Writes (`create`, `suspend`, `unsuspend`, `decommission`, `envelope
narrow|widen`, `transfer`, `description`) ship in P2 alongside the
identity-side lifecycle handlers. Migration (`migrate --dry-run`) ships
in P5. The full RFC 8628 device-authorization-grant flow lands in P4
when the dex mock IdP is wired in `warden-e2e`.

## Install

```sh
cargo install --path .                       # from a local checkout
cargo install --git https://github.com/vanteguardlabs/warden-ctl  # from source
```

The binary lands as `~/.cargo/bin/wardenctl`.

## Auth

`wardenctl auth login` caches an OIDC `id_token` per tenant in the
OS-correct credentials file (mode `0600` on Unix; ACL-restricted on
Windows by default).

| Platform | Path |
|---|---|
| Linux / macOS | `~/.warden/credentials.json` |
| Windows | `%APPDATA%\warden\credentials.json` |

Until device-flow ships in P4, supply the token via `--token-file
<path>` or `--token-stdin`. The expected workflow:

```sh
# Mint an id_token via your IdP CLI (Okta / Entra / dex / ...).
mint-okta-token | wardenctl auth login --tenant acme --token-stdin

# Subsequent reads pick up the cached bearer.
wardenctl agents list --tenant acme --json
wardenctl auth whoami --tenant acme
```

`auth logout --tenant <T>` drops the cached entry. The `id_token`'s
`sub` and `iss` claims are decoded (without signature verification) at
login time and surfaced via `auth whoami` — server-side validation on
every request remains the authoritative check.

## Configuration

`~/.warden/config.toml` (optional) holds CLI defaults:

```toml
identity_url = "https://identity.acme.com:8086"
default_tenant = "acme"
```

Resolution order, highest priority first:

1. Per-call `--identity-url` / `--tenant` flag.
2. `WARDEN_IDENTITY_URL` / `WARDEN_TENANT` env vars.
3. `~/.warden/config.toml`.
4. Built-in default for `identity_url`: `http://localhost:8086`.
   No built-in default for `--tenant` — missing fails loudly.

## Exit codes

Per `ONBOARDING.md` §9.3, deterministic and machine-checkable:

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
wardenctl agents list --tenant acme --state active --json | jq '.[].agent_name'
```

Get a single agent, human-readable:

```sh
wardenctl agents get 01HW...A001 --tenant acme
```

## Development

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

The crate is **not** part of a Cargo workspace — it sits next to its
sibling repos under `claude/repos/` and depends on `warden-sdk` via a
`path = "../warden-sdk"` dep. See the parent `CLAUDE.md` for the
multi-repo layout.

## License

Apache-2.0.
