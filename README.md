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

Onboarding read + write surfaces all shipped. The full RFC
8628 device-authorization-grant flow remains the open item — it lands
once the dex mock IdP is wired in `warden-e2e`; until then, supply the
`id_token` via `--token-file` or `--token-stdin`.

Read surface:

```sh
wardenctl auth login   --tenant <T> --token-file <PATH>
wardenctl auth login   --tenant <T> --token-stdin
wardenctl auth logout  --tenant <T>
wardenctl auth whoami  --tenant <T> [--json]
wardenctl agents list  --tenant <T> [--state ...] [--owner-team ...] [--json]
wardenctl agents get   <ID> --tenant <T> [--json]
```

Write surface (lifecycle, all wired through the SDK):

```sh
wardenctl agents create        --tenant <T> --name <N> --owner-team <T> \
                               --scope <S>... --yellow-scope <S>... \
                               --attestation-kind <K>... [--description <D>] [--if-absent]
wardenctl agents suspend       <ID> --tenant <T> [--reason <R>]
wardenctl agents unsuspend     <ID> --tenant <T> [--reason <R>]
wardenctl agents decommission  <ID> --tenant <T> [--reason <R>]
wardenctl agents envelope narrow <ID> --tenant <T> --scope <S>... --yellow-scope <S>...
wardenctl agents envelope widen  <ID> --tenant <T> --scope <S>... --yellow-scope <S>...
wardenctl agents transfer      <ID> --tenant <T> --to-team <T>
wardenctl agents description   <ID> --tenant <T> --text <D>
```

Migration:

```sh
wardenctl agents migrate \
  --identity-db /var/lib/warden-identity/identity.sqlite \
  [--dry-run] [--default-owner-team unassigned] \
  [--default-envelope '*'] [--default-attestation-kinds '*']
```

The migration command anchors `agent.registered` chain v3 rows with
`actor_sub = system:migration:<operator_oidc_sub>` so the chain
records the human who ran the bulk enrollment.

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

Until device-flow ships, supply the token via `--token-file
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
