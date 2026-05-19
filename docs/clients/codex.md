# OpenAI Codex CLI → Agent Warden

[Codex CLI](https://github.com/openai/codex) is OpenAI's open-source
agent-CLI for terminal-based coding. It reads MCP server config from
`~/.codex/config.toml` under the `[mcp_servers.*]` section.

## Config

`~/.codex/config.toml`:

```toml
[mcp_servers.warden]
command = "wardenctl"
args = [
  "mcp-bridge",
  "--url",   "https://localhost:19443",
  "--cert",  "/Users/you/warden/certs-dev/client.crt",
  "--key",   "/Users/you/warden/certs-dev/client.key",
  "--ca",    "/Users/you/warden/certs-dev/ca.crt",
  "--client-hint", "codex",
]
```

`[mcp_servers.<name>]` is a TOML table — `<name>` is the alias Codex
uses internally. Multiple `[mcp_servers.*]` sections coexist.

## OS-specific paths

| OS | Path |
|---|---|
| macOS | `~/.codex/config.toml` |
| Linux | `~/.codex/config.toml` |
| Windows | `%USERPROFILE%\.codex\config.toml` |

## Verify

```bash
codex --tools
```

The `warden` MCP server's tools should appear in the listing. Then
in an interactive `codex` session:

```text
> use a warden tool to list resources
```

The proxy log shows the call; ledger captures the row.

## Known quirks

- **TOML, not JSON.** Codex breaks from the Claude Code / Cursor /
  Cline convention. Reach for `[mcp_servers.<name>]`, not
  `mcpServers: { ... }`.
- **Auth model.** Codex authenticates against OpenAI's API for the
  model itself; Warden enforces a separate identity (the cert) for
  the agent's tool calls. Both layers stay independent.
- **Sandbox interaction.** Codex's own `--sandbox` flag restricts
  what tools the agent can invoke from a process standpoint. It does
  not replace Warden's network-level gating.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Codex doesn't list the warden server | Confirm TOML section name — must be `[mcp_servers.warden]`, not `[mcp_servers]` with a `warden` array element. |
| Bridge prints stderr but Codex shows nothing | Codex suppresses stderr by default; run with `RUST_LOG=debug codex --debug` to see bridge output inline. |
| `warden proxy 403` on every call | Vault entry missing for the agent_id; see [README.md](README.md#shared-prerequisites). |
