# Cursor → Agent Warden

[Cursor](https://cursor.com) registers MCP servers in
`~/.cursor/mcp.json` (global) or `<workspace>/.cursor/mcp.json`
(per-project). Cursor reads the same JSON shape Claude Code uses.

## Config

`~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "warden": {
      "command": "/usr/local/bin/wardenctl",
      "args": [
        "mcp-bridge",
        "--url",   "https://localhost:19443",
        "--cert",  "/Users/you/warden/certs-dev/client.crt",
        "--key",   "/Users/you/warden/certs-dev/client.key",
        "--ca",    "/Users/you/warden/certs-dev/ca.crt",
        "--client-hint", "cursor"
      ]
    }
  }
}
```

## OS-specific paths

| OS | Global config |
|---|---|
| macOS | `~/.cursor/mcp.json` |
| Linux | `~/.cursor/mcp.json` |
| Windows | `%USERPROFILE%\.cursor\mcp.json` |

Project-scoped: drop the same file at
`<workspace>/.cursor/mcp.json` — overrides the global entry for
that workspace.

## Verify

Open Cursor → Settings → MCP. The `warden` server should show as
"connected" with a green dot. Fire any tool from chat; the proxy
log lights up with the request, and the ledger captures a row
keyed on the cert's agent_id.

## Known quirks

- **Tool re-discovery on save.** Cursor re-runs the `tools/list` cycle
  whenever `mcp.json` is saved. The bridge handles this transparently
  — `tools/list` is a regular JSON-RPC call through the proxy.
- **Stale process on config change.** Cursor sometimes leaves the old
  bridge process running after a config edit. If a connection refuses
  to refresh, `pkill -f 'wardenctl mcp-bridge'` and re-open the MCP
  panel.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Red dot on MCP panel + log shows "spawn failed" | `command` path is wrong or `wardenctl` is not executable. `chmod +x /usr/local/bin/wardenctl`. |
| Tool list empty | `tools/list` upstream call failed — check proxy + brain are running, and the agent has Vault creds. |
| `warden proxy 403` on every call | Same as Claude Code — Vault entry missing for the agent_id. |
