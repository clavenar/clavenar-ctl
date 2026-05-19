# Cline (VS Code) → Agent Warden

[Cline](https://cline.bot) is a VS Code extension that drives an LLM
agent against your editor. It reads MCP server config from
`cline_mcp_settings.json` inside the extension's storage directory.

## Config

Open Cline's settings UI ("Cline: MCP Servers" → "Configure") and
paste:

```json
{
  "mcpServers": {
    "warden": {
      "command": "wardenctl",
      "args": [
        "mcp-bridge",
        "--url",   "https://localhost:19443",
        "--cert",  "/Users/you/warden/certs-dev/client.crt",
        "--key",   "/Users/you/warden/certs-dev/client.key",
        "--ca",    "/Users/you/warden/certs-dev/ca.crt",
        "--client-hint", "cline"
      ],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

The settings file itself lives at:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| Linux | `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| Windows | `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json` |

Leave `autoApprove` empty so every Warden-gated call still surfaces
through Cline's approval UI — defense in depth on top of the proxy's
HIL gate.

## Verify

In Cline's chat: "list available tools from the warden server." The
extension calls `tools/list` through the bridge; output should
include whatever tools the upstream MCP server (`warden-init-stub`
or your own) advertises.

## Known quirks

- **`disabled` flag.** Cline gates server boot on this field. If the
  bridge isn't running and no error appears in Cline's output panel,
  confirm `disabled: false`.
- **`autoApprove` list.** Cline allows pre-approving specific tool
  names; for Warden, leave this empty so Yellow-tier intents still
  hit HIL.
- **VS Code reload required.** Editing `cline_mcp_settings.json`
  directly (not via the UI) needs a window reload — Cline doesn't
  watch the file.

## Troubleshooting

| Symptom | Fix |
|---|---|
| "MCP server not connecting" + Cline output panel shows nothing | `command: wardenctl` must be on PATH for the VS Code process; use an absolute path if your shell's PATH isn't inherited. |
| `warden proxy 403` | Vault entry missing for the agent_id; see [README.md](README.md#shared-prerequisites). |
| Approval dialog appears for every call | Expected — Yellow-tier intents need approval. Add safe tool names to `autoApprove` if Cline's UX gets in the way (Warden's HIL still gates server-side). |
