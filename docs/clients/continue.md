# Continue.dev → Clavenar

[Continue](https://continue.dev) is an open-source AI-coding assistant
shipping as a VS Code and JetBrains extension. It reads MCP server
config from `~/.continue/config.json` under the
`experimental.modelContextProtocolServers` key (renamed to
`mcpServers` in the v0.10+ stable schema).

## Config

`~/.continue/config.json`:

```json
{
  "mcpServers": [
    {
      "name": "clavenar",
      "transport": {
        "type": "stdio",
        "command": "clavenarctl",
        "args": [
          "mcp-bridge",
          "--url",   "https://localhost:19443",
          "--cert",  "/Users/you/clavenar/certs-dev/client.crt",
          "--key",   "/Users/you/clavenar/certs-dev/client.key",
          "--ca",    "/Users/you/clavenar/certs-dev/ca.crt",
          "--client-hint", "continue"
        ]
      }
    }
  ]
}
```

Continue accepts `mcpServers` as an **array** of objects, in contrast
to Claude Code / Cursor / Cline's keyed map. Make sure you're editing
the array, not converting it.

## OS-specific paths

`~/.continue/config.json` on every OS — Continue normalizes the
location across macOS / Linux / Windows (`%USERPROFILE%\.continue\`).

## Verify

After save, Continue auto-loads new MCP servers on next chat turn.
In the chat panel, type "what tools do you see from the clavenar
server?" Continue calls `tools/list` and renders the response.

## Known quirks

- **Schema versioning.** Pre-v0.10 (Apr 2025) used
  `experimental.modelContextProtocolServers`. Upgrade Continue or
  adjust the key name; v0.10+ supports both during the deprecation
  window.
- **Transport `type` required.** Unlike Claude Code's flat shape,
  Continue requires the explicit `"type": "stdio"` discriminator —
  http and websocket transports are also schema-valid but not
  supported against Clavenar.
- **JetBrains plugin.** Same config file; JetBrains reads from the
  same path. No JetBrains-specific tweaks required.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Continue ignores the entry | Wrong schema key — confirm `mcpServers` (array) for v0.10+, or `experimental.modelContextProtocolServers` for older. |
| `Failed to start MCP server` | `command` not on PATH for the IDE process — use an absolute path. |
| `tools/list` returns empty | Upstream MCP server itself is empty; verify against `clavenarctl mcp-bridge` over a manual stdio session before blaming Continue. |
