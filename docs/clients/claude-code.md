# Claude Code → Clavenar

[Claude Code](https://claude.com/claude-code) registers MCP servers
via `~/.claude.json` or per-project `.mcp.json`, both readable via
`claude mcp add` and `claude mcp list`.

## Config

Add a `clavenar` MCP server (project-scoped — drop into
`<project>/.mcp.json`):

```json
{
  "mcpServers": {
    "clavenar": {
      "command": "/usr/local/bin/clavenarctl",
      "args": [
        "mcp-bridge",
        "--url",   "https://localhost:19443",
        "--cert",  "/home/you/clavenar/certs-dev/client.crt",
        "--key",   "/home/you/clavenar/certs-dev/client.key",
        "--ca",    "/home/you/clavenar/certs-dev/ca.crt",
        "--client-hint", "claude-code"
      ]
    }
  }
}
```

Or use the CLI helper:

```bash
claude mcp add clavenar /usr/local/bin/clavenarctl -- \
  mcp-bridge \
  --url   https://localhost:19443 \
  --cert  /home/you/clavenar/certs-dev/client.crt \
  --key   /home/you/clavenar/certs-dev/client.key \
  --ca    /home/you/clavenar/certs-dev/ca.crt \
  --client-hint claude-code
```

> **Dev shortcut.** Add `--insecure` to the args list if you're against
> a dev stack with a CN-only `server.crt`. The hash `gen_certs.sh`
> already mints proper SANs as of v0.20.0; this flag is left over for
> pre-rotation cert bundles. **Never pass `--insecure` against prod.**

## Verify

```bash
claude mcp list     # clavenar should appear in the active list
```

Then in a Claude Code session, hit any tool that talks to the
`clavenar` server (e.g. `list_resources`). The proxy log shows the
inbound call:

```text
INFO clavenar_proxy::mtls: agent_id=agent-001 method=list_resources
```

and the ledger captures a row at `/audit/agent-001`.

## Known quirks

- **protocolVersion negotiation.** Claude Code 2.1.x sends
  `"protocolVersion": "2025-11-25"`. The bridge passes this through;
  the upstream `clavenar-init-stub` echoes it back verbatim. Older
  Claude Code (≤2.0.x) sends `"2024-11-05"` — same flow, no
  divergence required.
- **Notifications.** Claude Code emits `notifications/initialized`
  immediately after the `initialize` round-trip. The bridge fire-
  and-forgets per JSON-RPC §4.1; no response is expected.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Failed to connect` in Claude Code's MCP panel | Bridge can't reach the proxy URL | `curl -k https://localhost:19443/health` from the same shell that runs Claude Code; check `--url` host:port. |
| `error: clavenar proxy 401` | mTLS cert rejected at proxy ingress | Confirm `--cert`/`--key`/`--ca` paths; CA must be the one that signed the proxy's `server.crt`. |
| `error: clavenar proxy 403 — No credentials found for agent ...` | Vault is missing the agent_id entry | See [README.md — Shared prerequisites](README.md#shared-prerequisites). |
| Tool returns immediately with no output | Bridge stdout flush stuck (rare; pre-v0.21 issue) | Upgrade clavenarctl. |
