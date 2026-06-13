# Connect an MCP client to Clavenar

There are two ways in, and the proxy now speaks the native MCP
control plane (`initialize` / `tools/list` / `ping` / `notifications/*`)
on both editions:

- **Native HTTP MCP** — a client that can add a *streamable-HTTP* MCP
  server points straight at the proxy's `/mcp` URL over mTLS. No shim:
  the proxy IS a spec-compliant MCP server, and with
  `CLAVENAR_PROXY_STREAMING=true` it relays an upstream's
  `text/event-stream` responses chunk-by-chunk (with sampled,
  detect-after-relay egress scanning).
- **stdio bridge** — a client that only drives a *stdio* MCP server (the
  common case for IDE plugins today) reaches `/mcp` through the
  `clavenarctl mcp-bridge` shim. The bridge speaks newline-delimited
  JSON-RPC on stdin / stdout and forwards each frame over mTLS. It is a
  **buffered** leg: a streamed (SSE) upstream response is collected
  before it reaches the stdio client, so the chunk-by-chunk relay above
  is a native-HTTP-only property.

The per-client recipes below are all the **same bridge command** — they
differ **only in the config-file shape** (where the client expects its
`mcpServers` definition to live). A native-HTTP client skips the bridge
entirely and uses the proxy URL directly.

| Client | Recipe | Tested on |
|---|---|---|
| Claude Code (Anthropic) | [claude-code.md](claude-code.md) | macOS / Linux |
| Cursor | [cursor.md](cursor.md) | macOS / Linux / Windows |
| Cline (VS Code extension) | [cline.md](cline.md) | VS Code on macOS / Linux / Windows |
| Continue.dev | [continue.md](continue.md) | VS Code + JetBrains |
| OpenAI Codex CLI | [codex.md](codex.md) | macOS / Linux |
| Generic stdio MCP | [generic-stdio.md](generic-stdio.md) | any client speaking MCP 2024-11-05 / 2025-11-25 |

## Shared prerequisites

Every recipe assumes you already have:

1. **A clavenar stack reachable over mTLS** — `prod` at
   `https://proxy.clavenar.local:8086` or `dev` at `https://localhost:19443`.
2. **A client cert pair** issued by the clavenar CA, with the agent's
   SPIFFE URI in the SAN (or CN fallback). Mint one for the smoke
   flow with:
   ```bash
   cd repos/clavenar-proxy && ./scripts/gen_certs.sh --env dev
   # → certs-dev/client.crt + client.key + ca.crt
   ```
   For real agents, use
   `clavenarctl agents create <name>` to enroll and have
   `clavenar-identity` mint a short-lived SVID.
3. **Vault stub credentials for the agent_id** — the proxy gates every
   request on the presence of a Vault entry:
   ```bash
   curl -H 'X-Vault-Token: root' -X POST \
        http://localhost:18200/v1/secret/data/agents/<agent-id> \
        -d '{"data":{"api_key":"stub-key"}}'
   ```
   The api_key is opaque to the proxy — it just gates "has credentials"
   vs "doesn't."

## Verification path (every recipe)

After wiring the config and starting the client:

1. Fire one tool call from the client (`list_resources` works for any
   MCP server — it's universal).
2. Tail the proxy or brain log — you should see the request flow
   through with the correlation_id stamped in.
3. Query the ledger:
   ```bash
   curl -s http://localhost:18083/audit/<agent-id> | jq '.[0]'
   ```
   A row exists with `correlation_id` matching the proxy's log line,
   `agent_id` matching the cert's SPIFFE/CN identity.
4. `curl -s http://localhost:18083/verify` returns `{"valid":true}`.

## `--client-hint` flag

`clavenarctl mcp-bridge` accepts `--client-hint <name>` where `<name>`
is one of `claude-code`, `cursor`, `cline`, `continue`, `codex`,
`generic`. Today the flag is **informational only** — the bridge
logs the hint to stderr at boot and passes JSON-RPC frames verbatim.
The flag reserves the surface for per-client quirks if any emerge
in the wild; recipes pass it for forward-compat.
