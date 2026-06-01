# Generic stdio MCP client → Clavenar

Any client that speaks the MCP `2024-11-05` or `2025-11-25` protocol
over stdio can ride the bridge. This recipe is the fallback for
clients that don't have a dedicated page above — or for ad-hoc
testing without a real client at all.

## Manual stdio session

`clavenarctl mcp-bridge` reads JSON-RPC frames from stdin and writes
responses to stdout. Drive it by hand:

```bash
clavenarctl mcp-bridge \
  --url   https://localhost:19443 \
  --cert  ./certs-dev/client.crt \
  --key   ./certs-dev/client.key \
  --ca    ./certs-dev/ca.crt \
  --client-hint generic <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
EOF
```

Expected output: one response per request line (initialize +
tools/list), with the `notifications/initialized` line drawing no
response per JSON-RPC §4.1.

## Wiring into a custom MCP client

If you're embedding the bridge into a custom agent runtime, treat
it as a stdio subprocess:

```python
import json, subprocess, sys

p = subprocess.Popen(
    [
        "clavenarctl", "mcp-bridge",
        "--url",   "https://localhost:19443",
        "--cert",  "/path/to/client.crt",
        "--key",   "/path/to/client.key",
        "--ca",    "/path/to/ca.crt",
        "--client-hint", "generic",
    ],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=sys.stderr,
    text=True,
)

def call(req):
    p.stdin.write(json.dumps(req) + "\n")
    p.stdin.flush()
    if "id" in req:
        return json.loads(p.stdout.readline())
    return None  # notification

call({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2025-11-25", "capabilities": {}}})
call({"jsonrpc": "2.0", "method": "notifications/initialized"})
print(call({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
```

## Protocol contract

The bridge enforces the MCP-spec wire shape on the way through, but
your client is responsible for:

- **JSON-RPC 2.0 envelope.** Every request needs
  `"jsonrpc": "2.0"`, a `method`, and (for non-notifications) an `id`.
- **Notification policy.** Methods named `notifications/*` or any
  frame lacking an `id` are fire-and-forget; the bridge POSTs them
  upstream but writes nothing to stdout.
- **Initialize handshake.** Send `initialize` first; the upstream
  `clavenar-init-stub` echoes your client's `protocolVersion` so you
  can negotiate whichever version your client supports.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Bridge exits with `parse jsonrpc frame` | Frame on the offending stdin line isn't valid JSON. Check for stray newlines, missing quotes. |
| `upstream 403` on every call | Vault entry missing for the agent_id derived from the cert's SPIFFE URI / CN. See [README.md](README.md#shared-prerequisites). |
| `upstream 401` | Cert chain doesn't validate against the proxy's CA. `openssl verify -CAfile ca.crt client.crt` to confirm locally. |
| Bridge hangs on stdin | Your client isn't writing newline-terminated frames. The bridge reads line-by-line; flush with `\n`. |
