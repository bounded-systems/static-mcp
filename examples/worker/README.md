# Example: remote verified-static MCP on Cloudflare Workers

Hosts [`@bounded-systems/static-mcp`](../../) as a **remote** MCP endpoint over
Streamable HTTP. Clients connect by URL — no local install, no subprocess.

```
src/index.ts     spec + config → createHttpHandler → Worker `fetch` (serves /mcp)
wrangler.jsonc   Worker config (nodejs_compat; per-response verify via Web Crypto)
```

## Deploy

```bash
cd examples/worker
npm install
npx wrangler login      # one-time, opens a browser for your Cloudflare account
npx wrangler deploy
```

`wrangler deploy` prints the URL, e.g. `https://example-remote-mcp.<account>.workers.dev`.
The MCP endpoint is that URL + `/mcp`.

## Connect a client by URL

Point any MCP client at the Streamable HTTP endpoint:

```jsonc
// Claude Code / Claude Desktop style config
{
  "mcpServers": {
    "example-remote": {
      "type": "http",
      "url": "https://example-remote-mcp.<account>.workers.dev/mcp"
    }
  }
}
```

Or with the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector
# Transport: Streamable HTTP · URL: https://…workers.dev/mcp
```

## Verification model (read this)

- **Per-response content integrity — every request.** Each tool/resource result
  is SHA-256'd with **Web Crypto** and required to equal the origin's signed
  `site.sha256` manifest entry before it is returned. Tamper / stale edge / a
  path that isn't a signed artifact ⇒ an error, not a response.
- **Manifest authenticity — at deploy, not per request.** The manifest's
  Sigstore signature is **not** re-verified inside the Worker (sigstore-js needs
  TUF + Node crypto/fs, which don't run there). It is trusted as verified at
  deploy time — hence `signatureMode: "off"`. For per-request signature
  verification, use the stdio/Node transport (`serveVerifiedStaticMcp`).
