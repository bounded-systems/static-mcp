# @bounded-systems/static-mcp

Serve [`@bounded-systems/verbspec`](https://jsr.io/@bounded-systems/verbspec)
verbs as a **read-only, Sigstore-verified static-response
[MCP](https://modelcontextprotocol.io) server**.

This is the generic core: you inject **where** the signed static origin lives
and **how strictly** to check its signature, plus the **verbs** (→ MCP tools)
and a **resource catalog** (→ MCP resources). Every resource read and every tool
call routes through a verifying client that SHA-256s the bytes a client would
receive and requires them to equal the entry in the origin's signed `sha256`
manifest **before returning anything**. A mismatch — a MITM, a stale CDN edge, a
tampered file, or a path that isn't a signed artifact — is an error, not a
response. There are no write/mutating surfaces.

It carries **no origin-specific values**. A thin implementation (e.g.
[`@bdelanghe/site-mcp`](https://github.com/bdelanghe/site-mcp)) supplies the
config, the verbs, and the catalog, and calls one function.

## Install

Published to **both** registries so either ecosystem can consume it:

```bash
# Deno / JSR-native
deno add jsr:@bounded-systems/static-mcp

# Node / npm (its JSR-only deps come from JSR via the npm bridge — see .npmrc)
npm install @bounded-systems/static-mcp
```

> **Why both?** The Bounded Systems libraries (`verbspec`, `verify`, `lone`)
> publish to JSR. `static-mcp` does too — but it is consumed by Node MCP servers
> (`site-mcp`), so it also ships to npm. Its JSR-only dependencies,
> `@bounded-systems/verbspec` and `@bounded-systems/verify`, are pulled into Node
> via JSR's npm bridge (`@jsr:registry=https://npm.jsr.io` in `.npmrc`).

## Use

Author each surface once as a `verbspec` `VerbSpec`, then hand the verbs +
resources + config to the core:

```ts
import { z } from "zod";
import {
  serveVerifiedStaticMcp,
  verifiedVerb,
  withDefaults,
  type StaticMcpSpec,
} from "@bounded-systems/static-mcp";

const config = withDefaults({
  baseUrl: "https://example.dev",
  expectedSignerIdentity:
    "https://github.com/me/site/.github/workflows/deploy.yml@refs/heads/main",
  expectedSignerIssuer: "https://token.actions.githubusercontent.com",
  // signatureMode defaults to "off"; "warn" | "require" enable Sigstore checks.
});

const spec: StaticMcpSpec = {
  server: { name: "example-mcp", version: "1.0.0" },
  verbs: {
    // A VerbSpec whose `run` fetches + verifies one artifact and returns it.
    get_profile: verifiedVerb({
      id: "get_profile",
      summary: "Fetch the verified profile.",
      input: z.object({}),
      resolve: (_input, deps) => deps.apiPath("profile.json"),
    }),
    get_post: verifiedVerb({
      id: "get_post",
      summary: "Fetch a single post by slug.",
      input: z.object({ slug: z.string().min(1) }),
      resolve: ({ slug }, deps) => deps.apiPath(`posts/${slug}.json`),
    }),
  },
  resources: [
    {
      uri: "site://profile",
      name: "profile",
      description: "Identity tokens.",
      path: "api/v1/profile.json",
    },
  ],
};

await serveVerifiedStaticMcp(spec, config); // stdio transport
```

The MCP tool name, description, and input schema for each verb are **projected**
from the same `VerbSpec` via `verbspec`'s `toMcpTool`, so the tool surface can
never drift from the verb. Resource reads and tool results carry a
`_meta.verification` block (manifest-relative path, source URL, the verified
`sha256`, and the manifest signature status).

### Two surfaces, one definition

`verbspec` projects each verb to **both** an MCP tool and a CLI subcommand. The
same `spec.verbs` therefore also drive a CLI — `runStaticCli(spec, config, argv)`
reuses verbspec's `parseArgs`/`toHelp` to resolve a subcommand, validate argv
against the verb's Zod input (the exact schema the MCP tool enforces), run it
through the verifying client, and print the verified bytes. A verification
failure exits non-zero with nothing on stdout. One verb set, two surfaces, no
drift:

```ts
const { stdout, stderr, code } = await runStaticCli(spec, config, ["get_post", "slug-here"]);
```

### Remote transport (Streamable HTTP — host it, connect by URL)

`serveVerifiedStaticMcp` is the **local** transport (stdio — the client spawns a
subprocess). `createHttpHandler` is the **remote** transport: a Web-standard
`(Request) => Response` handler that serves the *same* verified-static MCP over
HTTP ([MCP Streamable HTTP](https://modelcontextprotocol.io)), so clients connect
by **URL** — no local install. It runs anywhere the Fetch API does: a
**Cloudflare Worker** `fetch` handler, Deno/Bun, or Node 18+.

```ts
import { createHttpHandler } from "@bounded-systems/static-mcp";

// same `spec` + `config` as above
const handler = createHttpHandler(spec, config); // (Request) => Promise<Response>

// Cloudflare Worker entry:
export default { fetch: (req: Request) => handler(req) };
```

It reuses the exact same verbs, resource catalog, and verifying client as the
stdio transport — every response is still matched byte-for-byte against the
signed manifest. The only differences are runtime-shaped:

- the per-response SHA-256 runs on **Web Crypto** (`crypto.subtle`), so it needs
  no `node:crypto` and works inside a Worker; and
- it is **stateless** — a fresh MCP server + transport per request, while the
  verifying client (and its cached manifest) is shared across requests in a warm
  isolate.

#### Deploy to Cloudflare Workers

A complete example lives in [`examples/worker/`](./examples/worker) (a
`wrangler.jsonc` + a Worker entry that serves the MCP at `/mcp`):

```bash
cd examples/worker
npm install
npx wrangler login       # one-time
npx wrangler deploy      # prints https://<worker>.<account>.workers.dev
```

The MCP endpoint is that URL + `/mcp`. Point any MCP client at it as a
**Streamable HTTP** server:

```jsonc
{
  "mcpServers": {
    "example-remote": {
      "type": "http",
      "url": "https://<worker>.<account>.workers.dev/mcp"
    }
  }
}
```

#### Remote verification model (honest + deliberately weaker than stdio)

The remote transport proves **content integrity per request** and trusts
**manifest authenticity as established at deploy time** — not per request:

- **Per-response content integrity — always, every request.** Each tool/resource
  result is SHA-256'd (Web Crypto) and required to equal the origin's signed
  `site.sha256` manifest entry before it is returned. A MITM, a stale CDN edge, a
  tampered file, or a path that isn't a signed artifact ⇒ a `VerificationError`,
  not a response.
- **Manifest signature — at deploy, not per request.** The manifest's Sigstore
  signature is **not** re-verified inside a Worker: `@bounded-systems/verify` →
  sigstore-js needs TUF + Node `crypto`/`fs`, which don't run there (and it is
  lazy-imported, so it never enters the Worker bundle). It is trusted as verified
  at deploy time — the same signed bytes the origin already serves. Hence the
  remote default is `signatureMode: "off"`.

> For **per-request** signature verification (the full Sigstore check on every
> call), use the stdio/Node transport (`serveVerifiedStaticMcp`) with
> `signatureMode: "warn" | "require"`.

## API

| Export | What it is |
| --- | --- |
| `serveVerifiedStaticMcp(spec, config)` | **Local transport.** Build the server and serve it over **stdio**. The one-call entry. |
| `createHttpHandler(spec, config, options?)` | **Remote transport.** A `(Request) => Promise<Response>` Streamable-HTTP handler for Cloudflare Workers / Deno / Bun / Node — clients connect by URL. |
| `buildVerifiedStaticServer(spec, config, client?)` | Build (don't connect) the `McpServer` — for tests / embedding. |
| `runStaticCli(spec, config, argv, client?)` | Run the same verbs as a CLI; returns `{ stdout, stderr, code }`. |
| `verifiedVerb({ id, summary, input, resolve })` | Author a `VerbSpec` that fetches + verifies one artifact. |
| `withDefaults(input)` | Fill the generic, non-origin defaults around a `ConfigInput`. |
| `ApiClient` | The verifying client: `getVerified(path)` returns a `VerifiedArtifact` or throws. Takes an optional `(config, fetch?, hash?)`. |
| `parseManifest`, `assertMatchesManifest`, `compareDigestToManifest`, `sha256Hex`, `sha256HexWebCrypto` | The manifest / hash-check primitives. `sha256HexWebCrypto` is the Worker-safe (Web Crypto) digest. |
| `verifyManifestSignature` | Optional Sigstore check of the manifest bundle (lazy-delegates to `@bounded-systems/verify`). |
| `VerificationError` | Thrown when bytes don't match (or aren't in) the signed manifest. |
| Types | `Config`, `ConfigInput`, `StaticMcpSpec`, `HttpHandlerOptions`, `HashFn`, `VerifiedResource`, `VerifiedResourceTemplate`, `StaticDeps`, `VerifiedArtifact`, `Manifest`, `ServerInfo` |
| Re-exports | `defineVerb`, `toMcpTool`, `toMcpToolset`, `verbToken`, and verbspec types |

### `Config`

`baseUrl`, `apiPrefix`, `manifestPath`, `signaturePath`, `signatureMode`
(`off` \| `warn` \| `require`), `expectedSignerIdentity`,
`expectedSignerIssuer`, `fetchTimeoutMs`. `withDefaults` supplies the mechanical
conventions (`api/v1`, `site.sha256`, `site.sha256.sigstore.json`, `off`,
`15000`); the consumer must supply `baseUrl` and the expected signer identity —
those carry the origin's identity, which the core never hard-codes.

## Trust model

1. **Per-file hash check (always on).** Fetch `manifestPath` once per process
   (`sha256sum` format — `<digest>  <path>`, one line per published file). For
   every artifact: fetch it, SHA-256 the received bytes, and require that digest
   to equal the manifest entry. Mismatch → `VerificationError`, no response. A
   path absent from the manifest is refused — it isn't a signed artifact.
2. **Manifest signature check (optional).** With `signatureMode` `warn` or
   `require`, verify the Sigstore bundle over the manifest against the expected
   GitHub Actions workflow identity, anchoring the manifest to the build that
   produced it.

   > **Backend — [`@bounded-systems/verify`](https://jsr.io/@bounded-systems/verify).**
   > As of `verify@0.2.0` this check is **delegated** to verify's exported
   > `verifyManifestBundle({ bundle, manifest, identity, issuer })` — the canonical
   > in-process Sigstore-bundle verifier (`sigstore.verify(bundle, manifest, …)` +
   > a cosign-style cert-SAN identity + issuer match). static-mcp is verify's first
   > real consumer; it no longer carries its own copy of the check, and the direct
   > `sigstore` dependency is dropped (verify pulls it transitively). static-mcp
   > keeps only its own manifest parse + per-file sha256 match.

## Development

```bash
npm install
npm run build       # tsc → dist/
npm test            # node --test via tsx (engine + projection; no network)
deno check src/index.ts
deno publish --dry-run --allow-dirty
npm pack --dry-run
```

## Publishing

Published by [`publish.yml`](./.github/workflows/publish.yml) to **JSR** and
**npm** using **keyless OIDC** (no stored tokens) on a `v*` tag. JSR trusts the
GitHub repo; npm uses trusted publishing + provenance. One-time setup links the
repo/workflow on each registry.

## License

MIT — see [LICENSE](./LICENSE).
