/**
 * Example Cloudflare Worker: host a verified-static MCP as a *remote* endpoint.
 *
 * Clients connect by URL (e.g. `https://<your-worker>.workers.dev/mcp`) over MCP
 * Streamable HTTP — no local install, no subprocess. Every tool/resource result
 * is still SHA-256-verified against the origin's signed `site.sha256` manifest
 * before it is returned, using Web Crypto (so it runs in the Worker).
 *
 * Verification model (see the package README, "Remote transport"):
 *   • per-response content integrity is checked on every request (Web Crypto);
 *   • the manifest's Sigstore signature is trusted as verified at deploy time —
 *     hence `signatureMode: "off"` here (sigstore-js does not run in a Worker).
 *
 * Deploy:
 *   cd examples/worker
 *   npm install
 *   npx wrangler deploy
 */
import { z } from "zod";
import {
  createHttpHandler,
  type StaticMcpSpec,
  verifiedVerb,
  withDefaults,
} from "@bounded-systems/static-mcp";

// Where the signed static origin lives + how strictly to check it. For the
// remote/Worker transport keep `signatureMode: "off"` — manifest authenticity is
// established at deploy, and every response is still hash-verified per request.
const config = withDefaults({
  baseUrl: "https://example.dev",
  expectedSignerIdentity:
    "https://github.com/me/site/.github/workflows/deploy.yml@refs/heads/main",
  expectedSignerIssuer: "https://token.actions.githubusercontent.com",
  // signatureMode defaults to "off".
});

// The verbs (→ MCP tools) and resources (→ MCP resources). Authored once as
// VerbSpecs; the tool surface is projected from them, so it cannot drift.
const spec: StaticMcpSpec = {
  server: { name: "example-remote-mcp", version: "1.0.0" },
  verbs: {
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

// One handler, reused across requests (the shared ApiClient caches the signed
// manifest within a warm isolate; a fresh MCP server/transport is built per
// request, as stateless Streamable HTTP requires).
const handler = createHttpHandler(spec, config);

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/mcp") {
      return handler(request);
    }
    return new Response(
      "Verified-static MCP. Connect an MCP client to /mcp (Streamable HTTP).\n",
      { status: 200, headers: { "content-type": "text/plain" } },
    );
  },
};
