/**
 * Remote-transport test: drive `createHttpHandler` (Streamable HTTP) entirely
 * in-process with hand-crafted Web-standard `Request`s — initialize, list tools,
 * call a verified tool, read a verified resource — and prove a tampered manifest
 * is rejected per-request. No network, no server socket: the handler IS the MCP
 * endpoint a Worker would expose. Verification here runs on the Web-Crypto hash
 * path (`sha256HexWebCrypto`), the same code a Cloudflare Worker executes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
import {
  createHttpHandler,
  sha256Hex,
  type StaticMcpSpec,
  verifiedVerb,
  withDefaults,
} from "../src/index.js";

const enc = (s: string) => new TextEncoder().encode(s);

const config = withDefaults({
  baseUrl: "https://example.test",
  expectedSignerIdentity: "id",
  expectedSignerIssuer: "iss",
});

function fakeFetch(files: Record<string, string>): typeof fetch {
  return (async (input: any) => {
    const url = typeof input === "string" ? input : input.url;
    const body = files[url];
    if (body === undefined) {
      return new Response("not found", { status: 404, statusText: "Not Found" });
    }
    return new Response(enc(body), { status: 200 });
  }) as unknown as typeof fetch;
}

function fixture(tamper = false) {
  const profile = '{"headline":"hello"}';
  const posts = '{"items":[{"slug":"hi","title":"Hi","summary":"s"}]}';
  const manifest =
    `${sha256Hex(enc(profile))}  api/v1/profile.json\n` +
    `${sha256Hex(enc(posts))}  api/v1/posts.json\n`;
  return {
    "https://example.test/site.sha256": manifest,
    "https://example.test/api/v1/profile.json": tamper ? '{"headline":"EVIL"}' : profile,
    "https://example.test/api/v1/posts.json": posts,
  } as Record<string, string>;
}

const spec: StaticMcpSpec = {
  server: { name: "test-http-mcp", version: "0.0.0" },
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
      resolve: ({ slug }, deps) => deps.apiPath(`${slug}.json`),
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

const PROTOCOL_VERSION = "2025-06-18";

/** POST a JSON-RPC message to the handler and parse the JSON response. */
async function rpc(
  handler: (req: Request) => Promise<Response>,
  body: unknown,
): Promise<{ status: number; json: any }> {
  const res = await handler(
    new Request("https://worker.test/mcp", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-protocol-version": PROTOCOL_VERSION,
      },
      body: JSON.stringify(body),
    }),
  );
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

const initBody = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: "test-client", version: "0.0.0" },
  },
};

test("initialize over HTTP returns the server identity", async () => {
  const handler = createHttpHandler(spec, config, { fetchImpl: fakeFetch(fixture()) });
  const { status, json } = await rpc(handler, initBody);
  assert.equal(status, 200);
  assert.equal(json.result.serverInfo.name, "test-http-mcp");
  assert.equal(json.result.protocolVersion, PROTOCOL_VERSION);
});

test("tools/list over HTTP projects the verbs", async () => {
  const handler = createHttpHandler(spec, config, { fetchImpl: fakeFetch(fixture()) });
  await rpc(handler, initBody); // each POST is its own stateless transport
  const { json } = await rpc(handler, { jsonrpc: "2.0", id: 2, method: "tools/list" });
  const names = json.result.tools.map((t: any) => t.name).sort();
  assert.deepEqual(names, ["get_post", "get_profile"]);
});

test("tools/call over HTTP returns verified content + verification _meta", async () => {
  const handler = createHttpHandler(spec, config, { fetchImpl: fakeFetch(fixture()) });
  await rpc(handler, initBody);
  const { json } = await rpc(handler, {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "get_profile", arguments: {} },
  });
  assert.equal(json.result.content[0].text, '{"headline":"hello"}');
  assert.equal(json.result.structuredContent.headline, "hello");
  assert.equal(json.result._meta.verification.matchedSignedManifest, true);
  assert.equal(typeof json.result._meta.verification.sha256, "string");
});

test("resources/read over HTTP carries verification _meta", async () => {
  const handler = createHttpHandler(spec, config, { fetchImpl: fakeFetch(fixture()) });
  await rpc(handler, initBody);
  const { json } = await rpc(handler, {
    jsonrpc: "2.0",
    id: 4,
    method: "resources/read",
    params: { uri: "site://profile" },
  });
  assert.equal(json.result.contents[0].text, '{"headline":"hello"}');
  assert.equal(json.result._meta.verification.matchedSignedManifest, true);
});

test("a tampered artifact is rejected over HTTP (verified per-request)", async () => {
  const handler = createHttpHandler(spec, config, { fetchImpl: fakeFetch(fixture(true)) });
  await rpc(handler, initBody);
  const { json } = await rpc(handler, {
    jsonrpc: "2.0",
    id: 5,
    method: "tools/call",
    params: { name: "get_profile", arguments: {} },
  });
  assert.equal(json.result.isError, true);
  assert.match(JSON.stringify(json.result.content), /digest mismatch/);
});

test("non-JSON Accept header is rejected (Streamable HTTP contract)", async () => {
  const handler = createHttpHandler(spec, config, { fetchImpl: fakeFetch(fixture()) });
  const res = await handler(
    new Request("https://worker.test/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "text/plain" },
      body: JSON.stringify(initBody),
    }),
  );
  assert.equal(res.status, 406);
});
