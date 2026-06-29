/**
 * End-to-end projection test: VerbSpec verbs + a resource catalog → a live MCP
 * server (over an in-memory transport pair), driven by a real MCP client. Proves
 * the verbspec → tools/resources projection, the verified-response `_meta`, and
 * that a tampered manifest is rejected — no network.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  ApiClient,
  buildVerifiedStaticServer,
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
  server: { name: "test-mcp", version: "0.0.0" },
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

async function connect(files: Record<string, string>) {
  const server = buildVerifiedStaticServer(spec, config, new ApiClient(config, fakeFetch(files)));
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([server.connect(serverT), client.connect(clientT)]);
  return { client, server };
}

test("verbs are projected to MCP tools (names + input schema from verbspec)", async () => {
  const { client, server } = await connect(fixture());
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name).sort();
  assert.deepEqual(names, ["get_post", "get_profile"]);
  const getPost = tools.find((t) => t.name === "get_post")!;
  assert.equal((getPost.inputSchema as any).properties.slug.type, "string");
  await server.close();
});

test("resources are projected to MCP resources", async () => {
  const { client, server } = await connect(fixture());
  const { resources } = await client.listResources();
  assert.ok(resources.some((r) => r.uri === "site://profile"));
  await server.close();
});

test("a verb call returns verified content + verification _meta", async () => {
  const { client, server } = await connect(fixture());
  const res: any = await client.callTool({ name: "get_profile", arguments: {} });
  assert.equal(res.content[0].text, '{"headline":"hello"}');
  assert.equal(res.structuredContent.headline, "hello");
  assert.equal(res._meta.verification.matchedSignedManifest, true);
  assert.equal(typeof res._meta.verification.sha256, "string");
  await server.close();
});

test("a tampered artifact is rejected (verb call errors)", async () => {
  const { client, server } = await connect(fixture(true));
  const res: any = await client.callTool({ name: "get_profile", arguments: {} });
  assert.equal(res.isError, true);
  assert.match(JSON.stringify(res.content), /digest mismatch/);
  await server.close();
});

test("a verified resource read carries verification _meta", async () => {
  const { client, server } = await connect(fixture());
  const res: any = await client.readResource({ uri: "site://profile" });
  assert.equal(res.contents[0].text, '{"headline":"hello"}');
  assert.equal(res._meta.verification.matchedSignedManifest, true);
  await server.close();
});
