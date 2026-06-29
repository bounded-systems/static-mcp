/**
 * CLI projection: the SAME verbs that back the MCP tools, run as a CLI via
 * verbspec's parser. Proves the verified bytes come out on stdout, that a
 * tampered artifact fails closed (exit 1, no stdout), and that `--help`/usage
 * work — no network.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
import {
  ApiClient,
  runStaticCli,
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
    if (body === undefined) return new Response("nf", { status: 404, statusText: "Not Found" });
    return new Response(enc(body), { status: 200 });
  }) as unknown as typeof fetch;
}

function fixture(tamper = false) {
  const profile = '{"headline":"hello"}';
  const post = '{"slug":"hi","title":"Hi"}';
  const manifest =
    `${sha256Hex(enc(profile))}  api/v1/profile.json\n` +
    `${sha256Hex(enc(post))}  api/v1/posts/hi.json\n`;
  return {
    "https://example.test/site.sha256": manifest,
    "https://example.test/api/v1/profile.json": tamper ? '{"headline":"EVIL"}' : profile,
    "https://example.test/api/v1/posts/hi.json": post,
  } as Record<string, string>;
}

const spec: StaticMcpSpec = {
  server: { name: "demo", version: "0.0.0" },
  verbs: {
    get_profile: verifiedVerb({
      id: "get_profile",
      summary: "Fetch the verified profile.",
      input: z.object({}),
      resolve: (_i, deps) => deps.apiPath("profile.json"),
    }),
    get_post: verifiedVerb({
      id: "get_post",
      summary: "Fetch a post by slug.",
      input: z.object({ slug: z.string().min(1) }),
      positionals: ["slug"],
      resolve: ({ slug }, deps) => deps.apiPath(`posts/${slug}.json`),
    }),
  },
};

const run = (argv: string[], files = fixture()) =>
  runStaticCli(spec, config, argv, new ApiClient(config, fakeFetch(files)));

test("a verb prints the verified bytes on stdout (exit 0)", async () => {
  const r = await run(["get_profile"]);
  assert.equal(r.code, 0);
  assert.equal(r.stdout, '{"headline":"hello"}');
});

test("a positional argument is parsed from the same verb", async () => {
  const r = await run(["get_post", "hi"]);
  assert.equal(r.code, 0);
  assert.equal(JSON.parse(r.stdout).slug, "hi");
});

test("a tampered artifact fails closed (exit 1, no stdout)", async () => {
  const r = await run(["get_profile"], fixture(true));
  assert.equal(r.code, 1);
  assert.equal(r.stdout, "");
  assert.match(r.stderr, /digest mismatch/);
});

test("usage lists every verb; unknown command exits 1", async () => {
  const help = await run([]);
  assert.equal(help.code, 1);
  assert.match(help.stdout, /get_profile/);
  assert.match(help.stdout, /get_post/);
  const bad = await run(["nope"]);
  assert.equal(bad.code, 1);
  assert.match(bad.stderr, /unknown command: nope/);
});

test("--help on a verb prints its usage", async () => {
  const r = await run(["get_post", "--help"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /get_post/);
});
