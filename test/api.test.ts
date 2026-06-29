import { test } from "node:test";
import assert from "node:assert/strict";
import { ApiClient, sha256Hex, VerificationError, withDefaults } from "../src/index.js";

const enc = (s: string) => new TextEncoder().encode(s);

const config = withDefaults({
  baseUrl: "https://example.test",
  expectedSignerIdentity: "https://example.test/.github/workflows/deploy.yml@refs/heads/main",
  expectedSignerIssuer: "https://token.actions.githubusercontent.com",
});

/** Build a fake fetch backed by an in-memory {url -> body} map. */
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

function fixture() {
  const profile = '{"headline":"hello","label":"Engineer"}';
  const posts = '{"count":1,"items":[{"slug":"hi","title":"Hi","summary":"s"}]}';
  const manifest =
    `${sha256Hex(enc(profile))}  api/v1/profile.json\n` +
    `${sha256Hex(enc(posts))}  api/v1/posts.json\n`;
  return {
    profile,
    posts,
    files: {
      "https://example.test/site.sha256": manifest,
      "https://example.test/api/v1/profile.json": profile,
      "https://example.test/api/v1/posts.json": posts,
    } as Record<string, string>,
  };
}

test("withDefaults strips a trailing slash and keeps generic conventions", () => {
  const c = withDefaults({
    baseUrl: "https://x.test/",
    expectedSignerIdentity: "id",
    expectedSignerIssuer: "iss",
  });
  assert.equal(c.baseUrl, "https://x.test");
  assert.equal(c.apiPrefix, "api/v1");
  assert.equal(c.manifestPath, "site.sha256");
  assert.equal(c.signatureMode, "off");
});

test("getVerified returns parsed JSON when bytes match the manifest", async () => {
  const fx = fixture();
  const client = new ApiClient(config, fakeFetch(fx.files));
  const artifact = await client.getVerified("api/v1/profile.json");
  assert.deepEqual(artifact.json, { headline: "hello", label: "Engineer" });
  assert.equal(artifact.verification.actual, artifact.verification.expected);
  assert.equal(artifact.url, "https://example.test/api/v1/profile.json");
});

test("getVerified throws VerificationError when the served bytes are tampered", async () => {
  const fx = fixture();
  fx.files["https://example.test/api/v1/profile.json"] = '{"headline":"EVIL"}';
  const client = new ApiClient(config, fakeFetch(fx.files));
  await assert.rejects(
    () => client.getVerified("api/v1/profile.json"),
    VerificationError,
  );
});

test("getVerified throws when path is absent from the signed manifest", async () => {
  const fx = fixture();
  fx.files["https://example.test/api/v1/corpus.json"] = "{}";
  const client = new ApiClient(config, fakeFetch(fx.files));
  await assert.rejects(
    () => client.getVerified("api/v1/corpus.json"),
    /no manifest entry/,
  );
});

test("getManifest is cached (fetched once across calls)", async () => {
  const fx = fixture();
  let manifestFetches = 0;
  const counting: typeof fetch = (async (input: any) => {
    const url = typeof input === "string" ? input : input.url;
    if (url.endsWith("/site.sha256")) manifestFetches++;
    return fakeFetch(fx.files)(input);
  }) as unknown as typeof fetch;
  const client = new ApiClient(config, counting);
  await client.getVerified("api/v1/profile.json");
  await client.getVerified("api/v1/posts.json");
  assert.equal(manifestFetches, 1);
});
