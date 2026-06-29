import { test } from "node:test";
import assert from "node:assert/strict";
import {
  assertMatchesManifest,
  parseManifest,
  sha256Hex,
  VerificationError,
} from "../src/index.js";

const enc = (s: string) => new TextEncoder().encode(s);

test("parseManifest handles text- and binary-mode separators", () => {
  const a = sha256Hex(enc("a"));
  const b = sha256Hex(enc("b"));
  const text = `${a}  api/v1/profile.json\n${b} *blog.html\n\n`;
  const m = parseManifest(text);
  assert.equal(m.size, 2);
  assert.equal(m.get("api/v1/profile.json"), a);
  assert.equal(m.get("blog.html"), b);
});

test("parseManifest rejects an empty manifest", () => {
  assert.throws(() => parseManifest("\n\n"), VerificationError);
});

test("assertMatchesManifest passes on a correct digest", () => {
  const bytes = enc('{"ok":true}');
  const m = parseManifest(`${sha256Hex(bytes)}  api/v1/profile.json`);
  const v = assertMatchesManifest(m, "api/v1/profile.json", bytes);
  assert.equal(v.actual, v.expected);
});

test("assertMatchesManifest throws on a tampered byte", () => {
  const m = parseManifest(`${sha256Hex(enc("clean"))}  api/v1/profile.json`);
  assert.throws(
    () => assertMatchesManifest(m, "api/v1/profile.json", enc("tampered")),
    /digest mismatch/,
  );
});

test("assertMatchesManifest throws when path is not in the manifest", () => {
  const m = parseManifest(`${sha256Hex(enc("x"))}  blog.html`);
  assert.throws(
    () => assertMatchesManifest(m, "api/v1/secret.json", enc("x")),
    /no manifest entry/,
  );
});
