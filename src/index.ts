/**
 * `@bounded-systems/static-mcp` — serve `@bounded-systems/verbspec` verbs as a
 * **Sigstore-verified static-response MCP server**.
 *
 * This is the generic, site-agnostic core extracted from `site-mcp`. It is a
 * pure function of two things you inject:
 *
 *   - a {@link Config} (where the signed static origin lives + how strictly to
 *     check its Sigstore signature), and
 *   - a {@link StaticMcpSpec} (the VerbSpec verbs → MCP tools, plus a resource
 *     catalog → MCP resources, plus the server identity).
 *
 * Every resource read and every tool call routes through the verifying
 * {@link ApiClient}: the bytes a client would receive are SHA-256'd and required
 * to equal the entry in the origin's signed `sha256` manifest before anything is
 * returned. A mismatch (MITM, stale CDN edge, tampered file, or a path that
 * isn't a signed artifact) is a {@link VerificationError}, not a response. There
 * are no write/mutating surfaces — it is read-only by construction.
 *
 * The single source of truth for each verb is a `VerbSpec` (Zod input/output);
 * the MCP tool name/description/input-schema are **projected** from it via
 * `@bounded-systems/verbspec`'s `toMcpTool`, so the tool surface can never drift
 * from the verb.
 *
 * @module
 */

import { createHash } from "node:crypto";
import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { ZodType } from "zod";
import {
  defineVerb,
  parseArgs,
  render as renderJson,
  toHelp,
  toMcpTool,
  verbToken,
  type AnyVerbSpec,
  type Registry,
} from "@bounded-systems/verbspec";
import { verifyManifestBundle } from "@bounded-systems/verify";

// ─────────────────────────────────────────────────────────────────────────────
// Config — injected by the consumer. The core carries NO origin-specific values.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Runtime configuration for a verified-static MCP server. Everything here is
 * injected by the consumer (e.g. `site-mcp`): the core hard-codes no origin,
 * path, or signer identity.
 */
export interface Config {
  /** Origin that serves the static site + API + manifest. No trailing slash. */
  baseUrl: string;
  /** Path of the API surface relative to the site root (manifest-relative). */
  apiPrefix: string;
  /** Path of the signed manifest relative to the site root. */
  manifestPath: string;
  /** Path of the Sigstore bundle for the manifest, relative to the site root. */
  signaturePath: string;
  /**
   * Sigstore verification mode for the manifest itself:
   *   "off"     — only the per-file sha256 (manifest) check runs.
   *   "warn"    — attempt signature verification; surface failures as a note.
   *   "require" — fail hard if the manifest signature cannot be verified.
   */
  signatureMode: "off" | "warn" | "require";
  /** Expected Sigstore certificate identity (SAN) of the signing workflow. */
  expectedSignerIdentity: string;
  /** Expected Sigstore OIDC issuer. */
  expectedSignerIssuer: string;
  /** Per-request fetch timeout in milliseconds. */
  fetchTimeoutMs: number;
}

/** The subset of {@link Config} a consumer must supply; the rest is defaulted. */
export type ConfigInput =
  & Pick<Config, "baseUrl" | "expectedSignerIdentity" | "expectedSignerIssuer">
  & Partial<Omit<Config, "baseUrl" | "expectedSignerIdentity" | "expectedSignerIssuer">>;

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

/**
 * Fill the generic, non-origin-specific defaults around a consumer's
 * {@link ConfigInput}. Defaults are mechanical conventions (a `sha256sum`
 * manifest beside a Sigstore bundle, `off` signature mode, a 15s timeout) — they
 * carry no site identity, which is why `baseUrl` and the expected signer must be
 * supplied by the consumer.
 */
export function withDefaults(input: ConfigInput): Config {
  return {
    apiPrefix: "api/v1",
    manifestPath: "site.sha256",
    signaturePath: "site.sha256.sigstore.json",
    signatureMode: "off",
    fetchTimeoutMs: 15_000,
    ...input,
    baseUrl: stripTrailingSlash(input.baseUrl),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// The signed manifest — the trust anchor.
//
// `manifestPath` is an ordinary `sha256sum`-format file: one line per published
// artifact, `<64-hex-digest>  <site-root-relative-path>`, covering every file the
// origin serves. `signaturePath` is a Sigstore bundle signing its exact bytes.
//
// Trust model:
//   - Hash check (always on): fetch a resource, sha256 the bytes received, and
//     require it to equal the manifest entry. A MITM, a stale edge, or a tampered
//     file changes the bytes → the digest won't match → we refuse to return it.
//   - Signature check (optional): verify the Sigstore bundle over the manifest
//     against the expected GitHub Actions workflow identity, anchoring the
//     manifest to the build that produced it.
// ─────────────────────────────────────────────────────────────────────────────

/** Raised when bytes don't match the signed manifest (or aren't in it). */
export class VerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationError";
  }
}

/** A path → lowercase-hex-sha256 map parsed from a `sha256sum` manifest. */
export type Manifest = Map<string, string>;

const MANIFEST_LINE = /^([0-9a-f]{64})[ \t]+\*?(.+?)\s*$/i;

/**
 * Parse `sha256sum` output into a path → lowercase-hex-digest map. Tolerates
 * both text-mode (`  path`) and binary-mode (` *path`) separators.
 */
export function parseManifest(text: string): Manifest {
  const map: Manifest = new Map();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const m = MANIFEST_LINE.exec(line);
    if (!m) continue;
    map.set(m[2], m[1].toLowerCase());
  }
  if (map.size === 0) {
    throw new VerificationError("manifest contained no usable entries");
  }
  return map;
}

/** Lowercase hex SHA-256 of `bytes`. */
export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** The result of a successful per-file hash check. */
export interface VerifiedBytes {
  path: string;
  expected: string;
  actual: string;
}

/**
 * Assert that `bytes` match the manifest entry for `path`. Throws
 * {@link VerificationError} on a missing entry or a digest mismatch.
 */
export function assertMatchesManifest(
  manifest: Manifest,
  path: string,
  bytes: Uint8Array,
): VerifiedBytes {
  const expected = manifest.get(path);
  if (!expected) {
    throw new VerificationError(
      `no manifest entry for "${path}" — it is not a signed artifact of this origin`,
    );
  }
  const actual = sha256Hex(bytes);
  if (actual !== expected) {
    throw new VerificationError(
      `digest mismatch for "${path}": manifest=${expected} fetched=${actual} ` +
        `(the bytes returned do not match the signed manifest — refusing to serve)`,
    );
  }
  return { path, expected, actual };
}

// ─────────────────────────────────────────────────────────────────────────────
// Optional Sigstore verification of the manifest bytes against the bundle.
//
// Delegated to `@bounded-systems/verify` (jsr) — the canonical, side-effect-free
// in-process Sigstore-bundle verifier: the same `sigstore.verify(bundle,
// manifestBytes, …)` call (signature + Fulcio cert chain + offline Rekor
// inclusion) plus a cosign-style certificate-SAN identity match and OIDC-issuer
// enforcement, against the expected signing workflow. verify@0.2.0 exports
// `verifyManifestBundle(...)` and guards its CLI behind `import.meta.main`, so it
// is safe to import in-process — this package no longer carries its own copy of
// the check, and `sigstore` drops from its deps (verify pulls it transitively).
//
// This wrapper only adapts verify's result/throw contract to
// {@link Config.signatureMode} (`off` no-op · `warn` reports failures as an
// unverified result · `require` throws) and the local {@link SignatureResult}.
// The per-file sha256 manifest match ({@link assertMatchesManifest}) stays here —
// that is static-mcp's job, not verify's.
// ─────────────────────────────────────────────────────────────────────────────

/** Outcome of an attempted manifest-signature verification. */
export interface SignatureResult {
  verified: boolean;
  reason?: string;
}

/**
 * Verify a Sigstore bundle over the manifest bytes against the expected signer,
 * by delegating to `@bounded-systems/verify`'s `verifyManifestBundle`. Honors
 * {@link Config.signatureMode}: `off` is a no-op, `warn` reports failures as an
 * unverified result, `require` throws.
 */
export async function verifyManifestSignature(
  manifestBytes: Uint8Array,
  bundleJsonText: string,
  config: Config,
): Promise<SignatureResult> {
  if (config.signatureMode === "off") {
    return { verified: false, reason: "signature verification disabled" };
  }

  try {
    // Cryptographic bundle verification (signature + Fulcio cert + offline Rekor
    // inclusion) plus the cert-SAN identity + issuer match — all inside verify.
    await verifyManifestBundle({
      bundle: bundleJsonText,
      manifest: Buffer.from(manifestBytes),
      identity: config.expectedSignerIdentity,
      issuer: config.expectedSignerIssuer,
    });
    return { verified: true };
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    if (config.signatureMode === "require") {
      throw new Error(`manifest signature verification failed: ${reason}`);
    }
    return { verified: false, reason };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// The verifying API client. Fetches the signed manifest once per process, then
// serves artifacts only after their bytes are checked against it.
// ─────────────────────────────────────────────────────────────────────────────

/** A fetched-and-verified artifact. */
export interface VerifiedArtifact {
  /** Manifest-relative path, e.g. "api/v1/profile.json". */
  path: string;
  /** Absolute URL the bytes came from. */
  url: string;
  /** Raw response body. */
  text: string;
  /** Parsed JSON (artifacts are all JSON). */
  json: unknown;
  /** Hash verification detail. */
  verification: VerifiedBytes;
}

/** Marker so the core can recognize a verb that returned a verified artifact. */
function isVerifiedArtifact(value: unknown): value is VerifiedArtifact {
  return (
    typeof value === "object" &&
    value !== null &&
    "verification" in value &&
    "text" in value &&
    "url" in value
  );
}

/**
 * Read-only client over a signed static origin. Every {@link getVerified} call
 * checks the served bytes against the cached signed manifest before returning.
 */
export class ApiClient {
  private manifestCache?: Promise<{ manifest: Manifest; signature: SignatureResult }>;

  constructor(
    private readonly config: Config,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  /** Resolve a manifest-relative path to its absolute URL on the origin. */
  urlFor(path: string): string {
    return `${this.config.baseUrl}/${path}`;
  }

  /** Manifest-relative path for an API endpoint under the configured prefix. */
  apiPath(file: string): string {
    return `${this.config.apiPrefix}/${file}`;
  }

  private async fetchBytes(url: string): Promise<{ bytes: Uint8Array; text: string }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.fetchTimeoutMs);
    try {
      const res = await this.fetchImpl(url, {
        signal: controller.signal,
        headers: { accept: "application/json, text/plain, */*" },
      });
      if (!res.ok) {
        throw new Error(`GET ${url} → HTTP ${res.status} ${res.statusText}`);
      }
      const buf = new Uint8Array(await res.arrayBuffer());
      const text = new TextDecoder("utf-8").decode(buf);
      return { bytes: buf, text };
    } finally {
      clearTimeout(timer);
    }
  }

  /** Fetch + cache the signed manifest (and optionally verify its signature). */
  async getManifest(): Promise<{ manifest: Manifest; signature: SignatureResult }> {
    if (!this.manifestCache) {
      this.manifestCache = (async () => {
        const manifestUrl = this.urlFor(this.config.manifestPath);
        const { bytes, text } = await this.fetchBytes(manifestUrl);
        const manifest = parseManifest(text);

        let signature: SignatureResult = {
          verified: false,
          reason: "signature verification disabled",
        };
        if (this.config.signatureMode !== "off") {
          try {
            const { text: bundleText } = await this.fetchBytes(
              this.urlFor(this.config.signaturePath),
            );
            signature = await verifyManifestSignature(bytes, bundleText, this.config);
          } catch (err) {
            if (this.config.signatureMode === "require") throw err;
            signature = {
              verified: false,
              reason: err instanceof Error ? err.message : String(err),
            };
          }
        }
        return { manifest, signature };
      })().catch((err) => {
        // Don't cache a failed manifest fetch — allow retry on the next call.
        this.manifestCache = undefined;
        throw err;
      });
    }
    return this.manifestCache;
  }

  /**
   * Fetch a manifest-relative artifact and verify its bytes against the signed
   * manifest before returning. Throws {@link VerificationError} on mismatch.
   */
  async getVerified(path: string): Promise<VerifiedArtifact> {
    const { manifest } = await this.getManifest();
    const url = this.urlFor(path);
    const { bytes, text } = await this.fetchBytes(url);
    const verification = assertMatchesManifest(manifest, path, bytes);

    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch (err) {
      throw new VerificationError(
        `verified bytes for "${path}" are not valid JSON: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
    return { path, url, text, json, verification };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// The spec: VerbSpec verbs (→ MCP tools) + a resource catalog (→ MCP resources).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The per-verb capability slice the core hands to a verified verb's `run`: the
 * verifying client plus path helpers and the resolved config. A verb fetches its
 * artifact through this and returns the {@link VerifiedArtifact} — the core wraps
 * the result with the verification `_meta`.
 */
export interface StaticDeps {
  /** The verifying client. */
  client: ApiClient;
  /** Manifest-relative path for a file under the API prefix. */
  apiPath(file: string): string;
  /** The resolved config. */
  config: Config;
}

/**
 * Author a read-only verb that fetches + verifies a single static artifact. The
 * returned `VerbSpec` `run`s by resolving `input` → a manifest-relative path,
 * fetching it through the verifying client, and returning the
 * {@link VerifiedArtifact}. Its MCP tool projection (name/description/input
 * schema) comes from the same spec, so the surface can't drift from the verb.
 */
export function verifiedVerb<I extends ZodType>(opts: {
  /** Stable verb id → MCP tool name (spaces become `_`). */
  id: string;
  /** One-line summary → MCP tool description. */
  summary: string;
  /** Owning actor (capability/permission binding). Defaults to "anon". */
  actor?: string;
  /** Zod input schema. Defaults to an empty object (no args). */
  input: I;
  /** Input keys parsed as CLI positionals (in order) rather than `--flags`. */
  positionals?: readonly string[];
  /** Map validated input → the manifest-relative artifact path to verify. */
  resolve: (input: import("zod").infer<I>, deps: StaticDeps) => string;
}): AnyVerbSpec {
  // The output is an opaque verified artifact; the canonical multi-surface
  // contract is the *bytes* (hash-checked), so the output schema stays loose.
  return defineVerb({
    id: opts.id,
    summary: opts.summary,
    actor: opts.actor ?? "anon",
    input: opts.input,
    positionals: opts.positionals,
    // deno-lint-ignore no-explicit-any
    output: undefined as any,
    run: async (input: import("zod").infer<I>, deps?: StaticDeps) => {
      if (!deps) throw new Error(`verb "${opts.id}" ran without static deps`);
      return await deps.client.getVerified(opts.resolve(input, deps));
    },
  }) as AnyVerbSpec;
}

/** A fixed static resource: a stable MCP URI mapped to one verified artifact. */
export interface VerifiedResource {
  /** MCP resource URI, e.g. `site://profile`. */
  uri: string;
  /** Human-readable name. */
  name: string;
  /** Description shown to clients. */
  description: string;
  /** Manifest-relative artifact path to fetch + verify. */
  path: string;
  /** MIME type. Defaults to `application/json`. */
  mimeType?: string;
}

/** A templated resource family, e.g. `site://post/{slug}`. */
export interface VerifiedResourceTemplate {
  /** Resource family name. */
  name: string;
  /** URI template, e.g. `site://post/{slug}`. */
  template: string;
  /** Description shown to clients. */
  description: string;
  /** MIME type. Defaults to `application/json`. */
  mimeType?: string;
  /** Map a concrete URI → the manifest-relative path, or `undefined` to reject. */
  resolve: (uri: URL, deps: StaticDeps) => string | undefined;
  /** Optionally enumerate concrete members for resource listing. */
  list?: (deps: StaticDeps) => Promise<
    { uri: string; name: string; description?: string }[]
  >;
}

/** Identity for the MCP server itself. */
export interface ServerInfo {
  name: string;
  version: string;
  /** Optional override for the server `instructions`. A sensible default is built. */
  instructions?: string;
}

/**
 * The full description of a verified-static MCP server: who it is, the VerbSpec
 * verbs to project as tools, and the resource catalog to project as resources.
 */
export interface StaticMcpSpec {
  /** Server identity. */
  server: ServerInfo;
  /** VerbSpec verbs (ideally authored via {@link verifiedVerb}) → MCP tools. */
  verbs: Registry;
  /** Fixed resources → MCP resources. */
  resources?: VerifiedResource[];
  /** Templated resource families → MCP templated resources. */
  resourceTemplates?: VerifiedResourceTemplate[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Projection: spec + config → a read-only MCP server.
// ─────────────────────────────────────────────────────────────────────────────

function verificationMeta(a: VerifiedArtifact, signatureNote: string) {
  return {
    verification: {
      path: a.verification.path,
      source: a.url,
      sha256: a.verification.actual,
      matchedSignedManifest: true,
      manifestSignature: signatureNote,
    },
  };
}

/**
 * Build (but do not connect) the read-only MCP server for `spec` + `config`.
 * Every resource read and tool call routes through the verifying client, so
 * nothing is returned that hasn't matched the signed manifest. Useful for tests
 * and embedding; {@link serveVerifiedStaticMcp} wires it to stdio.
 */
export function buildVerifiedStaticServer(
  spec: StaticMcpSpec,
  config: Config,
  client: ApiClient = new ApiClient(config),
): McpServer {
  const deps: StaticDeps = {
    client,
    apiPath: (file: string) => client.apiPath(file),
    config,
  };

  const server = new McpServer(
    { name: spec.server.name, version: spec.server.version },
    {
      instructions: spec.server.instructions ??
        `Read-only access to ${config.baseUrl}'s signed static API. Every ` +
          `resource and tool result is verified byte-for-byte against the ` +
          `origin's Sigstore-signed sha256 manifest before being returned; a ` +
          `mismatch is an error.`,
    },
  );

  async function signatureNote(): Promise<string> {
    const { signature } = await client.getManifest();
    if (config.signatureMode === "off") return "not-checked (disabled)";
    return signature.verified
      ? "verified"
      : `unverified (${signature.reason ?? "unknown"})`;
  }

  // ---- Fixed resources ----
  for (const r of spec.resources ?? []) {
    server.registerResource(
      r.name,
      r.uri,
      {
        description: r.description,
        mimeType: r.mimeType ?? "application/json",
      },
      async (uri: URL) => {
        const artifact = await client.getVerified(r.path);
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: r.mimeType ?? "application/json",
              text: artifact.text,
            },
          ],
          _meta: verificationMeta(artifact, await signatureNote()),
        };
      },
    );
  }

  // ---- Templated resources ----
  for (const t of spec.resourceTemplates ?? []) {
    const template = new ResourceTemplate(t.template, {
      list: t.list
        ? async () => {
          const members = await t.list!(deps);
          return {
            resources: members.map((m) => ({
              uri: m.uri,
              name: m.name,
              description: m.description,
              mimeType: t.mimeType ?? "application/json",
            })),
          };
        }
        : undefined,
    });
    server.registerResource(
      t.name,
      template,
      { description: t.description, mimeType: t.mimeType ?? "application/json" },
      async (uri: URL) => {
        const path = t.resolve(uri, deps);
        if (!path) throw new VerificationError(`invalid resource URI: ${uri.href}`);
        const artifact = await client.getVerified(path);
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: t.mimeType ?? "application/json",
              text: artifact.text,
            },
          ],
          _meta: verificationMeta(artifact, await signatureNote()),
        };
      },
    );
  }

  // ---- Tools, projected from the VerbSpec registry ----
  for (const verb of Object.values(spec.verbs)) {
    const tool = toMcpTool(verb); // name + description + inputSchema, from verbspec
    const hasInput =
      Object.keys((tool.inputSchema as { properties?: object }).properties ?? {}).length > 0;

    const handler = async (...args: unknown[]) => {
      // With an input schema the SDK passes (parsedArgs, extra); without, (extra).
      const input = hasInput ? args[0] : {};
      const result = await verb.run(input, deps);
      if (!isVerifiedArtifact(result)) {
        // A verb that returned plain structured data (not a verified fetch).
        return {
          content: [{ type: "text" as const, text: JSON.stringify(result) }],
          structuredContent: (typeof result === "object" && result !== null
            ? (result as Record<string, unknown>)
            : { value: result }),
        };
      }
      return {
        content: [{ type: "text" as const, text: result.text }],
        structuredContent: result.json as Record<string, unknown>,
        _meta: verificationMeta(result, await signatureNote()),
      };
    };

    if (hasInput) {
      server.registerTool(
        tool.name,
        // The verb's Zod input is the validator the SDK advertises + enforces.
        { description: tool.description, inputSchema: verb.input },
        // deno-lint-ignore no-explicit-any
        handler as any,
      );
    } else {
      server.registerTool(
        tool.name,
        { description: tool.description },
        // deno-lint-ignore no-explicit-any
        handler as any,
      );
    }
  }

  return server;
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI projection: the SAME VerbSpec verbs, the other surface verbspec offers.
//
// verbspec projects one verb to BOTH an MCP tool and a CLI subcommand; here we
// reuse its `parseArgs` (the single argv→Zod-input parser the MCP tool input
// also validates with) and `toHelp` (the `--help` printer). One verb definition,
// two surfaces — no drift. Output is the verified artifact's bytes, exactly what
// the MCP tool returns.
// ─────────────────────────────────────────────────────────────────────────────

/** The captured outcome of a CLI invocation (pure — the caller does the I/O). */
export interface CliResult {
  stdout: string;
  stderr: string;
  /** Process exit code: 0 ok · 1 verification/usage failure · 2 bad arguments. */
  code: number;
}

/** Usage text: the bin, then one line per verb (its CLI subcommand + summary). */
function cliUsage(spec: StaticMcpSpec, bin: string): string {
  const lines = [
    `${bin} <command> [args]    — verified, read-only access to a signed static API`,
    "",
    "Commands:",
  ];
  for (const v of Object.values(spec.verbs)) {
    lines.push(`  ${verbToken(v.id).padEnd(18)} ${v.summary}`);
  }
  lines.push("", `Run \`${bin} <command> --help\` for a command's flags.`);
  return lines.join("\n");
}

/**
 * Run the verbs as a CLI: resolve a subcommand → parse argv against the verb's
 * Zod input (via verbspec's `parseArgs`) → run it through the verifying client →
 * print the verified bytes. A {@link VerificationError} fails closed (exit 1).
 * Pure: returns a {@link CliResult}; the caller writes the streams and exits.
 */
export async function runStaticCli(
  spec: StaticMcpSpec,
  config: Config,
  argv: readonly string[],
  client: ApiClient = new ApiClient(config),
): Promise<CliResult> {
  const bin = spec.server.name;
  const [id, ...rest] = argv;

  if (!id || id === "help" || id === "--help" || id === "-h") {
    return { stdout: cliUsage(spec, bin), stderr: "", code: id ? 0 : 1 };
  }

  const verb = spec.verbs[id] ?? Object.values(spec.verbs).find((v) => verbToken(v.id) === id);
  if (!verb) {
    return { stdout: "", stderr: `unknown command: ${id}\n\n${cliUsage(spec, bin)}`, code: 1 };
  }
  if (rest.includes("--help") || rest.includes("-h")) {
    return { stdout: toHelp(verb, bin), stderr: "", code: 0 };
  }

  let input: unknown;
  try {
    input = parseArgs(verb, rest);
  } catch (err) {
    return {
      stdout: "",
      stderr: `invalid arguments for "${verbToken(verb.id)}": ${
        err instanceof Error ? err.message : String(err)
      }`,
      code: 2,
    };
  }

  const deps: StaticDeps = { client, apiPath: (file: string) => client.apiPath(file), config };
  try {
    const result = await verb.run(input, deps);
    const text = isVerifiedArtifact(result) ? result.text : renderJson(result);
    return { stdout: text, stderr: "", code: 0 };
  } catch (err) {
    // VerificationError (or any run failure) fails closed — print nothing.
    return { stdout: "", stderr: err instanceof Error ? err.message : String(err), code: 1 };
  }
}

/**
 * Serve a verified-static MCP server over stdio (the transport MCP clients spawn
 * a subprocess for). Builds the server from `spec` + `config`, connects stdin/
 * stdout, and logs a readiness line to **stderr** (stdout is the MCP channel).
 */
export async function serveVerifiedStaticMcp(
  spec: StaticMcpSpec,
  config: Config,
): Promise<void> {
  const server = buildVerifiedStaticServer(spec, config);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Readiness line on stderr only (stdout is the MCP channel). Accessed through
  // `globalThis` so the lib (DOM/node/Deno) carrying `console` need not be
  // pinned — it is present in every runtime that runs an MCP stdio server.
  (globalThis as { console?: { error: (...args: unknown[]) => void } }).console
    ?.error(
      `${spec.server.name} ready (stdio) → ${config.baseUrl}; ` +
        `signature mode=${config.signatureMode}`,
    );
}

// Re-export the verbspec primitives a consumer needs to author verbs, so a thin
// implementation can depend on just this package for the common case.
export { defineVerb, toMcpTool, toMcpToolset, verbToken } from "@bounded-systems/verbspec";
export type { AnyVerbSpec, McpTool, Registry, VerbSpec } from "@bounded-systems/verbspec";
