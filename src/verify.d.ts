/**
 * Ambient types for `@bounded-systems/verify`.
 *
 * verify@0.2.0 is authored as a plain `.mjs` (JSDoc-typed) module, and JSR's npm
 * bridge (`@jsr/bounded-systems__verify`) ships it WITHOUT a generated `.d.ts`.
 * Under this package's `strict` tsc that import is an implicit-`any` error
 * (TS7016), so we declare the small slice we consume here. Deno consumers read
 * verify's own JSDoc types directly from the JSR source and ignore this file.
 *
 * Mirrors `verifyManifestBundle` in
 * https://jsr.io/@bounded-systems/verify/0.2.0 (verify.mjs).
 */
declare module "@bounded-systems/verify" {
  /** The GitHub Actions OIDC issuer enforced by default. */
  export const DEFAULT_ISSUER: string;

  /** Error thrown when bundle verification fails. `code` carries the machine reason. */
  export class VerifyError extends Error {
    code: string;
    identity?: string;
    cause?: unknown;
  }

  export interface VerifyManifestBundleArgs {
    /** Parsed Sigstore bundle (object) or its JSON text. */
    bundle: object | string;
    /** The signed artifact bytes (e.g. `site.sha256`). */
    manifest: Uint8Array | string;
    /** Optional: the cert SAN must match this regex (string is compiled to one). */
    identity?: RegExp | string;
    /** OIDC issuer to enforce (default {@link DEFAULT_ISSUER}). */
    issuer?: string;
    /** Injectable verifier; defaults to sigstore's `verify`. */
    verifyImpl?: (...args: unknown[]) => Promise<unknown>;
  }

  export interface VerifyManifestBundleResult {
    verified: true;
    identity: string;
    issuer: string;
  }

  /**
   * Cryptographically verify a Sigstore bundle over a whole-site manifest,
   * in-process and offline. Resolves to a structured result on success; throws a
   * typed {@link VerifyError} on any verification failure.
   */
  export function verifyManifestBundle(
    args: VerifyManifestBundleArgs,
  ): Promise<VerifyManifestBundleResult>;
}
