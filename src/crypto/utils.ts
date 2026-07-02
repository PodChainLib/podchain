// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Cryptographic Utilities
//
// All cryptographic operations use Bun's built-in Web Crypto API
// (globalThis.crypto.subtle). No third-party crypto libraries are used
// in the core signing path — platform-native implementations are the most
// thoroughly audited and maintained options available.
//
// Signature format: IEEE P1363 (raw r || s concatenation, 64 bytes for P-256)
// encoded as base64url. This matches the format produced by both Bun's
// Web Crypto API and the browser WebCrypto API used in Tier 3 recipient signing.
// ─────────────────────────────────────────────────────────────────────────────

import type { DeliveryPayload, PublicKeyJWK } from "../types.ts";
import { PodChainError } from "../errors.ts";

// ── Canonical Serialisation ───────────────────────────────────────────────────

/**
 * Produces the canonical JSON serialisation of a DeliveryPayload.
 * Keys are sorted alphabetically; no whitespace; UTF-8 encoding.
 *
 * This is the byte sequence that the rider's device signs and that the
 * server passes to the verification function. The two MUST be identical.
 * Any deviation — different key order, trailing space, unicode variant —
 * will produce a signature mismatch.
 */
export function canonicalSerialise(payload: DeliveryPayload): string {
  const ordered: Record<string, string> = {};
  const values = payload as unknown as Record<string, string>;
  for (const key of Object.keys(payload).sort()) {
    ordered[key] = values[key]!;
  }
  return JSON.stringify(ordered);
}

/**
 * Encodes the canonical serialisation to UTF-8 bytes.
 */
export function canonicalBytes(payload: DeliveryPayload): Uint8Array {
  return new TextEncoder().encode(canonicalSerialise(payload));
}

// ── Hashing ───────────────────────────────────────────────────────────────────

/**
 * Computes a SHA-256 digest and returns it as a lowercase hex string.
 * Used for: token hashing, coordinate hashing, hash chain computation.
 */
export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const hashBuffer = await crypto.subtle.digest("SHA-256", asWebCryptoBytes(bytes));
  return bufferToHex(hashBuffer);
}

/**
 * Converts an ArrayBuffer to a lowercase hex string.
 */
function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── Encoding Helpers ──────────────────────────────────────────────────────────

/**
 * Encodes a Uint8Array or ArrayBuffer as a base64url string (RFC 4648 §5).
 * No padding characters.
 */
export function toBase64Url(data: Uint8Array | ArrayBuffer): string {
  const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Decodes a base64url string to a Uint8Array.
 */
export function fromBase64Url(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)!;
  }
  return bytes;
}

// ── Public Key Operations ─────────────────────────────────────────────────────

/**
 * Imports a P-256 JWK public key as a CryptoKey object suitable for
 * ECDSA verification. Throws KEY_FORMAT_INVALID if the JWK is malformed
 * or does not describe a P-256 key.
 */
export async function importPublicKey(jwk: PublicKeyJWK): Promise<CryptoKey> {
  if (jwk.kty !== "EC" || jwk.crv !== "P-256") {
    throw new PodChainError(
      "KEY_FORMAT_INVALID",
      "Public key must be an EC key on the P-256 curve"
    );
  }
  if (!jwk.x || !jwk.y) {
    throw new PodChainError(
      "KEY_FORMAT_INVALID",
      "Public key JWK is missing x or y coordinate"
    );
  }

  try {
    return await crypto.subtle.importKey(
      "jwk",
      { ...jwk, key_ops: ["verify"], ext: true },
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );
  } catch {
    throw new PodChainError(
      "KEY_FORMAT_INVALID",
      "Failed to import public key — JWK may be malformed"
    );
  }
}

// ── Signature Verification ────────────────────────────────────────────────────

/**
 * Verifies an ECDSA P-256 signature over the given data.
 *
 * @param publicKey   CryptoKey imported via importPublicKey()
 * @param signature   base64url-encoded IEEE P1363 signature (64 bytes for P-256)
 * @param data        The exact bytes that were signed — must match what the
 *                    rider's device signed (use canonicalBytes() for payloads)
 *
 * Returns true if the signature is valid; false otherwise.
 * Does not throw on cryptographic failure — callers check the return value.
 */
export async function verifySignature(
  publicKey: CryptoKey,
  signature: string,
  data: Uint8Array
): Promise<boolean> {
  try {
    const sigBytes = fromBase64Url(signature);
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      publicKey,
      asWebCryptoBytes(sigBytes),
      asWebCryptoBytes(data)
    );
  } catch {
    // Any error during verification (malformed sig bytes, etc.) is a failure
    return false;
  }
}

function asWebCryptoBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes as Uint8Array<ArrayBuffer>;
}

// ── Random Token Generation ───────────────────────────────────────────────────

/**
 * Generates a cryptographically random token of the specified byte length,
 * returned as a hex string. Default is 32 bytes (256 bits).
 * Used for Tier 1 passive tokens and Tier 3 nonces.
 */
export function generateRandomToken(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bufferToHex(bytes.buffer);
}

/**
 * Generates a cryptographically random 6-digit numeric OTP for Tier 2.
 * The range is 100000–999999 to guarantee exactly 6 digits.
 */
export function generateOTP(): string {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  const value = new DataView(bytes.buffer).getUint32(0, false);
  const otp = 100000 + (value % 900000);
  return otp.toString();
}

// ── Coordinate Hashing ────────────────────────────────────────────────────────

/**
 * Hashes a GPS coordinate pair for storage in the Proof Certificate.
 * Satisfies the NDPA 2023 data minimisation requirement: the hash proves
 * that a location was recorded and signed without storing the raw coordinates
 * in the immutable certificate record.
 *
 * Input format: "latitude,longitude" as decimal strings, e.g. "6.5244,3.3792"
 */
export async function hashCoordinates(lat: number, lng: number): Promise<string> {
  return sha256Hex(`${lat},${lng}`);
}
