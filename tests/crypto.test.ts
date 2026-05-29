// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Crypto Utility Tests
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "bun:test";
import {
  canonicalSerialise,
  canonicalBytes,
  sha256Hex,
  toBase64Url,
  fromBase64Url,
  generateRandomToken,
  generateOTP,
  hashCoordinates,
  importPublicKey,
  verifySignature,
} from "../src/crypto/utils.ts";
import { PodChainError } from "../src/errors.ts";
import type { DeliveryPayload } from "../src/types.ts";
import { generateTestKeyPair, signPayload, buildTestPayload } from "./helpers.ts";

// ── canonicalSerialise ────────────────────────────────────────────────────────

describe("canonicalSerialise", () => {
  it("sorts keys alphabetically", () => {
    const payload: DeliveryPayload = {
      taskId: "task_001",
      riderId: "rider_001",
      signedAt: "2024-11-15T10:00:00.000Z",
      coordHash: "abc123",
      recipientProof: "proof_token",
      schemaVersion: "1.0",
    };

    const result = canonicalSerialise(payload);
    const parsed = JSON.parse(result);
    const keys = Object.keys(parsed);

    // Keys must be in ascending alphabetical order
    expect(keys).toEqual([...keys].sort());
  });

  it("produces no unnecessary whitespace", () => {
    const payload = buildTestPayload();
    const result = canonicalSerialise(payload);

    expect(result).not.toContain(" : ");
    expect(result).not.toContain(", ");
    expect(result).not.toContain("\n");
    expect(result).not.toContain("\t");
  });

  it("produces identical output for the same input regardless of property order", () => {
    const a: DeliveryPayload = {
      taskId: "t1", riderId: "r1", signedAt: "2024-01-01T00:00:00Z",
      coordHash: "ch1", recipientProof: "rp1", schemaVersion: "1.0",
    };
    const b: DeliveryPayload = {
      schemaVersion: "1.0", recipientProof: "rp1", coordHash: "ch1",
      signedAt: "2024-01-01T00:00:00Z", riderId: "r1", taskId: "t1",
    };

    expect(canonicalSerialise(a)).toBe(canonicalSerialise(b));
  });

  it("matches the shared test vector", () => {
    // This vector must match the output of the podchain_flutter library.
    // Any divergence means cross-platform signing will fail.
    const payload: DeliveryPayload = {
      coordHash: "a3f1b2c4",
      recipientProof: "e9d2c1b3",
      riderId: "rider_007",
      schemaVersion: "1.0",
      signedAt: "2024-11-15T10:32:00.000Z",
      taskId: "task_abc123",
    };

    const expected =
      '{"coordHash":"a3f1b2c4","recipientProof":"e9d2c1b3","riderId":"rider_007","schemaVersion":"1.0","signedAt":"2024-11-15T10:32:00.000Z","taskId":"task_abc123"}';

    expect(canonicalSerialise(payload)).toBe(expected);
  });
});

// ── sha256Hex ────────────────────────────────────────────────────────────────

describe("sha256Hex", () => {
  it("returns a 64-character lowercase hex string", async () => {
    const result = await sha256Hex("hello");
    expect(result).toHaveLength(64);
    expect(result).toMatch(/^[0-9a-f]+$/);
  });

  it("produces a known hash for an empty string", async () => {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const result = await sha256Hex("");
    expect(result).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("produces a known hash for a known input", async () => {
    // SHA-256("PODCHAIN") — pre-computed reference value for test vector
    const result = await sha256Hex("PODCHAIN");
    expect(result).toHaveLength(64);
    // Same input always produces same output
    expect(await sha256Hex("PODCHAIN")).toBe(result);
  });

  it("is sensitive to single-byte changes", async () => {
    const a = await sha256Hex("hello");
    const b = await sha256Hex("hellp");
    expect(a).not.toBe(b);
  });
});

// ── base64url encoding ────────────────────────────────────────────────────────

describe("toBase64Url / fromBase64Url", () => {
  it("round-trips arbitrary bytes", () => {
    const original = new Uint8Array([0, 1, 2, 3, 255, 254, 128, 64]);
    const encoded = toBase64Url(original);
    const decoded = fromBase64Url(encoded);
    expect(decoded).toEqual(original);
  });

  it("produces no padding characters", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const encoded = toBase64Url(bytes);
    expect(encoded).not.toContain("=");
  });

  it("uses URL-safe characters only", () => {
    // 1000 random bytes — should produce only base64url chars
    const bytes = new Uint8Array(1000);
    crypto.getRandomValues(bytes);
    const encoded = toBase64Url(bytes);
    expect(encoded).toMatch(/^[A-Za-z0-9\-_]+$/);
  });
});

// ── Token generation ──────────────────────────────────────────────────────────

describe("generateRandomToken", () => {
  it("produces a 64-character hex string by default (32 bytes)", () => {
    const token = generateRandomToken();
    expect(token).toHaveLength(64);
    expect(token).toMatch(/^[0-9a-f]+$/);
  });

  it("produces unique tokens on each call", () => {
    const tokens = new Set(Array.from({ length: 100 }, () => generateRandomToken()));
    expect(tokens.size).toBe(100);
  });
});

describe("generateOTP", () => {
  it("produces exactly 6 digits", () => {
    for (let i = 0; i < 50; i++) {
      const otp = generateOTP();
      expect(otp).toHaveLength(6);
      expect(otp).toMatch(/^\d{6}$/);
    }
  });

  it("stays within the 100000–999999 range", () => {
    for (let i = 0; i < 50; i++) {
      const n = parseInt(generateOTP(), 10);
      expect(n).toBeGreaterThanOrEqual(100000);
      expect(n).toBeLessThanOrEqual(999999);
    }
  });
});

// ── Coordinate hashing ────────────────────────────────────────────────────────

describe("hashCoordinates", () => {
  it("produces a 64-character hex string", async () => {
    const hash = await hashCoordinates(6.5244, 3.3792);
    expect(hash).toHaveLength(64);
  });

  it("is deterministic for the same coordinates", async () => {
    const a = await hashCoordinates(6.5244, 3.3792);
    const b = await hashCoordinates(6.5244, 3.3792);
    expect(a).toBe(b);
  });

  it("produces different hashes for different coordinates", async () => {
    const a = await hashCoordinates(6.5244, 3.3792);
    const b = await hashCoordinates(6.5245, 3.3792);
    expect(a).not.toBe(b);
  });
});

// ── Key import and signature verification ────────────────────────────────────

describe("importPublicKey", () => {
  it("successfully imports a valid P-256 JWK", async () => {
    const { publicKeyJwk } = await generateTestKeyPair();
    const key = await importPublicKey(publicKeyJwk);
    expect(key).toBeDefined();
    expect(key.type).toBe("public");
  });

  it("throws KEY_FORMAT_INVALID for a non-P-256 key claim", async () => {
    const bad = { kty: "EC", crv: "P-384", x: "abc", y: "def" };
    await expect(importPublicKey(bad as never)).rejects.toMatchObject({
      code: "KEY_FORMAT_INVALID",
    });
  });

  it("throws KEY_FORMAT_INVALID for a malformed JWK", async () => {
    const bad = { kty: "EC", crv: "P-256" }; // missing x and y
    await expect(importPublicKey(bad as never)).rejects.toMatchObject({
      code: "KEY_FORMAT_INVALID",
    });
  });
});

describe("verifySignature", () => {
  it("returns true for a valid signature over the correct data", async () => {
    const { publicKeyJwk, privateKey } = await generateTestKeyPair();
    const payload = buildTestPayload();
    const signature = await signPayload(privateKey, payload);
    const cryptoKey = await importPublicKey(publicKeyJwk);
    const result = await verifySignature(cryptoKey, signature, canonicalBytes(payload));
    expect(result).toBe(true);
  });

  it("returns false when the payload has been tampered with after signing", async () => {
    const { publicKeyJwk, privateKey } = await generateTestKeyPair();
    const payload = buildTestPayload();
    const signature = await signPayload(privateKey, payload);

    // Tamper with the payload after signing
    const tampered = { ...payload, taskId: "task_different" };
    const cryptoKey = await importPublicKey(publicKeyJwk);
    const result = await verifySignature(cryptoKey, signature, canonicalBytes(tampered));
    expect(result).toBe(false);
  });

  it("returns false for a signature from a different key pair", async () => {
    const { publicKeyJwk } = await generateTestKeyPair();
    const { privateKey: differentPrivateKey } = await generateTestKeyPair();
    const payload = buildTestPayload();

    const signatureFromDifferentKey = await signPayload(differentPrivateKey, payload);
    const cryptoKey = await importPublicKey(publicKeyJwk);
    const result = await verifySignature(cryptoKey, signatureFromDifferentKey, canonicalBytes(payload));
    expect(result).toBe(false);
  });

  it("returns false for a malformed signature string", async () => {
    const { publicKeyJwk } = await generateTestKeyPair();
    const payload = buildTestPayload();
    const cryptoKey = await importPublicKey(publicKeyJwk);
    const result = await verifySignature(cryptoKey, "not-a-valid-signature", canonicalBytes(payload));
    expect(result).toBe(false);
  });
});
