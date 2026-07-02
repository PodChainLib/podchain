// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Server-Side Cryptographic Benchmarks
//
// Measures the latency of individual cryptographic operations on the server:
//   - ECDSA signature verification
//   - SHA-256 hashing (token and coordinate)
//   - Canonical payload serialisation
//   - Hash chain computation (single record)
//
// These results correspond to the server-side rows in the Chapter 5
// performance benchmarking table.
//
// Run: bun run benchmarks/crypto.bench.ts
// ─────────────────────────────────────────────────────────────────────────────

import { benchmark, printResults, serialiseResults } from "./runner.ts";
import {
  importPublicKey,
  verifySignature,
  sha256Hex,
  canonicalSerialise,
  canonicalBytes,
  toBase64Url,
  generateRandomToken,
  hashCoordinates,
} from "../src/crypto/utils.ts";
import type { DeliveryPayload } from "../src/types.ts";

// ── Test Fixtures ─────────────────────────────────────────────────────────────

// Generate a real key pair once — used for all signature benchmarks
const keyPair = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"]
);

const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
const cryptoKey = await importPublicKey({
  kty: "EC",
  crv: "P-256",
  x: publicKeyJwk.x as string,
  y: publicKeyJwk.y as string,
});

const testPayload: DeliveryPayload = {
  coordHash: "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
  recipientProof: "e9d2c1b3a4f5e6d7c8b9a0f1e2d3c4b5",
  riderId: "rider_emeka_001",
  schemaVersion: "1.0",
  signedAt: "2024-11-15T10:32:00.000Z",
  taskId: "task_abc123def456",
};

const payloadBytes = canonicalBytes(testPayload);

// Pre-sign the payload so we have a valid signature for the verification benchmark
const sigBuffer = await crypto.subtle.sign(
  { name: "ECDSA", hash: { name: "SHA-256" } },
  keyPair.privateKey,
  payloadBytes
);
const validSignature = toBase64Url(new Uint8Array(sigBuffer));

// ── Benchmarks ────────────────────────────────────────────────────────────────

console.log("Preparing server-side cryptographic benchmarks…");

const results = await Promise.all([

  benchmark(
    "Canonical payload serialisation",
    async () => { canonicalSerialise(testPayload); },
    200  // very fast — run more iterations for statistical stability
  ),

  benchmark(
    "SHA-256 hash (token, 32 bytes)",
    async () => { await sha256Hex(generateRandomToken(32)); },
    200
  ),

  benchmark(
    "SHA-256 hash (coordinate pair)",
    async () => { await hashCoordinates(6.5244, 3.3792); },
    200
  ),

  benchmark(
    "ECDSA P-256 signature verification",
    async () => {
      await verifySignature(cryptoKey, validSignature, payloadBytes);
    },
    50
  ),

  benchmark(
    "ECDSA P-256 signature verification (invalid sig)",
    async () => {
      // Benchmark rejection path — important for pipeline latency under attack
      const tampered = validSignature.slice(0, -4) + "AAAA";
      await verifySignature(cryptoKey, tampered, payloadBytes);
    },
    50
  ),

  benchmark(
    "Key import from JWK (P-256)",
    async () => {
      await importPublicKey({
        kty: "EC",
        crv: "P-256",
        x: publicKeyJwk.x as string,
        y: publicKeyJwk.y as string,
      });
    },
    50
  ),

]);

printResults({
  suite: "Server — Cryptographic Operations",
  timestamp: new Date().toISOString(),
  runtime: `Bun ${Bun.version}`,
  results,
});

// Write JSON output for thesis appendix
await Bun.write(
  "benchmarks/results/crypto-server.json",
  serialiseResults({
    suite: "Server — Cryptographic Operations",
    timestamp: new Date().toISOString(),
    runtime: `Bun ${Bun.version}`,
    results,
  })
);
