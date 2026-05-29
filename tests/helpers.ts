// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Test Helpers
// Shared utilities for generating keys, building payloads, and signing them
// in test contexts. Uses Bun's built-in Web Crypto API directly.
// ─────────────────────────────────────────────────────────────────────────────

import { Database } from "bun:sqlite";
import { SQLiteAdapter } from "../src/adapters/sqlite-adapter.ts";
import { PodChain } from "../src/podchain.ts";
import { canonicalBytes, toBase64Url } from "../src/crypto/utils.ts";
import type { DeliveryPayload, PublicKeyJWK } from "../src/types.ts";

export interface TestKeyPair {
  publicKeyJwk: PublicKeyJWK;
  privateKey: CryptoKey;
}

/**
 * Generates a fresh ECDSA P-256 key pair for use in tests.
 */
export async function generateTestKeyPair(): Promise<TestKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

  return {
    publicKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: jwk.x as string,
      y: jwk.y as string,
      key_ops: ["verify"],
      ext: true,
    },
    privateKey: keyPair.privateKey,
  };
}

/**
 * Signs a DeliveryPayload using the given private key.
 * Returns a base64url IEEE P1363 signature — the exact format
 * the verification pipeline expects.
 */
export async function signPayload(
  privateKey: CryptoKey,
  payload: DeliveryPayload
): Promise<string> {
  const bytes = canonicalBytes(payload);
  const sigBuffer = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    privateKey,
    bytes
  );
  return toBase64Url(new Uint8Array(sigBuffer));
}

/**
 * Returns a valid DeliveryPayload for testing with sensible defaults.
 */
export function buildTestPayload(overrides: Partial<DeliveryPayload> = {}): DeliveryPayload {
  return {
    coordHash: "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
    recipientProof: "test-recipient-proof-token",
    riderId: "rider_test_001",
    schemaVersion: "1.0",
    signedAt: new Date().toISOString(),
    taskId: "task_test_001",
    ...overrides,
  };
}

/**
 * Creates a fresh in-memory PodChain instance for each test.
 * Each call returns an independent instance with its own SQLite database,
 * preventing state leakage between tests.
 */
export function createTestPodChain(): PodChain {
  const db = new Database(":memory:");
  const storage = new SQLiteAdapter(db);
  return new PodChain({ storage });
}

/**
 * Seeds a PodChain instance with a registered rider and a pending task,
 * returning everything needed to construct and submit a valid proof.
 */
export async function seedRiderAndTask(
  podchain: PodChain,
  tier: 1 | 2 | 3 = 1
): Promise<{
  riderId: string;
  taskId: string;
  keyPair: TestKeyPair;
  rawToken: string;
}> {
  const riderId = `rider_${crypto.randomUUID().slice(0, 8)}`;
  const keyPair = await generateTestKeyPair();

  await podchain.registerKey({ riderId, publicKey: keyPair.publicKeyJwk });

  const task = await podchain.createTask({
    riderId,
    recipientName: "Test Recipient",
    recipientPhone: "+2348012345678",
    deliveryAddress: "14 Broad Street, Lagos Island, Lagos",
    tier,
  });

  // For Tier 1, rawToken is the passive token
  // For Tier 2 in tests we use the OTP directly
  // For Tier 3 we use the nonce as the proof placeholder
  const rawToken =
    task.rawToken ?? task.otp ?? task.deepLinkNonce ?? "no-token";

  return { riderId, taskId: task.taskId, keyPair, rawToken };
}
