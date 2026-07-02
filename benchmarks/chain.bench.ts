// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Hash Chain Benchmarks
//
// Measures the latency of hash chain operations at representative scale:
//   - Chain hash computation per record (single append)
//   - Full chain verification at 10, 100, and 1,000 records
//
// The 1,000-record verification benchmark directly answers whether the chain
// verification endpoint is practical for use in legal audit contexts,
// as stated in Chapter 5 (threshold: < 2,000ms).
//
// Run: bun run benchmarks/chain.bench.ts
// ─────────────────────────────────────────────────────────────────────────────

import { benchmark, printResults, serialiseResults } from "./runner.ts";
import { Database } from "bun:sqlite";
import { SQLiteAdapter } from "../src/adapters/sqlite-adapter.ts";
import { PodChain } from "../src/podchain.ts";
import { canonicalBytes, toBase64Url } from "../src/crypto/utils.ts";
import type { DeliveryPayload } from "../src/types.ts";

// ── Helpers ───────────────────────────────────────────────────────────────────

async function generateKeyPair() {
  const kp = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  return {
    publicKeyJwk: { kty: "EC" as const, crv: "P-256" as const, x: jwk.x as string, y: jwk.y as string },
    privateKey: kp.privateKey,
  };
}

async function signPayload(privateKey: CryptoKey, payload: DeliveryPayload): Promise<string> {
  const bytes = canonicalBytes(payload);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, privateKey, bytes);
  return toBase64Url(new Uint8Array(sig));
}

/**
 * Seeds a PodChain instance with n verified proof records.
 * Returns the populated instance ready for chain verification benchmarking.
 */
async function seedChain(n: number): Promise<PodChain> {
  const db = new Database(":memory:");
  const podchain = new PodChain({ storage: new SQLiteAdapter(db) });

  const { publicKeyJwk, privateKey } = await generateKeyPair();
  const riderId = "bench_rider";
  await podchain.registerKey({ riderId, publicKey: publicKeyJwk });

  for (let i = 0; i < n; i++) {
    const task = await podchain.createTask({
      riderId,
      recipientName: `Recipient ${i}`,
      recipientPhone: "+2348012345678",
      deliveryAddress: `${i} Broad Street, Lagos`,
      tier: 1,
    });

    const payload: DeliveryPayload = {
      coordHash: "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
      recipientProof: task.rawToken!,
      riderId,
      schemaVersion: "1.0",
      signedAt: new Date().toISOString(),
      taskId: task.taskId,
    };

    const signature = await signPayload(privateKey, payload);

    await podchain.verifyAndStore({
      taskId: task.taskId,
      riderId,
      payload: JSON.stringify(
        Object.fromEntries(Object.entries(payload).sort(([a], [b]) => a.localeCompare(b)))
      ),
      signature,
    });
  }

  return podchain;
}

// ── Seed chains of different sizes ───────────────────────────────────────────

console.log("Seeding chains for verification benchmarks (this may take a moment)…");

const chain10   = await seedChain(10);
const chain100  = await seedChain(100);
const chain1000 = await seedChain(1000);

console.log("Chains ready. Running benchmarks…\n");

// ── Single record hash computation ───────────────────────────────────────────

// A standalone chain hash computation is just a SHA-256 of ~600 bytes of JSON.
// We benchmark it in isolation to establish the per-record cost.
const { sha256Hex } = await import("../src/crypto/utils.ts");
const representativeCertJson = JSON.stringify({
  chainHash: "",
  chainPosition: 1,
  coordHash: "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
  offlineSubmitted: false,
  prevHash: "0".repeat(64),
  proofId: crypto.randomUUID(),
  receivedAt: "2024-11-15T10:32:01.000Z",
  recipientProof: "e9d2c1b3",
  riderId: "rider_emeka_001",
  riderSignature: "A".repeat(86),
  schemaVersion: "1.0",
  signedAt: "2024-11-15T10:32:00.000Z",
  signedPayload: '{"coordHash":"a3f1b2c4","recipientProof":"e9d2c1b3","riderId":"rider_emeka_001","schemaVersion":"1.0","signedAt":"2024-11-15T10:32:00.000Z","taskId":"task_abc123"}',
  taskId: "task_abc123def456",
  tier: 1,
});

const results = await Promise.all([

  benchmark(
    "Chain hash computation (single record)",
    async () => { await sha256Hex(representativeCertJson); },
    500
  ),

  benchmark(
    "Chain verification — 10 records",
    async () => { await chain10.verifyChain(); },
    50
  ),

  benchmark(
    "Chain verification — 100 records",
    async () => { await chain100.verifyChain(); },
    20
  ),

  benchmark(
    "Chain verification — 1,000 records",
    async () => { await chain1000.verifyChain(); },
    10
  ),

]);

printResults({
  suite: "Server — Hash Chain Operations",
  timestamp: new Date().toISOString(),
  runtime: `Bun ${Bun.version}`,
  results,
});

await Bun.write(
  "benchmarks/results/chain-server.json",
  serialiseResults({
    suite: "Server — Hash Chain Operations",
    timestamp: new Date().toISOString(),
    runtime: `Bun ${Bun.version}`,
    results,
  })
);
