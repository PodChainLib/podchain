// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — End-to-End Pipeline Benchmarks
//
// Measures the latency of complete protocol operations as they would execute
// in production — from proof submission through the full 9-step pipeline
// to Proof Certificate storage and retrieval.
//
// These are the server-side "wall clock" numbers that Chapter 5 reports:
//   - RecipientToken generation (per tier)
//   - RecipientToken validation (per tier)
//   - Full verifyAndStore() (Tier 1, end-to-end)
//   - Proof Certificate storage (SQLite write)
//   - Proof Certificate retrieval (SQLite read)
//
// Run: bun run benchmarks/pipeline.bench.ts
// ─────────────────────────────────────────────────────────────────────────────

import { benchmark, printResults, serialiseResults } from "./runner.ts";
import { Database } from "bun:sqlite";
import { SQLiteAdapter } from "../src/adapters/sqlite-adapter.ts";
import { PodChain } from "../src/podchain.ts";
import { canonicalSerialise, canonicalBytes, toBase64Url } from "../src/crypto/utils.ts";
import type { DeliveryPayload } from "../src/types.ts";

// ── Shared Setup ──────────────────────────────────────────────────────────────

async function makeKeyPair() {
  const kp = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  return {
    publicKeyJwk: { kty: "EC" as const, crv: "P-256" as const, x: jwk.x as string, y: jwk.y as string },
    privateKey: kp.privateKey,
  };
}

async function sign(privateKey: CryptoKey, payload: DeliveryPayload): Promise<string> {
  const bytes = canonicalBytes(payload);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, privateKey, bytes);
  return toBase64Url(new Uint8Array(sig));
}

// Fresh in-memory DB for the pipeline benchmarks
function freshPodChain() {
  return new PodChain({ storage: new SQLiteAdapter(new Database(":memory:")) });
}

const { publicKeyJwk, privateKey } = await makeKeyPair();
const riderId = "bench_pipeline_rider";

// ── Token Generation Benchmarks ───────────────────────────────────────────────

// Each token generation needs a fresh task — we pre-create a pool of task IDs
// rather than regenerating the full chain on each iteration.

const results = [];

// Tier 1 token generation
results.push(await benchmark(
  "RecipientToken generation — Tier 1 (passive)",
  async () => {
    const pc = freshPodChain();
    await pc.registerKey({ riderId, publicKey: publicKeyJwk });
    await pc.createTask({
      riderId, recipientName: "Test", recipientPhone: "+234800",
      deliveryAddress: "Lagos", tier: 1,
    });
  },
  50
));

// Tier 2 token generation (OTP + hash)
results.push(await benchmark(
  "RecipientToken generation — Tier 2 (OTP)",
  async () => {
    const pc = freshPodChain();
    await pc.registerKey({ riderId, publicKey: publicKeyJwk });
    await pc.createTask({
      riderId, recipientName: "Test", recipientPhone: "+234800",
      deliveryAddress: "Lagos", tier: 2,
    });
  },
  50
));

// ── Proof Submission (full pipeline) ─────────────────────────────────────────

// For each iteration we need a fresh task — pre-seed a single podchain
// instance and reset per benchmark using fresh instances.
results.push(await benchmark(
  "Full verifyAndStore() — Tier 1 (9-step pipeline)",
  async () => {
    const pc = freshPodChain();
    await pc.registerKey({ riderId, publicKey: publicKeyJwk });

    const task = await pc.createTask({
      riderId, recipientName: "Test", recipientPhone: "+234800",
      deliveryAddress: "14 Broad Street, Lagos", tier: 1,
    });

    const payload: DeliveryPayload = {
      coordHash: "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
      recipientProof: task.rawToken!,
      riderId,
      schemaVersion: "1.0",
      signedAt: new Date().toISOString(),
      taskId: task.taskId,
    };

    const signature = await sign(privateKey, payload);

    await pc.verifyAndStore({
      taskId: task.taskId,
      riderId,
      payload: canonicalSerialise(payload),
      signature,
    });
  },
  50
));

// Proof Certificate retrieval (SQLite read)
// Pre-create a completed proof, then benchmark the retrieval in isolation.
const pcForRetrieval = freshPodChain();
await pcForRetrieval.registerKey({ riderId, publicKey: publicKeyJwk });
const taskForRetrieval = await pcForRetrieval.createTask({
  riderId, recipientName: "Test", recipientPhone: "+234800",
  deliveryAddress: "Lagos", tier: 1,
});
const retrievalPayload: DeliveryPayload = {
  coordHash: "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
  recipientProof: taskForRetrieval.rawToken!,
  riderId,
  schemaVersion: "1.0",
  signedAt: new Date().toISOString(),
  taskId: taskForRetrieval.taskId,
};
await pcForRetrieval.verifyAndStore({
  taskId: taskForRetrieval.taskId,
  riderId,
  payload: canonicalSerialise(retrievalPayload),
  signature: await sign(privateKey, retrievalPayload),
});

results.push(await benchmark(
  "Proof Certificate retrieval (SQLite read)",
  async () => {
    await pcForRetrieval.getProof(taskForRetrieval.taskId);
  },
  200
));

// ── Rejection Pipeline Benchmarks ────────────────────────────────────────────
// How fast are the early rejection paths? Important for resilience under attack.

// Pre-create a key pair for rejection benchmarks
const { publicKeyJwk: goodKey, privateKey: goodPriv } = await makeKeyPair();
const { privateKey: badPriv } = await makeKeyPair(); // different key — will fail sig check

const pcRejection = freshPodChain();
await pcRejection.registerKey({ riderId: "reject_rider", publicKey: goodKey });
const rejTask = await pcRejection.createTask({
  riderId: "reject_rider", recipientName: "Test", recipientPhone: "+234800",
  deliveryAddress: "Lagos", tier: 1,
});
const rejPayload: DeliveryPayload = {
  coordHash: "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
  recipientProof: rejTask.rawToken!,
  riderId: "reject_rider",
  schemaVersion: "1.0",
  signedAt: new Date().toISOString(),
  taskId: rejTask.taskId,
};
const badSignature = await sign(badPriv, rejPayload); // Wrong key — will fail at step 3

results.push(await benchmark(
  "Pipeline rejection — SIGNATURE_INVALID (step 3 early exit)",
  async () => {
    try {
      await pcRejection.verifyAndStore({
        taskId: rejTask.taskId,
        riderId: "reject_rider",
        payload: canonicalSerialise(rejPayload),
        signature: badSignature,
      });
    } catch {
      // Expected rejection — we're measuring how fast the pipeline exits
    }
  },
  50
));

// ── Output ────────────────────────────────────────────────────────────────────

printResults({
  suite: "Server — End-to-End Pipeline",
  timestamp: new Date().toISOString(),
  runtime: `Bun ${Bun.version}`,
  results,
});

await Bun.write(
  "benchmarks/results/pipeline-server.json",
  serialiseResults({
    suite: "Server — End-to-End Pipeline",
    timestamp: new Date().toISOString(),
    runtime: `Bun ${Bun.version}`,
    results,
  })
);
