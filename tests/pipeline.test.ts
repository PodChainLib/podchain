// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Verification Pipeline Integration Tests
// Covers all correctness, attack simulation, and chain integrity scenarios
// from Chapter 5 of the thesis.
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect, beforeEach } from "bun:test";
import { PodChain } from "../src/podchain.ts";
import { canonicalSerialise } from "../src/crypto/utils.ts";
import {
  createTestPodChain,
  generateTestKeyPair,
  signPayload,
  buildTestPayload,
  seedRiderAndTask,
} from "./helpers.ts";

// ── CT: Correctness Tests ─────────────────────────────────────────────────────

describe("CT — Correctness Tests", () => {
  let podchain: PodChain;

  beforeEach(() => {
    podchain = createTestPodChain();
  });

  it("CT-01: accepts a valid Tier 1 proof and issues a Proof Certificate", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);

    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
    const signature = await signPayload(keyPair.privateKey, payload);

    const cert = await podchain.verifyAndStore({
      taskId, riderId,
      payload: canonicalSerialise(payload),
      signature,
    });

    expect(cert.proofId).toBeDefined();
    expect(cert.taskId).toBe(taskId);
    expect(cert.riderId).toBe(riderId);
    expect(cert.chainHash).toHaveLength(64);
    expect(cert.chainPosition).toBe(1);
    expect(cert.tier).toBe(1);
  });

  it("CT-02: accepts a valid Tier 2 proof with correct OTP", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 2);

    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
    const signature = await signPayload(keyPair.privateKey, payload);

    const cert = await podchain.verifyAndStore({
      taskId, riderId,
      payload: canonicalSerialise(payload),
      signature,
    });

    expect(cert.tier).toBe(2);
    expect(cert.offlineSubmitted).toBe(false);
  });

  it("CT-03: the Proof Certificate contains the coordHash from the payload", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
    const coordHash = "f1e2d3c4b5a697887766554433221100f1e2d3c4b5a697887766554433221100";

    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken, coordHash });
    const signature = await signPayload(keyPair.privateKey, payload);

    const cert = await podchain.verifyAndStore({
      taskId, riderId,
      payload: canonicalSerialise(payload),
      signature,
    });

    expect(cert.coordHash).toBe(coordHash);
  });

  it("CT-04: sets offlineSubmitted flag when signedAt is 2 hours before receivedAt", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);

    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken, signedAt: twoHoursAgo });
    const signature = await signPayload(keyPair.privateKey, payload);

    const cert = await podchain.verifyAndStore({
      taskId, riderId,
      payload: canonicalSerialise(payload),
      signature,
    });

    expect(cert.offlineSubmitted).toBe(true);
  });

  it("CT-05: a second call to getProof returns the stored certificate", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
    const signature = await signPayload(keyPair.privateKey, payload);

    await podchain.verifyAndStore({ taskId, riderId, payload: canonicalSerialise(payload), signature });

    const retrieved = await podchain.getProof(taskId);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.taskId).toBe(taskId);
  });

  it("CT-06: chain position increments correctly across multiple proofs", async () => {
    const results = [];

    for (let i = 0; i < 3; i++) {
      const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
      const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
      const signature = await signPayload(keyPair.privateKey, payload);
      const cert = await podchain.verifyAndStore({ taskId, riderId, payload: canonicalSerialise(payload), signature });
      results.push(cert.chainPosition);
    }

    expect(results).toEqual([1, 2, 3]);
  });
});

// ── CT: Rejection Tests ───────────────────────────────────────────────────────

describe("CT — Rejection Tests", () => {
  let podchain: PodChain;

  beforeEach(() => {
    podchain = createTestPodChain();
  });

  it("CT-07: rejects a proof with an invalid ECDSA signature (bit-flip)", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
    const validSignature = await signPayload(keyPair.privateKey, payload);

    // Flip the last character of the base64url signature
    const tampered = validSignature.slice(0, -1) + (validSignature.endsWith("a") ? "b" : "a");

    await expect(
      podchain.verifyAndStore({ taskId, riderId, payload: canonicalSerialise(payload), signature: tampered })
    ).rejects.toMatchObject({ code: "SIGNATURE_INVALID" });
  });

  it("CT-08: rejects a proof signed by an unregistered key", async () => {
    const { riderId, taskId, rawToken } = await seedRiderAndTask(podchain, 1);
    const { privateKey: foreignKey } = await generateTestKeyPair(); // different key pair

    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
    const signature = await signPayload(foreignKey, payload);

    await expect(
      podchain.verifyAndStore({ taskId, riderId, payload: canonicalSerialise(payload), signature })
    ).rejects.toMatchObject({ code: "SIGNATURE_INVALID" });
  });

  it("CT-09: rejects a proof when the rider's key is revoked", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
    await podchain.revokeKey({ riderId }); // revoke before submission

    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
    const signature = await signPayload(keyPair.privateKey, payload);

    await expect(
      podchain.verifyAndStore({ taskId, riderId, payload: canonicalSerialise(payload), signature })
    ).rejects.toMatchObject({ code: "KEY_REVOKED" });
  });

  it("CT-10: rejects a malformed payload missing a required field", async () => {
    const { riderId, taskId } = await seedRiderAndTask(podchain, 1);
    const { privateKey } = await generateTestKeyPair();

    // Payload missing coordHash
    const incomplete = JSON.stringify({ taskId, riderId, signedAt: new Date().toISOString() });

    await expect(
      podchain.verifyAndStore({ taskId, riderId, payload: incomplete, signature: "any" })
    ).rejects.toMatchObject({ code: "PAYLOAD_MALFORMED" });
  });

  it("CT-11: rejects a payload that is not valid JSON", async () => {
    const { riderId, taskId } = await seedRiderAndTask(podchain, 1);

    await expect(
      podchain.verifyAndStore({ taskId, riderId, payload: "not json at all", signature: "any" })
    ).rejects.toMatchObject({ code: "PAYLOAD_MALFORMED" });
  });

  it("CT-12: rejects when the wrong OTP is submitted for a Tier 2 task", async () => {
    const { riderId, taskId, keyPair } = await seedRiderAndTask(podchain, 2);

    const payload = buildTestPayload({ taskId, riderId, recipientProof: "000000" }); // wrong OTP
    const signature = await signPayload(keyPair.privateKey, payload);

    await expect(
      podchain.verifyAndStore({ taskId, riderId, payload: canonicalSerialise(payload), signature })
    ).rejects.toMatchObject({ code: "TOKEN_INVALID" });
  });
});

// ── AT: Attack Simulation Tests ───────────────────────────────────────────────

describe("AT — Attack Simulation Tests", () => {
  let podchain: PodChain;

  beforeEach(() => {
    podchain = createTestPodChain();
  });

  it("AT-01: REPLAY ATTACK — rejects a resubmission of an already-accepted proof", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
    const signature = await signPayload(keyPair.privateKey, payload);
    const input = { taskId, riderId, payload: canonicalSerialise(payload), signature };

    // First submission — should succeed
    await podchain.verifyAndStore(input);

    // Replay — must be rejected
    await expect(podchain.verifyAndStore(input)).rejects.toMatchObject({
      code: "TASK_ALREADY_COMPLETED",
    });
  });

  it("AT-02: PAYLOAD TAMPERING — rejects a proof whose payload was modified after signing", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
    const signature = await signPayload(keyPair.privateKey, payload);

    // Tamper: change the taskId in the serialised payload string
    const tamperedPayload = canonicalSerialise({ ...payload, coordHash: "0".repeat(64) });

    await expect(
      podchain.verifyAndStore({ taskId, riderId, payload: tamperedPayload, signature })
    ).rejects.toMatchObject({ code: "SIGNATURE_INVALID" });
  });

  it("AT-03: TOKEN REUSE — rejects use of a consumed Tier 1 token on a second task", async () => {
    const { riderId, keyPair, rawToken: token1, taskId: task1 } =
      await seedRiderAndTask(podchain, 1);

    // Submit and complete task 1
    const p1 = buildTestPayload({ taskId: task1, riderId, recipientProof: token1 });
    const s1 = await signPayload(keyPair.privateKey, p1);
    await podchain.verifyAndStore({ taskId: task1, riderId, payload: canonicalSerialise(p1), signature: s1 });

    // Create a second task — it gets its own independent token
    const task2 = await podchain.createTask({
      riderId, recipientName: "Another Recipient", recipientPhone: "+2348099999999",
      deliveryAddress: "Somewhere else", tier: 1,
    });

    // Try to use task 1's already-consumed token on task 2
    const p2 = buildTestPayload({ taskId: task2.taskId, riderId, recipientProof: token1 });
    const s2 = await signPayload(keyPair.privateKey, p2);

    await expect(
      podchain.verifyAndStore({ taskId: task2.taskId, riderId, payload: canonicalSerialise(p2), signature: s2 })
    ).rejects.toMatchObject({ code: "TOKEN_INVALID" });
  });

  it("AT-04: REVOKED KEY — rejects a submission from a rider whose key was revoked", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
    await podchain.revokeKey({ riderId });

    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
    const signature = await signPayload(keyPair.privateKey, payload);

    await expect(
      podchain.verifyAndStore({ taskId, riderId, payload: canonicalSerialise(payload), signature })
    ).rejects.toMatchObject({ code: "KEY_REVOKED" });
  });

  it("AT-05: FRAUDULENT KEY REGISTRATION — rejects a malformed JWK", async () => {
    await expect(
      podchain.registerKey({
        riderId: "attacker_001",
        publicKey: { kty: "EC", crv: "P-384", x: "bad", y: "data" } as never,
      })
    ).rejects.toMatchObject({ code: "KEY_FORMAT_INVALID" });
  });

  it("AT-06: CLOCK SKEW >24h — rejects a proof with a timestamp more than 24 hours old", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
    const thirtyHoursAgo = new Date(Date.now() - 30 * 60 * 60 * 1000).toISOString();

    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken, signedAt: thirtyHoursAgo });
    const signature = await signPayload(keyPair.privateKey, payload);

    await expect(
      podchain.verifyAndStore({ taskId, riderId, payload: canonicalSerialise(payload), signature })
    ).rejects.toMatchObject({ code: "TIMESTAMP_OUT_OF_RANGE" });
  });

  it("AT-07: CLOCK SKEW within 24h — accepts with offline_submitted flag", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
    const eighteenHoursAgo = new Date(Date.now() - 18 * 60 * 60 * 1000).toISOString();

    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken, signedAt: eighteenHoursAgo });
    const signature = await signPayload(keyPair.privateKey, payload);

    const cert = await podchain.verifyAndStore({
      taskId, riderId, payload: canonicalSerialise(payload), signature,
    });

    expect(cert.offlineSubmitted).toBe(true);
  });

  it("AT-08: DUPLICATE RIDER REGISTRATION — rejects a second key registration for the same rider", async () => {
    const riderId = "rider_dup_test";
    const { publicKeyJwk: key1 } = await generateTestKeyPair();
    const { publicKeyJwk: key2 } = await generateTestKeyPair();

    await podchain.registerKey({ riderId, publicKey: key1 });

    await expect(
      podchain.registerKey({ riderId, publicKey: key2 })
    ).rejects.toMatchObject({ code: "RIDER_ALREADY_EXISTS" });
  });
});

// ── Chain Integrity Tests ─────────────────────────────────────────────────────

describe("HCT — Hash Chain Integrity Tests", () => {
  let podchain: PodChain;

  beforeEach(() => {
    podchain = createTestPodChain();
  });

  it("HCT-01: verifyChain returns intact for an empty chain", async () => {
    const report = await podchain.verifyChain();
    expect(report.chainIntact).toBe(true);
    expect(report.recordsChecked).toBe(0);
  });

  it("HCT-02: verifyChain returns intact after valid proof insertions", async () => {
    for (let i = 0; i < 5; i++) {
      const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
      const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
      const signature = await signPayload(keyPair.privateKey, payload);
      await podchain.verifyAndStore({ taskId, riderId, payload: canonicalSerialise(payload), signature });
    }

    const report = await podchain.verifyChain();
    expect(report.chainIntact).toBe(true);
    expect(report.recordsChecked).toBe(5);
    expect(report.terminalHash).toHaveLength(64);
  });

  it("HCT-03: each proof's prevHash equals the preceding proof's chainHash", async () => {
    const certs = [];

    for (let i = 0; i < 3; i++) {
      const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
      const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
      const signature = await signPayload(keyPair.privateKey, payload);
      const cert = await podchain.verifyAndStore({ taskId, riderId, payload: canonicalSerialise(payload), signature });
      certs.push(cert);
    }

    // Each cert's prevHash should match the preceding cert's chainHash
    expect(certs[1]!.prevHash).toBe(certs[0]!.chainHash);
    expect(certs[2]!.prevHash).toBe(certs[1]!.chainHash);
  });

  it("HCT-04: getProof returns null for a task with no proof", async () => {
    const result = await podchain.getProof("nonexistent_task");
    expect(result).toBeNull();
  });
});

// ── Key Registry Tests ────────────────────────────────────────────────────────

describe("KR — Key Registry Tests", () => {
  let podchain: PodChain;

  beforeEach(() => {
    podchain = createTestPodChain();
  });

  it("KR-01: allows a valid key to be registered and retrieved via proof submission", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
    const signature = await signPayload(keyPair.privateKey, payload);

    const cert = await podchain.verifyAndStore({ taskId, riderId, payload: canonicalSerialise(payload), signature });
    expect(cert.riderId).toBe(riderId);
  });

  it("KR-02: revoking a key is idempotent — revoking twice does not throw", async () => {
    const riderId = "rider_idempotent";
    const { publicKeyJwk } = await generateTestKeyPair();

    await podchain.registerKey({ riderId, publicKey: publicKeyJwk });
    await podchain.revokeKey({ riderId });

    await expect(podchain.revokeKey({ riderId })).resolves.toBeUndefined();
  });

  it("KR-03: revoking a non-existent rider throws KEY_NOT_FOUND", async () => {
    await expect(
      podchain.revokeKey({ riderId: "ghost_rider" })
    ).rejects.toMatchObject({ code: "KEY_NOT_FOUND" });
  });

  it("KR-04: proofs from before revocation are still retrievable", async () => {
    const { riderId, taskId, keyPair, rawToken } = await seedRiderAndTask(podchain, 1);
    const payload = buildTestPayload({ taskId, riderId, recipientProof: rawToken });
    const signature = await signPayload(keyPair.privateKey, payload);

    // Submit proof first, then revoke
    await podchain.verifyAndStore({ taskId, riderId, payload: canonicalSerialise(payload), signature });
    await podchain.revokeKey({ riderId });

    // The stored certificate is still retrievable
    const cert = await podchain.getProof(taskId);
    expect(cert).not.toBeNull();
    expect(cert!.riderId).toBe(riderId);
  });
});
