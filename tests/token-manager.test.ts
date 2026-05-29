// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Token Manager Tests
// Covers token generation, validation, expiry, and Tier 3 confirmation
// for all three RecipientToken tiers.
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect, beforeEach } from "bun:test";
import { Database } from "bun:sqlite";
import { SQLiteAdapter } from "../src/adapters/sqlite-adapter.ts";
import { TokenManager } from "../src/modules/token-manager.ts";
import { sha256Hex, toBase64Url } from "../src/crypto/utils.ts";

function createTokenManager() {
  const db = new Database(":memory:");
  const storage = new SQLiteAdapter(db);

  // Insert a dummy task so FK constraints are satisfied
  db.run(`INSERT INTO riders (rider_id, registered_at, status) VALUES ('r1', '2024-01-01', 'active')`);
  db.run(`INSERT INTO key_registry (rider_id, public_key_jwk, curve, registered_at) VALUES ('r1', '{}', 'P-256', '2024-01-01')`);

  return { manager: new TokenManager(storage), storage, db };
}

function insertTask(db: Database, taskId: string, tier: number) {
  db.run(
    `INSERT INTO tasks (task_id, rider_id, recipient_name, recipient_phone,
     delivery_address, tier, status, created_at)
     VALUES ($id, 'r1', 'Test', '+234800', 'Lagos', $tier, 'pending', '2024-01-01')`,
    { $id: taskId, $tier: tier }
  );
}

// ── Tier 1 ────────────────────────────────────────────────────────────────────

describe("TokenManager — Tier 1 (Passive Token)", () => {
  it("generates a token and returns a raw token, no OTP or nonce", async () => {
    const { manager, db } = createTokenManager();
    const taskId = "task_t1_gen";
    insertTask(db, taskId, 1);

    const result = await manager.generateToken(taskId, 1);

    expect(result.tier).toBe(1);
    expect(result.rawToken).toBeDefined();
    expect(result.rawToken).not.toBeNull();
    expect(result.otp).toBeNull();
    expect(result.deepLinkNonce).toBeNull();
    expect(result.rawToken!.length).toBe(64); // 32 bytes as hex
  });

  it("stores only the SHA-256 hash — not the raw token value", async () => {
    const { manager, storage, db } = createTokenManager();
    const taskId = "task_t1_hash";
    insertTask(db, taskId, 1);

    const result = await manager.generateToken(taskId, 1);
    const stored = await storage.getToken(taskId);

    const expectedHash = await sha256Hex(result.rawToken!);
    expect(stored!.tokenHash).toBe(expectedHash);
    expect(stored!.tokenHash).not.toBe(result.rawToken);
  });

  it("validates the correct raw token", async () => {
    const { manager, db } = createTokenManager();
    const taskId = "task_t1_valid";
    insertTask(db, taskId, 1);

    const result = await manager.generateToken(taskId, 1);

    await expect(
      manager.validate(taskId, result.rawToken!)
    ).resolves.toBeDefined();
  });

  it("rejects an incorrect token", async () => {
    const { manager, db } = createTokenManager();
    const taskId = "task_t1_wrong";
    insertTask(db, taskId, 1);

    await manager.generateToken(taskId, 1);

    await expect(
      manager.validate(taskId, "completely-wrong-token")
    ).rejects.toMatchObject({ code: "TOKEN_INVALID" });
  });

  it("rejects a consumed token", async () => {
    const { manager, storage, db } = createTokenManager();
    const taskId = "task_t1_consumed";
    insertTask(db, taskId, 1);

    const result = await manager.generateToken(taskId, 1);
    const token = await storage.getToken(taskId);

    // Consume the token
    await storage.consumeToken(token!.tokenId);

    await expect(
      manager.validate(taskId, result.rawToken!)
    ).rejects.toMatchObject({ code: "TOKEN_CONSUMED" });
  });

  it("throws TOKEN_INVALID for a non-existent task", async () => {
    const { manager } = createTokenManager();

    await expect(
      manager.validate("nonexistent_task", "any-token")
    ).rejects.toMatchObject({ code: "TOKEN_INVALID" });
  });
});

// ── Tier 2 ────────────────────────────────────────────────────────────────────

describe("TokenManager — Tier 2 (OTP)", () => {
  it("generates a 6-digit OTP with an expiry timestamp", async () => {
    const { manager, storage, db } = createTokenManager();
    const taskId = "task_t2_gen";
    insertTask(db, taskId, 2);

    const result = await manager.generateToken(taskId, 2);
    const stored = await storage.getToken(taskId);

    expect(result.otp).not.toBeNull();
    expect(result.otp!.length).toBe(6);
    expect(/^\d{6}$/.test(result.otp!)).toBe(true);
    expect(stored!.expiresAt).not.toBeNull();
    expect(result.rawToken).toBeNull();
  });

  it("stores only the OTP hash — not the raw OTP", async () => {
    const { manager, storage, db } = createTokenManager();
    const taskId = "task_t2_hash";
    insertTask(db, taskId, 2);

    const result = await manager.generateToken(taskId, 2);
    const stored = await storage.getToken(taskId);
    const expectedHash = await sha256Hex(result.otp!);

    expect(stored!.tokenHash).toBe(expectedHash);
    expect(stored!.tokenHash).not.toBe(result.otp);
  });

  it("validates the correct OTP within the expiry window", async () => {
    const { manager, db } = createTokenManager();
    const taskId = "task_t2_valid";
    insertTask(db, taskId, 2);

    const result = await manager.generateToken(taskId, 2);

    await expect(
      manager.validate(taskId, result.otp!)
    ).resolves.toBeDefined();
  });

  it("rejects an incorrect OTP", async () => {
    const { manager, db } = createTokenManager();
    const taskId = "task_t2_wrong";
    insertTask(db, taskId, 2);

    await manager.generateToken(taskId, 2);

    await expect(
      manager.validate(taskId, "000000")
    ).rejects.toMatchObject({ code: "TOKEN_INVALID" });
  });

  it("AT-04: rejects an OTP that has passed its expiry time", async () => {
    const { manager, storage, db } = createTokenManager();
    const taskId = "task_t2_expired";
    insertTask(db, taskId, 2);

    await manager.generateToken(taskId, 2);
    const token = await storage.getToken(taskId);

    // Manually backdate the expiry to one hour ago
    const expiredAt = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    db.run(
      `UPDATE recipient_tokens SET expires_at = $exp WHERE token_id = $id`,
      { $exp: expiredAt, $id: token!.tokenId }
    );

    // Reload the token to get any value for the OTP hash check
    // We need to know the OTP — retrieve it by checking the hash
    // For this test, submit any 6-digit code — expiry check runs first
    await expect(
      manager.validate(taskId, "123456")
    ).rejects.toMatchObject({ code: "TOKEN_EXPIRED" });
  });

  it("expiry check precedes hash check — expired tokens rejected regardless of code", async () => {
    const { manager, storage, db } = createTokenManager();
    const taskId = "task_t2_expfirst";
    insertTask(db, taskId, 2);

    const result = await manager.generateToken(taskId, 2);
    const token = await storage.getToken(taskId);

    // Backdate expiry
    db.run(
      `UPDATE recipient_tokens SET expires_at = $exp WHERE token_id = $id`,
      { $exp: new Date(Date.now() - 1000).toISOString(), $id: token!.tokenId }
    );

    // Even the correct OTP is rejected because expiry is checked first
    await expect(
      manager.validate(taskId, result.otp!)
    ).rejects.toMatchObject({ code: "TOKEN_EXPIRED" });
  });
});

// ── Tier 3 ────────────────────────────────────────────────────────────────────

describe("TokenManager — Tier 3 (Two-Sided Signing)", () => {
  it("generates a nonce, no raw token or OTP", async () => {
    const { manager, db } = createTokenManager();
    const taskId = "task_t3_gen";
    insertTask(db, taskId, 3);

    const result = await manager.generateToken(taskId, 3);

    expect(result.deepLinkNonce).not.toBeNull();
    expect(result.deepLinkNonce!.length).toBe(32); // 16 bytes as hex
    expect(result.rawToken).toBeNull();
    expect(result.otp).toBeNull();
  });

  it("rejects a Tier 3 submission before the recipient has confirmed", async () => {
    const { manager, db } = createTokenManager();
    const taskId = "task_t3_noconf";
    insertTask(db, taskId, 3);

    await manager.generateToken(taskId, 3);

    // Attempt to validate before recipient confirmation step
    await expect(
      manager.validate(taskId, "any-proof")
    ).rejects.toMatchObject({ code: "RECIPIENT_PROOF_INVALID" });
  });
});

// ── General token behaviour ───────────────────────────────────────────────────

describe("TokenManager — general", () => {
  it("generates unique tokenIds across multiple calls", async () => {
    const { manager, db } = createTokenManager();
    const ids = new Set<string>();

    for (let i = 0; i < 20; i++) {
      const taskId = `task_unique_${i}`;
      insertTask(db, taskId, 1);
      const result = await manager.generateToken(taskId, 1);
      ids.add(result.tokenId);
    }

    expect(ids.size).toBe(20);
  });

  it("generates unique raw tokens across multiple calls", async () => {
    const { manager, db } = createTokenManager();
    const tokens = new Set<string>();

    for (let i = 0; i < 20; i++) {
      const taskId = `task_unique_tok_${i}`;
      insertTask(db, taskId, 1);
      const result = await manager.generateToken(taskId, 1);
      tokens.add(result.rawToken!);
    }

    expect(tokens.size).toBe(20);
  });
});
