// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — SQLite Storage Adapter
//
// The reference StorageAdapter implementation for the demonstration system.
// Uses Bun's native bun:sqlite bindings — no ORM, no migrations library.
// Schema is initialised on construction with CREATE TABLE IF NOT EXISTS
// statements, making the adapter zero-configuration to use.
//
// In production, replace this with your platform's database adapter by
// extending StorageAdapter and implementing each abstract method.
// ─────────────────────────────────────────────────────────────────────────────

import { Database } from "bun:sqlite";
import { StorageAdapter } from "./storage-adapter.ts";
import type {
  StoredKey,
  StoredTask,
  StoredToken,
  StoredProof,
  Tier,
  SchemaVersion,
} from "../types.ts";

export class SQLiteAdapter extends StorageAdapter {
  private readonly db: Database;

  constructor(db: Database) {
    super();
    this.db = db;
    this.initialiseSchema();
  }

  // ── Schema Init ─────────────────────────────────────────────────────────────

  private initialiseSchema(): void {
    this.db.run("PRAGMA journal_mode = WAL;");
    this.db.run("PRAGMA foreign_keys = ON;");

    this.db.run(`
      CREATE TABLE IF NOT EXISTS riders (
        rider_id        TEXT PRIMARY KEY,
        registered_at   TEXT NOT NULL,
        status          TEXT NOT NULL DEFAULT 'active'
      )
    `);

    this.db.run(`
      CREATE TABLE IF NOT EXISTS key_registry (
        rider_id        TEXT PRIMARY KEY,
        public_key_jwk  TEXT NOT NULL,
        curve           TEXT NOT NULL DEFAULT 'P-256',
        registered_at   TEXT NOT NULL,
        revoked_at      TEXT,
        FOREIGN KEY (rider_id) REFERENCES riders(rider_id)
      )
    `);

    this.db.run(`
      CREATE TABLE IF NOT EXISTS tasks (
        task_id          TEXT PRIMARY KEY,
        rider_id         TEXT NOT NULL,
        recipient_name   TEXT NOT NULL,
        recipient_phone  TEXT NOT NULL,
        delivery_address TEXT NOT NULL,
        tier             INTEGER NOT NULL,
        status           TEXT NOT NULL DEFAULT 'pending',
        created_at       TEXT NOT NULL,
        FOREIGN KEY (rider_id) REFERENCES riders(rider_id)
      )
    `);

    this.db.run(`
      CREATE TABLE IF NOT EXISTS recipient_tokens (
        token_id    TEXT PRIMARY KEY,
        task_id     TEXT NOT NULL UNIQUE,
        token_hash  TEXT NOT NULL,
        tier        INTEGER NOT NULL,
        consumed    INTEGER NOT NULL DEFAULT 0,
        issued_at   TEXT NOT NULL,
        expires_at  TEXT,
        FOREIGN KEY (task_id) REFERENCES tasks(task_id)
      )
    `);

    this.db.run(`
      CREATE TABLE IF NOT EXISTS proof_certificates (
        proof_id          TEXT PRIMARY KEY,
        task_id           TEXT NOT NULL UNIQUE,
        rider_id          TEXT NOT NULL,
        signed_payload    TEXT NOT NULL,
        rider_signature   TEXT NOT NULL,
        recipient_proof   TEXT NOT NULL,
        coord_hash        TEXT NOT NULL,
        signed_at         TEXT NOT NULL,
        received_at       TEXT NOT NULL,
        offline_submitted INTEGER NOT NULL DEFAULT 0,
        prev_hash         TEXT NOT NULL,
        chain_hash        TEXT NOT NULL,
        chain_position    INTEGER NOT NULL,
        tier              INTEGER NOT NULL,
        schema_version    TEXT NOT NULL DEFAULT '1.0',
        FOREIGN KEY (task_id) REFERENCES tasks(task_id),
        FOREIGN KEY (rider_id) REFERENCES key_registry(rider_id)
      )
    `);

    // Index for fast chain traversal
    this.db.run(`
      CREATE INDEX IF NOT EXISTS idx_proofs_chain_position
        ON proof_certificates(chain_position ASC)
    `);
  }

  // ── Key Registry ────────────────────────────────────────────────────────────

  async saveKey(key: StoredKey): Promise<void> {
    this.db.run(
      `INSERT INTO riders (rider_id, registered_at) VALUES ($riderId, $registeredAt)`,
      { $riderId: key.riderId, $registeredAt: key.registeredAt }
    );
    this.db.run(
      `INSERT INTO key_registry
         (rider_id, public_key_jwk, curve, registered_at, revoked_at)
       VALUES ($riderId, $publicKeyJwk, $curve, $registeredAt, $revokedAt)`,
      {
        $riderId: key.riderId,
        $publicKeyJwk: JSON.stringify(key.publicKeyJwk),
        $curve: key.curve,
        $registeredAt: key.registeredAt,
        $revokedAt: key.revokedAt ?? null,
      }
    );
  }

  async getKey(riderId: string): Promise<StoredKey | null> {
    const row = this.db
      .prepare(
        `SELECT rider_id, public_key_jwk, curve, registered_at, revoked_at
         FROM key_registry WHERE rider_id = $riderId`
      )
      .get({ $riderId: riderId }) as RawKey | null;

    if (!row) return null;

    return {
      riderId: row.rider_id,
      publicKeyJwk: JSON.parse(row.public_key_jwk),
      curve: "P-256",
      registeredAt: row.registered_at,
      revokedAt: row.revoked_at ?? null,
    };
  }

  async revokeKey(riderId: string, revokedAt: string): Promise<void> {
    this.db.run(
      `UPDATE key_registry SET revoked_at = $revokedAt WHERE rider_id = $riderId`,
      { $revokedAt: revokedAt, $riderId: riderId }
    );
    this.db.run(
      `UPDATE riders SET status = 'revoked' WHERE rider_id = $riderId`,
      { $riderId: riderId }
    );
  }

  // ── Tasks ───────────────────────────────────────────────────────────────────

  async saveTask(task: StoredTask): Promise<void> {
    this.db.run(
      `INSERT INTO tasks
         (task_id, rider_id, recipient_name, recipient_phone, delivery_address,
          tier, status, created_at)
       VALUES
         ($taskId, $riderId, $recipientName, $recipientPhone, $deliveryAddress,
          $tier, $status, $createdAt)`,
      {
        $taskId: task.taskId,
        $riderId: task.riderId,
        $recipientName: task.recipientName,
        $recipientPhone: task.recipientPhone,
        $deliveryAddress: task.deliveryAddress,
        $tier: task.tier,
        $status: task.status,
        $createdAt: task.createdAt,
      }
    );
  }

  async getTask(taskId: string): Promise<StoredTask | null> {
    const row = this.db
      .prepare(
        `SELECT task_id, rider_id, recipient_name, recipient_phone,
                delivery_address, tier, status, created_at
         FROM tasks WHERE task_id = $taskId`
      )
      .get({ $taskId: taskId }) as RawTask | null;

    if (!row) return null;

    return {
      taskId: row.task_id,
      riderId: row.rider_id,
      recipientName: row.recipient_name,
      recipientPhone: row.recipient_phone,
      deliveryAddress: row.delivery_address,
      tier: row.tier as Tier,
      status: row.status as "pending" | "completed" | "cancelled",
      createdAt: row.created_at,
    };
  }

  async updateTaskStatus(taskId: string, status: string): Promise<void> {
    this.db.run(
      `UPDATE tasks SET status = $status WHERE task_id = $taskId`,
      { $status: status, $taskId: taskId }
    );
  }

  // ── Recipient Tokens ────────────────────────────────────────────────────────

  async saveToken(token: StoredToken): Promise<void> {
    this.db.run(
      `INSERT INTO recipient_tokens
         (token_id, task_id, token_hash, tier, consumed, issued_at, expires_at)
       VALUES
         ($tokenId, $taskId, $tokenHash, $tier, 0, $issuedAt, $expiresAt)`,
      {
        $tokenId: token.tokenId,
        $taskId: token.taskId,
        $tokenHash: token.tokenHash,
        $tier: token.tier,
        $issuedAt: token.issuedAt,
        $expiresAt: token.expiresAt ?? null,
      }
    );
  }

  async getToken(taskId: string): Promise<StoredToken | null> {
    const row = this.db
      .prepare(
        `SELECT token_id, task_id, token_hash, tier, consumed, issued_at, expires_at
         FROM recipient_tokens WHERE task_id = $taskId`
      )
      .get({ $taskId: taskId }) as RawToken | null;

    if (!row) return null;

    return {
      tokenId: row.token_id,
      taskId: row.task_id,
      tokenHash: row.token_hash,
      tier: row.tier as Tier,
      consumed: row.consumed === 1,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at ?? null,
    };
  }

  /**
   * Atomically consumes a token using a single UPDATE WHERE consumed = 0.
   * If another request has already consumed the token, this returns false
   * without any state change — the caller must reject the submission.
   */
  async consumeToken(tokenId: string): Promise<boolean> {
    const result = this.db.run(
      `UPDATE recipient_tokens SET consumed = 1
       WHERE token_id = $tokenId AND consumed = 0`,
      { $tokenId: tokenId }
    );
    return result.changes > 0;
  }

  async updateTokenData(tokenId: string, newTokenHash: string): Promise<void> {
    this.db.run(
      `UPDATE recipient_tokens SET token_hash = $tokenHash WHERE token_id = $tokenId`,
      { $tokenHash: newTokenHash, $tokenId: tokenId }
    );
  }

  // ── Proof Certificates ──────────────────────────────────────────────────────

  async saveProof(proof: StoredProof): Promise<void> {
    this.db.run(
      `INSERT INTO proof_certificates
         (proof_id, task_id, rider_id, signed_payload, rider_signature,
          recipient_proof, coord_hash, signed_at, received_at,
          offline_submitted, prev_hash, chain_hash, chain_position,
          tier, schema_version)
       VALUES
         ($proofId, $taskId, $riderId, $signedPayload, $riderSignature,
          $recipientProof, $coordHash, $signedAt, $receivedAt,
          $offlineSubmitted, $prevHash, $chainHash, $chainPosition,
          $tier, $schemaVersion)`,
      {
        $proofId: proof.proofId,
        $taskId: proof.taskId,
        $riderId: proof.riderId,
        $signedPayload: proof.signedPayload,
        $riderSignature: proof.riderSignature,
        $recipientProof: proof.recipientProof,
        $coordHash: proof.coordHash,
        $signedAt: proof.signedAt,
        $receivedAt: proof.receivedAt,
        $offlineSubmitted: proof.offlineSubmitted ? 1 : 0,
        $prevHash: proof.prevHash,
        $chainHash: proof.chainHash,
        $chainPosition: proof.chainPosition,
        $tier: proof.tier,
        $schemaVersion: proof.schemaVersion,
      }
    );
  }

  async getProof(taskId: string): Promise<StoredProof | null> {
    const row = this.db
      .prepare(`SELECT * FROM proof_certificates WHERE task_id = $taskId`)
      .get({ $taskId: taskId }) as RawProof | null;

    return row ? rawToProof(row) : null;
  }

  async getLastProof(): Promise<StoredProof | null> {
    const row = this.db
      .prepare(
        `SELECT * FROM proof_certificates ORDER BY chain_position DESC LIMIT 1`
      )
      .get() as RawProof | null;

    return row ? rawToProof(row) : null;
  }

  async getAllProofsOrdered(): Promise<StoredProof[]> {
    const rows = this.db
      .prepare(`SELECT * FROM proof_certificates ORDER BY chain_position ASC`)
      .all() as RawProof[];

    return rows.map(rawToProof);
  }
}

// ── Raw row types (SQLite returns plain objects) ──────────────────────────────

interface RawKey {
  rider_id: string;
  public_key_jwk: string;
  curve: string;
  registered_at: string;
  revoked_at: string | null;
}

interface RawTask {
  task_id: string;
  rider_id: string;
  recipient_name: string;
  recipient_phone: string;
  delivery_address: string;
  tier: number;
  status: string;
  created_at: string;
}

interface RawToken {
  token_id: string;
  task_id: string;
  token_hash: string;
  tier: number;
  consumed: number;
  issued_at: string;
  expires_at: string | null;
}

interface RawProof {
  proof_id: string;
  task_id: string;
  rider_id: string;
  signed_payload: string;
  rider_signature: string;
  recipient_proof: string;
  coord_hash: string;
  signed_at: string;
  received_at: string;
  offline_submitted: number;
  prev_hash: string;
  chain_hash: string;
  chain_position: number;
  tier: number;
  schema_version: string;
}

function rawToProof(row: RawProof): StoredProof {
  return {
    proofId: row.proof_id,
    taskId: row.task_id,
    riderId: row.rider_id,
    signedPayload: row.signed_payload,
    riderSignature: row.rider_signature,
    recipientProof: row.recipient_proof,
    coordHash: row.coord_hash,
    signedAt: row.signed_at,
    receivedAt: row.received_at,
    offlineSubmitted: row.offline_submitted === 1,
    prevHash: row.prev_hash,
    chainHash: row.chain_hash,
    chainPosition: row.chain_position,
    tier: row.tier as Tier,
    schemaVersion: row.schema_version as SchemaVersion,
  };
}
