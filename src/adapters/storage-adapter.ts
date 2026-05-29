// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Storage Adapter Interface
//
// The StorageAdapter is the boundary between the protocol logic and the
// persistence layer. All database operations in the podchain library go
// through this interface — no module touches a database directly.
//
// This abstraction is what makes podchain a genuine drop-in library:
// platform operators substitute their own database (PostgreSQL, DynamoDB,
// MongoDB, etc.) by implementing this interface, without modifying any
// protocol logic. The SQLiteAdapter in this package is the reference
// implementation for the demonstration system.
// ─────────────────────────────────────────────────────────────────────────────

import type {
  StoredKey,
  StoredTask,
  StoredToken,
  StoredProof,
} from "../types.ts";

export abstract class StorageAdapter {

  // ── Key Registry ────────────────────────────────────────────────────────────

  /**
   * Persists a rider's public key to the key registry.
   * Implementations must reject duplicate riderIds.
   */
  abstract saveKey(key: StoredKey): Promise<void>;

  /**
   * Retrieves a stored key by rider ID.
   * Returns null if the rider has no registered key.
   */
  abstract getKey(riderId: string): Promise<StoredKey | null>;

  /**
   * Sets the revoked_at timestamp on a key record.
   * The key record is retained for audit purposes — historical proofs
   * signed by the key before revocation remain verifiable.
   */
  abstract revokeKey(riderId: string, revokedAt: string): Promise<void>;

  // ── Tasks ───────────────────────────────────────────────────────────────────

  /**
   * Persists a new delivery task.
   */
  abstract saveTask(task: StoredTask): Promise<void>;

  /**
   * Retrieves a task by its ID.
   * Returns null if not found.
   */
  abstract getTask(taskId: string): Promise<StoredTask | null>;

  /**
   * Updates the status of a task (e.g. "pending" → "completed").
   */
  abstract updateTaskStatus(taskId: string, status: string): Promise<void>;

  // ── Recipient Tokens ────────────────────────────────────────────────────────

  /**
   * Persists a new RecipientToken for a task.
   * One task has exactly one token at any given time.
   */
  abstract saveToken(token: StoredToken): Promise<void>;

  /**
   * Retrieves the RecipientToken for a task.
   * Returns null if no token has been issued for this task.
   */
  abstract getToken(taskId: string): Promise<StoredToken | null>;

  /**
   * Atomically marks a token as consumed.
   *
   * CRITICAL: This must be implemented as a single atomic database operation
   * (e.g. UPDATE WHERE consumed = false) to prevent race conditions where
   * two concurrent submissions both read consumed=false and both attempt
   * to consume the same token.
   *
   * Returns true if the token was successfully consumed.
   * Returns false if the token was already consumed (concurrent submission).
   */
  abstract consumeToken(tokenId: string): Promise<boolean>;

  /**
   * Updates the tokenHash field of an existing token record.
   * Used exclusively by the Tier 3 flow: after the recipient completes
   * the WebCrypto signing page, the nonce hash is replaced with the
   * full recipient confirmation JSON, which is later embedded in the
   * Proof Certificate.
   */
  abstract updateTokenData(tokenId: string, newTokenHash: string): Promise<void>;

  // ── Proof Certificates ──────────────────────────────────────────────────────

  /**
   * Persists a completed Proof Certificate.
   * This is an append-only operation — certificates are never updated.
   */
  abstract saveProof(proof: StoredProof): Promise<void>;

  /**
   * Retrieves the Proof Certificate for a completed task.
   * Returns null if the task has no accepted proof.
   */
  abstract getProof(taskId: string): Promise<StoredProof | null>;

  /**
   * Retrieves the most recently inserted Proof Certificate.
   * Used by the Hash Chain Manager to obtain the prev_hash for new insertions.
   * Returns null if the chain is empty (no proofs yet).
   */
  abstract getLastProof(): Promise<StoredProof | null>;

  /**
   * Retrieves all Proof Certificates in chain order (ascending by chain_position).
   * Used by the chain verification endpoint.
   * For large chains, implementations may wish to stream rather than load all
   * records into memory — this interface can be extended with a streaming
   * variant in future versions.
   */
  abstract getAllProofsOrdered(): Promise<StoredProof[]>;
}
