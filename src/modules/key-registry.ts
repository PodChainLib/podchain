// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Key Registry Module
//
// Manages the lifecycle of rider public keys: registration, retrieval,
// import as CryptoKey objects for verification, and revocation.
//
// The Key Registry is the trust anchor of the entire protocol.
// A fraudulent public key registered here would allow fabricated proofs,
// so registration must always be gated by the platform's authenticated
// rider onboarding flow.
// ─────────────────────────────────────────────────────────────────────────────

import { StorageAdapter } from "../adapters/storage-adapter.ts";
import { importPublicKey } from "../crypto/utils.ts";
import { PodChainError } from "../errors.ts";
import type { PublicKeyJWK, StoredKey } from "../types.ts";

export class KeyRegistry {
  constructor(private readonly storage: StorageAdapter) {}

  /**
   * Registers a rider's public key with the platform.
   * Validates that the JWK describes a P-256 ECDSA key before persisting.
   * Rejects duplicate rider IDs unconditionally.
   */
  async register(riderId: string, publicKey: PublicKeyJWK): Promise<StoredKey> {
    // Validate the key format by attempting to import it.
    // importPublicKey() throws KEY_FORMAT_INVALID if the JWK is invalid.
    await importPublicKey(publicKey);

    // Check for duplicate registration
    const existing = await this.storage.getKey(riderId);
    if (existing) {
      throw new PodChainError(
        "RIDER_ALREADY_EXISTS",
        `A key is already registered for rider ${riderId}. ` +
          `To rotate keys, revoke the existing key first.`
      );
    }

    const storedKey: StoredKey = {
      riderId,
      publicKeyJwk: publicKey,
      curve: "P-256",
      registeredAt: new Date().toISOString(),
      revokedAt: null,
    };

    await this.storage.saveKey(storedKey);
    return storedKey;
  }

  /**
   * Retrieves a rider's stored key record.
   * Throws KEY_NOT_FOUND if the rider has no registered key.
   * Throws KEY_REVOKED if the key exists but has been revoked.
   *
   * Revoked keys are not deleted — they are retained for audit.
   * Past proofs signed before revocation remain verifiable.
   */
  async getActiveKey(riderId: string): Promise<StoredKey> {
    const key = await this.storage.getKey(riderId);

    if (!key) {
      throw new PodChainError(
        "KEY_NOT_FOUND",
        `No key registered for rider ${riderId}`
      );
    }

    if (key.revokedAt !== null) {
      throw new PodChainError(
        "KEY_REVOKED",
        `The key for rider ${riderId} was revoked at ${key.revokedAt}. ` +
          `The rider must re-register from a new device.`
      );
    }

    return key;
  }

  /**
   * Imports the stored JWK as a CryptoKey object ready for signature verification.
   * This is called immediately before verification in the pipeline —
   * the CryptoKey is not cached, keeping key management simple.
   */
  async importForVerification(key: StoredKey): Promise<CryptoKey> {
    return importPublicKey(key.publicKeyJwk);
  }

  /**
   * Revokes a rider's key.
   * After revocation, all future proof submissions from this rider are rejected.
   * Past proofs signed before the revocation timestamp remain valid.
   */
  async revoke(riderId: string): Promise<void> {
    const key = await this.storage.getKey(riderId);

    if (!key) {
      throw new PodChainError(
        "KEY_NOT_FOUND",
        `No key registered for rider ${riderId}`
      );
    }

    if (key.revokedAt !== null) {
      // Idempotent — revoking an already-revoked key is not an error
      return;
    }

    await this.storage.revokeKey(riderId, new Date().toISOString());
  }
}
