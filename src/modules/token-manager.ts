// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — RecipientToken Manager
//
// Handles token generation and validation for all three RecipientToken tiers.
// The tier is determined at task creation and governs which generation and
// validation paths are used for the entire lifecycle of that task's token.
//
// Tier 1 — Passive Token:    platform-issued, no recipient action required
// Tier 2 — OTP Token:        recipient must share code; QR display variant
// Tier 3 — Two-Sided Signing: recipient signs in-browser via WebCrypto API
// ─────────────────────────────────────────────────────────────────────────────

import { StorageAdapter } from "../adapters/storage-adapter.ts";
import {
  generateRandomToken,
  generateOTP,
  sha256Hex,
  importPublicKey,
  verifySignature,
  canonicalBytes,
} from "../crypto/utils.ts";
import { PodChainError } from "../errors.ts";
import type {
  StoredToken,
  Tier,
  Tier3RecipientConfirmation,
} from "../types.ts";

// Tier 2 OTP expiry window — 30 minutes
const TIER2_EXPIRY_MINUTES = 30;

export interface GenerateTokenResult {
  tokenId: string;
  taskId: string;
  tier: Tier;
  /** Tier 1 only — raw passive token for the rider app to embed in the payload */
  rawToken: string | null;
  /** Tier 2 only — raw OTP to dispatch to the recipient via SMS */
  otp: string | null;
  /** Tier 3 only — nonce to embed in the recipient's deep link */
  deepLinkNonce: string | null;
}

export class TokenManager {
  constructor(private readonly storage: StorageAdapter) {}

  // ── Token Generation ────────────────────────────────────────────────────────

  /**
   * Generates a RecipientToken for the given task and tier.
   * Persists the token hash (never the raw value) to the token store.
   * Returns the raw value where applicable for the caller to dispatch.
   */
  async generateToken(taskId: string, tier: Tier): Promise<GenerateTokenResult> {
    const tokenId = crypto.randomUUID();
    const now = new Date().toISOString();
    let rawToken: string | null = null;
    let otp: string | null = null;
    let deepLinkNonce: string | null = null;
    let tokenHash: string;
    let expiresAt: string | null = null;

    switch (tier) {
      case 1: {
        // Tier 1: cryptographically random 32-byte token
        // The rider app embeds this directly in the signed payload.
        // No recipient action is required.
        rawToken = generateRandomToken(32);
        tokenHash = await sha256Hex(rawToken);
        break;
      }

      case 2: {
        // Tier 2: 6-digit OTP with a 30-minute expiry window.
        // The caller dispatches the raw OTP to the recipient via SMS.
        // Only the hash is stored — the server never retains the raw OTP.
        otp = generateOTP();
        tokenHash = await sha256Hex(otp);
        const expiry = new Date(Date.now() + TIER2_EXPIRY_MINUTES * 60 * 1000);
        expiresAt = expiry.toISOString();
        break;
      }

      case 3: {
        // Tier 3: random nonce embedded in the recipient's deep link.
        // The recipient's browser session signs a payload containing this nonce,
        // binding their confirmation to this specific task.
        deepLinkNonce = generateRandomToken(16);
        tokenHash = await sha256Hex(deepLinkNonce);
        break;
      }
    }

    const storedToken: StoredToken = {
      tokenId,
      taskId,
      tokenHash,
      tier,
      consumed: false,
      issuedAt: now,
      expiresAt,
    };

    await this.storage.saveToken(storedToken);

    return { tokenId, taskId, tier, rawToken, otp, deepLinkNonce };
  }

  // ── Recipient Confirmation (Tier 3) ─────────────────────────────────────────

  /**
   * Records the recipient's WebCrypto signature for a Tier 3 task.
   * Verifies the signature and nonce before updating the token record.
   * Called when the recipient completes the deep-link signing page.
   */
  async recordRecipientConfirmation(
    taskId: string,
    confirmation: Tier3RecipientConfirmation
  ): Promise<void> {
    const token = await this.storage.getToken(taskId);

    if (!token || token.tier !== 3) {
      throw new PodChainError(
        "TASK_NOT_FOUND",
        `No Tier 3 token found for task ${taskId}`
      );
    }

    // Verify the nonce in the recipient's signed payload matches what was issued
    const nonce = confirmation.signedPayload.nonce;
    const expectedNonceHash = await sha256Hex(nonce);
    if (expectedNonceHash !== token.tokenHash) {
      throw new PodChainError(
        "RECIPIENT_PROOF_INVALID",
        "Nonce in recipient payload does not match the stored token"
      );
    }

    // Verify the recipient's ECDSA signature over their signed payload
    const recipientKey = await importPublicKey(confirmation.sessionPublicKey);
    const payloadBytes = canonicalBytes({
      coordHash: "",  // not present — use the raw payload for recipient signing
      recipientProof: "",
      riderId: "",
      schemaVersion: "1.0",
      signedAt: confirmation.signedPayload.timestamp,
      taskId: confirmation.signedPayload.taskId,
    });

    // For Tier 3 recipient signing we serialise the exact object the browser signed
    const recipientPayloadBytes = new TextEncoder().encode(
      JSON.stringify({
        statement: confirmation.signedPayload.statement,
        taskId: confirmation.signedPayload.taskId,
        nonce: confirmation.signedPayload.nonce,
        timestamp: confirmation.signedPayload.timestamp,
      })
    );

    const sigValid = await verifySignature(
      recipientKey,
      confirmation.signature,
      recipientPayloadBytes
    );

    if (!sigValid) {
      throw new PodChainError(
        "RECIPIENT_PROOF_INVALID",
        "Recipient WebCrypto signature did not verify"
      );
    }

    // Store the full confirmation JSON by updating the token's hash field.
    // The consumed flag is set later by the pipeline — not here.
    await this.storage.updateTokenData(token.tokenId, JSON.stringify(confirmation));
  }

  // ── Token Validation ────────────────────────────────────────────────────────

  /**
   * Validates the submitted recipient proof against the stored token.
   * Called from step 5 of the Verification Pipeline.
   *
   * Returns the tokenId on success (used for atomic consumption in step 7).
   * Throws a PodChainError on any validation failure.
   */
  async validate(
    taskId: string,
    submittedProof: string
  ): Promise<string> {
    const token = await this.storage.getToken(taskId);

    if (!token) {
      throw new PodChainError(
        "TOKEN_INVALID",
        `No RecipientToken found for task ${taskId}`
      );
    }

    if (token.consumed) {
      throw new PodChainError(
        "TOKEN_CONSUMED",
        "This RecipientToken has already been consumed"
      );
    }

    switch (token.tier) {
      case 1:
        await this.validateTier1(submittedProof, token);
        break;
      case 2:
        await this.validateTier2(submittedProof, token);
        break;
      case 3:
        await this.validateTier3(submittedProof, token);
        break;
    }

    return token.tokenId;
  }

  private async validateTier1(
    submittedToken: string,
    stored: StoredToken
  ): Promise<void> {
    const submittedHash = await sha256Hex(submittedToken);
    if (submittedHash !== stored.tokenHash) {
      throw new PodChainError(
        "TOKEN_INVALID",
        "Tier 1 token does not match the stored hash"
      );
    }
  }

  private async validateTier2(
    submittedCode: string,
    stored: StoredToken
  ): Promise<void> {
    // Check expiry first — expired tokens are rejected even if the hash matches
    if (stored.expiresAt && new Date() > new Date(stored.expiresAt)) {
      throw new PodChainError(
        "TOKEN_EXPIRED",
        `Tier 2 OTP expired at ${stored.expiresAt}`
      );
    }

    const submittedHash = await sha256Hex(submittedCode);
    if (submittedHash !== stored.tokenHash) {
      throw new PodChainError(
        "TOKEN_INVALID",
        "Tier 2 OTP does not match the stored hash"
      );
    }
  }

  private async validateTier3(
    submittedProof: string,
    stored: StoredToken
  ): Promise<void> {
    // For Tier 3, the token_hash field was replaced with the full confirmation JSON
    // after the recipient completed the signing page (recordRecipientConfirmation).
    // If it still looks like a hex hash, the recipient has not yet confirmed.
    if (stored.tokenHash.length === 64 && /^[0-9a-f]+$/.test(stored.tokenHash)) {
      throw new PodChainError(
        "RECIPIENT_PROOF_INVALID",
        "Recipient has not yet completed the Tier 3 signing step"
      );
    }

    // The submitted proof in the payload must match the stored confirmation
    if (submittedProof !== stored.tokenHash) {
      throw new PodChainError(
        "RECIPIENT_PROOF_INVALID",
        "Tier 3 recipient proof does not match the stored confirmation"
      );
    }
  }
}
