// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Verification Pipeline
//
// The critical path of the protocol. Every submitted proof passes through
// nine ordered steps. Rejection at any step terminates the pipeline
// immediately — no partial acceptance, no fallback.
//
// The fail-fast ordering is deliberate:
//   Steps 1–3 validate cryptographic authenticity before any DB writes.
//   Step 7 (token consumption) is the only irreversible state change
//   and occurs only after all reversible checks have passed.
// ─────────────────────────────────────────────────────────────────────────────

import { StorageAdapter } from "../adapters/storage-adapter.ts";
import { KeyRegistry } from "./key-registry.ts";
import { TokenManager } from "./token-manager.ts";
import { HashChainManager } from "./hash-chain.ts";
import {
  canonicalBytes,
  verifySignature,
} from "../crypto/utils.ts";
import { PodChainError } from "../errors.ts";
import type {
  DeliveryPayload,
  ProofCertificate,
  StoredProof,
  SchemaVersion,
} from "../types.ts";

// Maximum clock skew between device signing time and server receipt time.
// Proofs submitted within this window are accepted and annotated as offline.
const MAX_TIMESTAMP_SKEW_HOURS = 24;

export interface PipelineInput {
  taskId: string;
  riderId: string;
  payload: string;     // canonical JSON string as received from the rider's app
  signature: string;   // base64url IEEE P1363 ECDSA signature
}

export class VerificationPipeline {
  constructor(
    private readonly storage: StorageAdapter,
    private readonly keyRegistry: KeyRegistry,
    private readonly tokenManager: TokenManager,
    private readonly hashChain: HashChainManager
  ) {}

  /**
   * Runs the full verification pipeline for a submitted proof.
   * Returns a completed ProofCertificate on success.
   * Throws a PodChainError with a specific code on any failure.
   */
  async run(input: PipelineInput): Promise<ProofCertificate> {
    const receivedAt = new Date().toISOString();

    // ── Step 1: Parse and validate payload structure ─────────────────────────
    const payload = this.parsePayload(input.payload);

    // Confirm the riderId in the payload matches the submitted riderId
    if (payload.riderId !== input.riderId) {
      throw new PodChainError(
        "PAYLOAD_MALFORMED",
        "riderId in payload does not match the submitted riderId"
      );
    }

    // Confirm the taskId in the payload matches the submitted taskId
    if (payload.taskId !== input.taskId) {
      throw new PodChainError(
        "PAYLOAD_MALFORMED",
        "taskId in payload does not match the submitted taskId"
      );
    }

    // ── Step 2: Retrieve the rider's registered public key ───────────────────
    // getActiveKey() throws KEY_NOT_FOUND or KEY_REVOKED if applicable.
    const storedKey = await this.keyRegistry.getActiveKey(input.riderId);
    const cryptoKey = await this.keyRegistry.importForVerification(storedKey);

    // ── Step 3: Verify the ECDSA signature ───────────────────────────────────
    // The bytes passed to verify must be byte-for-byte identical to those
    // that were signed on the device. canonicalBytes() is the shared
    // serialisation function — any deviation produces a verification failure.
    const payloadBytes = canonicalBytes(payload);
    const signatureValid = await verifySignature(
      cryptoKey,
      input.signature,
      payloadBytes
    );

    if (!signatureValid) {
      throw new PodChainError(
        "SIGNATURE_INVALID",
        "ECDSA signature did not verify against the registered public key"
      );
    }

    // ── Step 4: Retrieve and validate the task ───────────────────────────────
    const task = await this.storage.getTask(input.taskId);

    if (!task) {
      throw new PodChainError(
        "TASK_NOT_FOUND",
        `Task ${input.taskId} does not exist`
      );
    }

    if (task.status === "completed") {
      throw new PodChainError(
        "TASK_ALREADY_COMPLETED",
        `A proof has already been accepted for task ${input.taskId}`
      );
    }

    if (task.status === "cancelled") {
      throw new PodChainError(
        "TASK_NOT_FOUND",
        `Task ${input.taskId} has been cancelled`
      );
    }

    // ── Step 5: Validate the RecipientToken ──────────────────────────────────
    // Delegates to the TokenManager — tier-specific validation is handled there.
    // Returns the tokenId for atomic consumption in step 7.
    const tokenId = await this.tokenManager.validate(
      input.taskId,
      payload.recipientProof
    );

    // ── Step 6: Check timestamp divergence ───────────────────────────────────
    const signedAt = new Date(payload.signedAt);
    const receivedAtDate = new Date(receivedAt);
    const skewMs = Math.abs(receivedAtDate.getTime() - signedAt.getTime());
    const skewHours = skewMs / (1000 * 60 * 60);
    const offlineSubmitted = skewHours > 0.5; // Flag if more than 30 min skew

    if (skewHours > MAX_TIMESTAMP_SKEW_HOURS) {
      throw new PodChainError(
        "TIMESTAMP_OUT_OF_RANGE",
        `Signing timestamp ${payload.signedAt} diverges from server time by ` +
          `${skewHours.toFixed(1)} hours, exceeding the ${MAX_TIMESTAMP_SKEW_HOURS}-hour window`
      );
    }

    // ── Step 7: Consume the RecipientToken (atomic, irreversible) ────────────
    // This is the only irreversible state change and occurs after all
    // reversible checks have passed. consumeToken() is atomic — a concurrent
    // submission that reaches this point simultaneously will find consumed=true
    // and return false, causing rejection.
    const consumed = await this.storage.consumeToken(tokenId);
    if (!consumed) {
      throw new PodChainError(
        "TOKEN_CONSUMED",
        "RecipientToken was consumed by a concurrent submission"
      );
    }

    // ── Step 8: Compute hash chain values and build the Proof Certificate ────
    const proofId = crypto.randomUUID();

    const proofData: Omit<StoredProof, "prevHash" | "chainHash" | "chainPosition"> = {
      proofId,
      taskId: input.taskId,
      riderId: input.riderId,
      signedPayload: input.payload,
      riderSignature: input.signature,
      recipientProof: payload.recipientProof,
      coordHash: payload.coordHash,
      signedAt: payload.signedAt,
      receivedAt,
      offlineSubmitted,
      tier: task.tier,
      schemaVersion: payload.schemaVersion as SchemaVersion,
    };

    const { prevHash, chainHash, chainPosition } =
      await this.hashChain.computeChainValues(proofData);

    const storedProof: StoredProof = {
      ...proofData,
      prevHash,
      chainHash,
      chainPosition,
    };

    // ── Step 9: Persist the Proof Certificate and update task status ─────────
    await this.storage.saveProof(storedProof);
    await this.storage.updateTaskStatus(input.taskId, "completed");

    return this.toProofCertificate(storedProof);
  }

  // ── Helpers ─────────────────────────────────────────────────────────────────

  private parsePayload(raw: string): DeliveryPayload {
    let parsed: unknown;

    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new PodChainError(
        "PAYLOAD_MALFORMED",
        "Payload is not valid JSON"
      );
    }

    const p = parsed as Record<string, unknown>;
    const required: Array<keyof DeliveryPayload> = [
      "coordHash",
      "recipientProof",
      "riderId",
      "schemaVersion",
      "signedAt",
      "taskId",
    ];

    for (const field of required) {
      if (typeof p[field] !== "string" || !p[field]) {
        throw new PodChainError(
          "PAYLOAD_MALFORMED",
          `Payload is missing required field: ${field}`
        );
      }
    }

    return {
      coordHash: p["coordHash"] as string,
      recipientProof: p["recipientProof"] as string,
      riderId: p["riderId"] as string,
      schemaVersion: p["schemaVersion"] as SchemaVersion,
      signedAt: p["signedAt"] as string,
      taskId: p["taskId"] as string,
    };
  }

  private toProofCertificate(stored: StoredProof): ProofCertificate {
    return {
      proofId: stored.proofId,
      taskId: stored.taskId,
      riderId: stored.riderId,
      signedPayload: stored.signedPayload,
      riderSignature: stored.riderSignature,
      recipientProof: stored.recipientProof,
      coordHash: stored.coordHash,
      signedAt: stored.signedAt,
      receivedAt: stored.receivedAt,
      offlineSubmitted: stored.offlineSubmitted,
      prevHash: stored.prevHash,
      chainHash: stored.chainHash,
      chainPosition: stored.chainPosition,
      tier: stored.tier,
      schemaVersion: stored.schemaVersion,
    };
  }
}
