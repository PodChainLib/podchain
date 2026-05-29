// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — PodChain Facade
//
// The single entry point for all protocol operations. Platform operators
// interact only with this class — all internal modules are hidden behind it.
//
// Usage:
//   const podchain = new PodChain({ storage: new SQLiteAdapter(db) });
//   await podchain.registerKey({ riderId, publicKey });
//   const task = await podchain.createTask({ riderId, tier: 2, ... });
//   const cert = await podchain.verifyAndStore({ taskId, riderId, payload, signature });
//   const report = await podchain.verifyChain();
// ─────────────────────────────────────────────────────────────────────────────

import { StorageAdapter } from "./adapters/storage-adapter.ts";
import { KeyRegistry } from "./modules/key-registry.ts";
import { TokenManager } from "./modules/token-manager.ts";
import { HashChainManager } from "./modules/hash-chain.ts";
import { VerificationPipeline } from "./modules/verification-pipeline.ts";
import { PodChainError } from "./errors.ts";
import type {
  RegisterKeyInput,
  CreateTaskInput,
  CreateTaskResult,
  VerifyProofInput,
  RevokeKeyInput,
  RecordRecipientConfirmationInput,
  ProofCertificate,
  ChainVerificationReport,
  StoredTask,
  Tier,
} from "./types.ts";

export interface PodChainConfig {
  storage: StorageAdapter;
}

export class PodChain {
  private readonly keyRegistry: KeyRegistry;
  private readonly tokenManager: TokenManager;
  private readonly hashChain: HashChainManager;
  private readonly pipeline: VerificationPipeline;
  private readonly storage: StorageAdapter;

  constructor(config: PodChainConfig) {
    this.storage = config.storage;
    this.keyRegistry = new KeyRegistry(this.storage);
    this.tokenManager = new TokenManager(this.storage);
    this.hashChain = new HashChainManager(this.storage);
    this.pipeline = new VerificationPipeline(
      this.storage,
      this.keyRegistry,
      this.tokenManager,
      this.hashChain
    );
  }

  // ── Rider Key Management ────────────────────────────────────────────────────

  /**
   * Registers a delivery agent's ECDSA P-256 public key.
   * Call this during rider onboarding, after the rider's device has generated
   * a key pair using the podchain_flutter library.
   *
   * Throws RIDER_ALREADY_EXISTS if the riderId already has a registered key.
   * Throws KEY_FORMAT_INVALID if the JWK does not describe a valid P-256 key.
   */
  async registerKey(input: RegisterKeyInput): Promise<void> {
    await this.keyRegistry.register(input.riderId, input.publicKey);
  }

  /**
   * Revokes a delivery agent's key.
   * After revocation, all future proof submissions from this rider are rejected.
   * Past proofs remain verifiable — revocation is not retroactive.
   */
  async revokeKey(input: RevokeKeyInput): Promise<void> {
    await this.keyRegistry.revoke(input.riderId);
  }

  // ── Task and Token Management ───────────────────────────────────────────────

  /**
   * Creates a delivery task and generates its RecipientToken.
   *
   * The returned CreateTaskResult contains:
   *   - rawToken     (Tier 1 only) — embed this in the task for the rider app
   *   - otp          (Tier 2 only) — dispatch this to the recipient via SMS
   *   - deepLinkNonce (Tier 3 only) — embed in: /confirm/taskId?nonce=VALUE
   *
   * Throws KEY_NOT_FOUND if the assigned rider has no registered key.
   * Throws KEY_REVOKED if the rider's key is revoked.
   * Throws INVALID_TIER if the tier value is not 1, 2, or 3.
   */
  async createTask(input: CreateTaskInput): Promise<CreateTaskResult> {
    if (![1, 2, 3].includes(input.tier)) {
      throw new PodChainError(
        "INVALID_TIER",
        `Tier must be 1, 2, or 3. Received: ${input.tier}`
      );
    }

    // Confirm the assigned rider has an active key before creating the task
    await this.keyRegistry.getActiveKey(input.riderId);

    const taskId = crypto.randomUUID();
    const now = new Date().toISOString();

    const task: StoredTask = {
      taskId,
      riderId: input.riderId,
      recipientName: input.recipientName,
      recipientPhone: input.recipientPhone,
      deliveryAddress: input.deliveryAddress,
      tier: input.tier as Tier,
      status: "pending",
      createdAt: now,
    };

    await this.storage.saveTask(task);

    const tokenResult = await this.tokenManager.generateToken(
      taskId,
      input.tier as Tier
    );

    return {
      taskId,
      tier: input.tier as Tier,
      rawToken: tokenResult.rawToken,
      otp: tokenResult.otp,
      deepLinkNonce: tokenResult.deepLinkNonce,
      createdAt: now,
    };
  }

  /**
   * Records a Tier 3 recipient's WebCrypto signature.
   * Call this when the recipient completes the deep-link signing page.
   * Must be called before the rider submits their signed proof.
   */
  async recordRecipientConfirmation(
    input: RecordRecipientConfirmationInput
  ): Promise<void> {
    await this.tokenManager.recordRecipientConfirmation(
      input.taskId,
      input.confirmation
    );
  }

  // ── Proof Verification and Storage ─────────────────────────────────────────

  /**
   * The core operation. Runs the full 9-step verification pipeline on a
   * submitted proof and, if all checks pass, stores and returns the
   * Proof Certificate.
   *
   * Throws a PodChainError with a specific code on any failure.
   * See errors.ts for the full list of error codes and their meanings.
   */
  async verifyAndStore(input: VerifyProofInput): Promise<ProofCertificate> {
    return this.pipeline.run(input);
  }

  /**
   * Retrieves the Proof Certificate for a completed delivery task.
   * Returns null if the task has no accepted proof.
   */
  async getProof(taskId: string): Promise<ProofCertificate | null> {
    const stored = await this.storage.getProof(taskId);
    if (!stored) return null;

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

  // ── Chain Verification ──────────────────────────────────────────────────────

  /**
   * Verifies the integrity of the complete hash chain.
   * Traverses all stored Proof Certificates and recomputes each chain_hash.
   * Any discrepancy indicates tampering with a stored record.
   *
   * This is the operational answer to Research Question RQ3.
   */
  async verifyChain(): Promise<ChainVerificationReport> {
    return this.hashChain.verifyChain();
  }
}
