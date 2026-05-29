// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Hash Chain Manager
//
// Implements the append-only SHA-256 hash chain that links every Proof
// Certificate to its predecessor. Any modification to a historical record
// breaks the chain from that point forward, making tampering detectable
// by any party with read access to the full record set.
//
// This is NOT a blockchain. There is no distributed consensus, no peer
// network, no token. It is a server-side hash chain providing tamper-
// detectability for a single-operator logistics platform — the right
// tradeoff for this use case.
// ─────────────────────────────────────────────────────────────────────────────

import { StorageAdapter } from "../adapters/storage-adapter.ts";
import { sha256Hex } from "../crypto/utils.ts";
import { PodChainError } from "../errors.ts";
import type { StoredProof, ChainVerificationReport, SchemaVersion } from "../types.ts";

// The genesis constant anchors the chain. The first Proof Certificate's
// prev_hash is SHA-256 of this string, giving the chain a known starting point.
const GENESIS_CONSTANT = "PODCHAIN_GENESIS_v1.0";

export class HashChainManager {
  private genesisHash: string | null = null;

  constructor(private readonly storage: StorageAdapter) {}

  // ── Appending to the Chain ──────────────────────────────────────────────────

  /**
   * Computes the prev_hash and chain_hash values for a new Proof Certificate
   * and returns them alongside the chain position.
   *
   * This must be called immediately before saveProof() — the two operations
   * should be wrapped in a database transaction by the caller to prevent
   * a partial write from corrupting the chain.
   */
  async computeChainValues(
    proofData: Omit<StoredProof, "prevHash" | "chainHash" | "chainPosition">
  ): Promise<{ prevHash: string; chainHash: string; chainPosition: number }> {
    const lastProof = await this.storage.getLastProof();

    const prevHash = lastProof
      ? lastProof.chainHash
      : await this.getGenesisHash();

    const chainPosition = lastProof ? lastProof.chainPosition + 1 : 1;

    // The chain_hash covers the full certificate including prev_hash.
    // Key ordering matches the StoredProof interface (alphabetical by convention).
    const canonicalCert = canonicaliseProof({
      ...proofData,
      prevHash,
      chainHash: "",   // placeholder — excluded from self-hash computation
      chainPosition,
    });

    const chainHash = await sha256Hex(canonicalCert);

    return { prevHash, chainHash, chainPosition };
  }

  // ── Chain Verification ──────────────────────────────────────────────────────

  /**
   * Traverses all stored Proof Certificates in chain order and verifies
   * that each record's chain_hash matches a fresh SHA-256 computation
   * over its canonical form.
   *
   * Any discrepancy indicates that the record (or a preceding one) was
   * modified after storage. The report identifies the first mismatched
   * record precisely.
   */
  async verifyChain(): Promise<ChainVerificationReport> {
    const proofs = await this.storage.getAllProofsOrdered();
    const verifiedAt = new Date().toISOString();

    if (proofs.length === 0) {
      return {
        chainIntact: true,
        recordsChecked: 0,
        terminalHash: await this.getGenesisHash(),
        verifiedAt,
      };
    }

    let expectedPrevHash = await this.getGenesisHash();

    for (const proof of proofs) {
      // Verify prev_hash matches what we expect
      if (proof.prevHash !== expectedPrevHash) {
        return {
          chainIntact: false,
          recordsChecked: proof.chainPosition,
          terminalHash: null,
          firstMismatchAt: {
            chainPosition: proof.chainPosition,
            proofId: proof.proofId,
          },
          verifiedAt,
        };
      }

      // Recompute chain_hash from the canonical form of this record
      const canonicalCert = canonicaliseProof({
        ...proof,
        chainHash: "",  // exclude from self-hash, as when originally computed
      });
      const recomputedHash = await sha256Hex(canonicalCert);

      if (recomputedHash !== proof.chainHash) {
        return {
          chainIntact: false,
          recordsChecked: proof.chainPosition,
          terminalHash: null,
          firstMismatchAt: {
            chainPosition: proof.chainPosition,
            proofId: proof.proofId,
          },
          verifiedAt,
        };
      }

      expectedPrevHash = proof.chainHash;
    }

    const lastProof = proofs[proofs.length - 1]!;

    return {
      chainIntact: true,
      recordsChecked: lastProof.chainPosition,
      terminalHash: lastProof.chainHash,
      verifiedAt,
    };
  }

  // ── Genesis Hash ────────────────────────────────────────────────────────────

  private async getGenesisHash(): Promise<string> {
    if (!this.genesisHash) {
      this.genesisHash = await sha256Hex(GENESIS_CONSTANT);
    }
    return this.genesisHash;
  }
}

// ── Canonical Proof Serialisation ─────────────────────────────────────────────

/**
 * Produces a deterministic string representation of a Proof Certificate
 * for hash chain computation. Keys are sorted alphabetically.
 * The chainHash field is set to an empty string before serialisation
 * so that the hash is computed over the record's content, not a
 * circular self-reference.
 */
function canonicaliseProof(
  proof: Omit<StoredProof, "chainHash"> & { chainHash: string }
): string {
  const ordered: Record<string, unknown> = {};
  for (const key of Object.keys(proof).sort()) {
    ordered[key] = (proof as Record<string, unknown>)[key];
  }
  return JSON.stringify(ordered);
}
