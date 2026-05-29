// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Public API
//
// Everything a platform operator needs is exported from this file.
// Internal modules are not exported — the PodChain class is the only
// entry point to the protocol logic.
// ─────────────────────────────────────────────────────────────────────────────

// Core
export { PodChain } from "./podchain.ts";
export type { PodChainConfig } from "./podchain.ts";

// Storage adapter (for implementing custom backends)
export { StorageAdapter } from "./adapters/storage-adapter.ts";

// Types
export type {
  Tier,
  PublicKeyJWK,
  DeliveryPayload,
  ProofCertificate,
  ChainVerificationReport,
  Tier3RecipientConfirmation,
  RegisterKeyInput,
  CreateTaskInput,
  CreateTaskResult,
  VerifyProofInput,
  RevokeKeyInput,
  RecordRecipientConfirmationInput,
} from "./types.ts";

// Errors
export { PodChainError } from "./errors.ts";
export type { PodChainErrorCode } from "./errors.ts";

// Crypto utilities (exposed for platform developers building custom integrations)
export {
  canonicalSerialise,
  sha256Hex,
  toBase64Url,
  fromBase64Url,
  hashCoordinates,
} from "./crypto/utils.ts";
