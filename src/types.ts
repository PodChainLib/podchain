// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Type Definitions
// All domain types used across the podchain library.
// ─────────────────────────────────────────────────────────────────────────────

export type Tier = 1 | 2 | 3;
export type TaskStatus = "pending" | "completed" | "cancelled";
export type KeyStatus = "active" | "revoked";
export type SchemaVersion = "1.0";

// ── Public Key ────────────────────────────────────────────────────────────────

/**
 * A P-256 ECDSA public key in JSON Web Key format (RFC 7517).
 * This is the only key format accepted by the PODCHAIN protocol.
 * Private keys never leave the rider's device and are never seen by this library.
 */
export interface PublicKeyJWK {
  kty: "EC";
  crv: "P-256";
  x: string;   // base64url-encoded x coordinate
  y: string;   // base64url-encoded y coordinate
  key_ops?: string[];
  ext?: boolean;
}

// ── Delivery Payload ──────────────────────────────────────────────────────────

/**
 * The structured payload that the rider's device signs before submitting a proof.
 * Fields are sorted alphabetically in the canonical serialisation — this ordering
 * is mandatory. Any deviation produces a signature mismatch on verification.
 *
 * Canonical form: JSON.stringify with keys sorted A–Z, no whitespace, UTF-8 bytes.
 */
export interface DeliveryPayload {
  coordHash: string;       // SHA-256 of "lat,lng" — never raw coordinates
  recipientProof: string;  // Tier-appropriate token or recipient signature JSON
  riderId: string;
  schemaVersion: SchemaVersion;
  signedAt: string;        // ISO 8601 timestamp, set on device at signing time
  taskId: string;
}

// ── Recipient Proof ───────────────────────────────────────────────────────────

/**
 * The payload that a Tier 3 recipient signs in their browser using the
 * WebCrypto API. Both the payload and the session public key are submitted
 * to the platform and stored in the Proof Certificate.
 */
export interface Tier3RecipientConfirmation {
  sessionPublicKey: PublicKeyJWK;  // Ephemeral key generated in the browser
  signature: string;               // base64url IEEE P1363 ECDSA signature
  signedPayload: {
    taskId: string;
    nonce: string;
    timestamp: string;
    statement: "I confirm receipt of this delivery";
  };
}

// ── Proof Certificate ─────────────────────────────────────────────────────────

/**
 * The verified, tamper-evident delivery record produced after a successful
 * proof submission. This is the primary output of the PODCHAIN protocol and
 * the record that satisfies Evidence Act 2011 s.84 admissibility requirements.
 */
export interface ProofCertificate {
  proofId: string;
  taskId: string;
  riderId: string;
  signedPayload: string;          // The canonical JSON string that was signed
  riderSignature: string;         // base64url IEEE P1363 ECDSA signature
  recipientProof: string;         // Tier-dependent — see RecipientToken tiers
  coordHash: string;              // SHA-256 of GPS coordinates (data minimisation)
  signedAt: string;               // Device timestamp at signing
  receivedAt: string;             // Server timestamp on receipt
  offlineSubmitted: boolean;      // True if queued and submitted after connectivity gap
  prevHash: string;               // chain_hash of the preceding certificate
  chainHash: string;              // SHA-256 of this certificate's canonical form
  chainPosition: number;          // Insertion-order index in the chain
  tier: Tier;
  schemaVersion: SchemaVersion;
}

// ── Chain Verification Report ────────────────────────────────────────────────

export interface ChainVerificationReport {
  chainIntact: boolean;
  recordsChecked: number;
  terminalHash: string | null;
  firstMismatchAt?: {
    chainPosition: number;
    proofId: string;
  };
  verifiedAt: string;
}

// ── Storage Types (internal representations) ─────────────────────────────────

export interface StoredKey {
  riderId: string;
  publicKeyJwk: PublicKeyJWK;
  curve: "P-256";
  registeredAt: string;
  revokedAt: string | null;
}

export interface StoredTask {
  taskId: string;
  riderId: string;
  recipientName: string;
  recipientPhone: string;
  deliveryAddress: string;
  tier: Tier;
  status: TaskStatus;
  createdAt: string;
}

export interface StoredToken {
  tokenId: string;
  taskId: string;
  tokenHash: string;   // SHA-256 of the raw token — raw value is never stored
  tier: Tier;
  consumed: boolean;
  issuedAt: string;
  expiresAt: string | null;  // Only set for Tier 2
}

export interface StoredProof {
  proofId: string;
  taskId: string;
  riderId: string;
  signedPayload: string;
  riderSignature: string;
  recipientProof: string;
  coordHash: string;
  signedAt: string;
  receivedAt: string;
  offlineSubmitted: boolean;
  prevHash: string;
  chainHash: string;
  chainPosition: number;
  tier: Tier;
  schemaVersion: SchemaVersion;
}

// ── Input / Output Types for the PodChain facade ─────────────────────────────

export interface RegisterKeyInput {
  riderId: string;
  publicKey: PublicKeyJWK;
}

export interface CreateTaskInput {
  riderId: string;
  recipientName: string;
  recipientPhone: string;
  deliveryAddress: string;
  tier: Tier;
}

export interface CreateTaskResult {
  taskId: string;
  tier: Tier;
  rawToken: string | null;   // Tier 1 only — the passive token for the rider app
  otp: string | null;        // Tier 2 only — dispatch this to recipient via SMS
  deepLinkNonce: string | null; // Tier 3 only — embed in the recipient deep link
  createdAt: string;
}

export interface VerifyProofInput {
  taskId: string;
  riderId: string;
  payload: string;     // Canonical JSON string as received from the rider's app
  signature: string;   // base64url IEEE P1363 ECDSA signature
}

export interface RevokeKeyInput {
  riderId: string;
}

export interface RecordRecipientConfirmationInput {
  taskId: string;
  confirmation: Tier3RecipientConfirmation;
}
