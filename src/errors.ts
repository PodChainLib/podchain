// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Error Classes
// All protocol errors carry a machine-readable code that maps directly to
// the API error responses documented in Appendix A.
// ─────────────────────────────────────────────────────────────────────────────

export type PodChainErrorCode =
  | "KEY_FORMAT_INVALID"
  | "KEY_NOT_FOUND"
  | "KEY_REVOKED"
  | "RIDER_ALREADY_EXISTS"
  | "TASK_NOT_FOUND"
  | "TASK_ALREADY_COMPLETED"
  | "TOKEN_INVALID"
  | "TOKEN_EXPIRED"
  | "TOKEN_CONSUMED"
  | "RECIPIENT_PROOF_INVALID"
  | "TIMESTAMP_OUT_OF_RANGE"
  | "PAYLOAD_MALFORMED"
  | "SIGNATURE_INVALID"
  | "MISSING_FIELDS"
  | "INVALID_TIER"
  | "CHAIN_VERIFICATION_ERROR";

export class PodChainError extends Error {
  public readonly code: PodChainErrorCode;
  public readonly httpStatus: number;

  constructor(code: PodChainErrorCode, message: string) {
    super(message);
    this.name = "PodChainError";
    this.code = code;
    this.httpStatus = PodChainError.statusFor(code);
  }

  toJSON() {
    return {
      success: false,
      error: this.code,
      message: this.message,
    };
  }

  private static statusFor(code: PodChainErrorCode): number {
    const map: Record<PodChainErrorCode, number> = {
      KEY_FORMAT_INVALID: 400,
      MISSING_FIELDS: 400,
      INVALID_TIER: 400,
      PAYLOAD_MALFORMED: 400,
      TIMESTAMP_OUT_OF_RANGE: 400,
      SIGNATURE_INVALID: 401,
      TOKEN_INVALID: 401,
      TOKEN_EXPIRED: 401,
      RECIPIENT_PROOF_INVALID: 401,
      KEY_REVOKED: 403,
      KEY_NOT_FOUND: 404,
      TASK_NOT_FOUND: 404,
      RIDER_ALREADY_EXISTS: 409,
      TASK_ALREADY_COMPLETED: 409,
      TOKEN_CONSUMED: 409,
      CHAIN_VERIFICATION_ERROR: 500,
    };
    return map[code];
  }
}
