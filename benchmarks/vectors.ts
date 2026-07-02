// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Cross-Platform Serialisation Test Vectors
//
// This file contains the canonical test vectors that BOTH the server-side
// TypeScript library and the Flutter Dart library must produce identical
// output for. A mismatch between the two outputs causes signature
// verification failures in production.
//
// HOW TO USE:
// 1. Run the TypeScript vector test:   bun test benchmarks/vectors.test.ts
// 2. Run the Dart vector test:         flutter test benchmark/vectors_test.dart
// 3. Both must produce identical hex output for every vector.
//
// If they diverge, the canonical serialisation implementation in one or both
// libraries is incorrect and must be fixed before any integration testing.
//
// These vectors are also cited in Chapter 5 as the cross-platform
// consistency validation evidence.
// ─────────────────────────────────────────────────────────────────────────────

export const TEST_VECTORS = [
  {
    description: "Standard Tier 1 delivery payload",
    input: {
      coordHash:     "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
      recipientProof:"e9d2c1b3a4f5e6d7c8b9a0f1",
      riderId:       "rider_emeka_001",
      schemaVersion: "1.0",
      signedAt:      "2024-11-15T10:32:00.000Z",
      taskId:        "task_abc123def456",
    },
    expectedCanonical:
      '{"coordHash":"a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",' +
      '"recipientProof":"e9d2c1b3a4f5e6d7c8b9a0f1",' +
      '"riderId":"rider_emeka_001",' +
      '"schemaVersion":"1.0",' +
      '"signedAt":"2024-11-15T10:32:00.000Z",' +
      '"taskId":"task_abc123def456"}',
    expectedSha256OfCanonical:
      // Pre-computed SHA-256 of the canonical string above.
      // Run: echo -n '<canonical>' | sha256sum  to verify.
      "COMPUTE_AND_PIN_ON_FIRST_RUN",
  },
  {
    description: "Minimal field values (edge case — single-char strings)",
    input: {
      coordHash:     "0".repeat(64),
      recipientProof:"x",
      riderId:       "r",
      schemaVersion: "1.0",
      signedAt:      "2024-01-01T00:00:00.000Z",
      taskId:        "t",
    },
    expectedCanonical:
      '{"coordHash":"' + "0".repeat(64) + '",' +
      '"recipientProof":"x",' +
      '"riderId":"r",' +
      '"schemaVersion":"1.0",' +
      '"signedAt":"2024-01-01T00:00:00.000Z",' +
      '"taskId":"t"}',
    expectedSha256OfCanonical: "COMPUTE_AND_PIN_ON_FIRST_RUN",
  },
  {
    description: "Tier 2 payload (numeric OTP as recipientProof)",
    input: {
      coordHash:     "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
      recipientProof:"847291",
      riderId:       "rider_fatima_002",
      schemaVersion: "1.0",
      signedAt:      "2024-11-15T14:05:30.000Z",
      taskId:        "task_xyz789uvw012",
    },
    expectedCanonical:
      '{"coordHash":"b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",' +
      '"recipientProof":"847291",' +
      '"riderId":"rider_fatima_002",' +
      '"schemaVersion":"1.0",' +
      '"signedAt":"2024-11-15T14:05:30.000Z",' +
      '"taskId":"task_xyz789uvw012"}',
    expectedSha256OfCanonical: "COMPUTE_AND_PIN_ON_FIRST_RUN",
  },
] as const;
