// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Cross-Platform Vector Tests (TypeScript / Server side)
//
// Validates canonical serialisation output against the shared test vectors.
// The Dart counterpart (vectors_test.dart) must produce identical output.
//
// Run: bun test benchmarks/vectors.test.ts
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "bun:test";
import { canonicalSerialise, sha256Hex } from "../src/crypto/utils.ts";
import { TEST_VECTORS } from "./vectors.ts";
import type { DeliveryPayload } from "../src/types.ts";

describe("Cross-platform serialisation vectors (TypeScript)", () => {

  for (const vector of TEST_VECTORS) {
    it(`Vector: ${vector.description}`, async () => {
      const payload = vector.input as DeliveryPayload;
      const canonical = canonicalSerialise(payload);

      // The canonical string must match the expected value exactly
      expect(canonical).toBe(vector.expectedCanonical);

      // Compute and log the SHA-256 so it can be pinned in the vector file
      const hash = await sha256Hex(canonical);
      console.log(`  SHA-256: ${hash}`);

      // If expectedSha256OfCanonical has been pinned, assert it too
      if (vector.expectedSha256OfCanonical !== "COMPUTE_AND_PIN_ON_FIRST_RUN") {
        expect(hash).toBe(vector.expectedSha256OfCanonical);
      }
    });
  }

  it("No whitespace in any canonical output", () => {
    for (const vector of TEST_VECTORS) {
      const canonical = canonicalSerialise(vector.input as DeliveryPayload);
      expect(canonical).not.toMatch(/[ \t\n\r]/);
    }
  });

  it("Keys are alphabetically ordered in every vector", () => {
    for (const vector of TEST_VECTORS) {
      const canonical = canonicalSerialise(vector.input as DeliveryPayload);
      const parsed = JSON.parse(canonical) as Record<string, unknown>;
      const keys = Object.keys(parsed);
      expect(keys).toEqual([...keys].sort());
    }
  });

  it("Output is valid JSON parseable back to the original values", () => {
    for (const vector of TEST_VECTORS) {
      const canonical = canonicalSerialise(vector.input as DeliveryPayload);
      const parsed = JSON.parse(canonical) as Record<string, string>;

      const input = vector.input as Record<string, string>;
      for (const key of Object.keys(input)) {
        expect(parsed[key]).toBe(input[key]);
      }
    }
  });
});
