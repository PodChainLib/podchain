# PODCHAIN Benchmark Suite

Reproduces the performance results reported in **Chapter 5, Section 5.2.3** of the thesis. Running the full suite on the target hardware produces the median values for Table 5.1.

---

## Structure

```
podchain/benchmarks/
  runner.ts            ← timing harness (stat helpers, table printer)
  crypto.bench.ts      ← server cryptographic operation benchmarks
  chain.bench.ts       ← hash chain append and verification benchmarks
  pipeline.bench.ts    ← end-to-end verifyAndStore() pipeline benchmarks
  run-all.ts           ← runs all three server suites in sequence
  format-report.ts     ← formats JSON results into the Chapter 5 table
  vectors.ts           ← shared cross-platform serialisation test vectors
  vectors.test.ts      ← validates vectors against the TypeScript library
  results/             ← JSON output files (git-ignored, generated at runtime)

podchain_flutter/benchmark/
  harness.dart                    ← Flutter timing harness
  podchain_benchmark_test.dart    ← mobile benchmark test suite (BM-01 – BM-08)
  vectors_test.dart               ← validates vectors against the Dart library

podchain_flutter/integration_test/
  benchmark_runner.dart           ← integration_test entry point (runs on device)

podchain_flutter/test_driver/
  benchmark_driver.dart           ← host-side driver (captures device output)
```

---

## 1. Server-Side Benchmarks (`podchain`)

### Prerequisites

```bash
cd podchain
bun install
```

### Run all server suites

```bash
bun run bench
```

This runs all three suites in sequence and writes:
- `benchmarks/results/crypto-server.json`
- `benchmarks/results/chain-server.json`
- `benchmarks/results/pipeline-server.json`
- `benchmarks/results/report.json` (combined)

### Run individual suites

```bash
bun run bench:crypto    # cryptographic operations only
bun run bench:chain     # hash chain operations only
bun run bench:pipeline  # end-to-end pipeline only
```

### Validate cross-platform serialisation vectors

```bash
bun run bench:vectors
```

All vector assertions must pass before mobile benchmarks are considered valid.

---

## 2. Mobile Benchmarks (`podchain_flutter`)

### Prerequisites

```bash
cd podchain_flutter
flutter pub get
```

### Connect a physical Android device

```bash
flutter devices
```

Note the device ID. **Do not use the emulator** — it does not use hardware-backed key storage and does not accurately reflect real-device latency.

### The thesis benchmarked two devices

| Label | Device | OS | RAM |
|---|---|---|---|
| Mid-range | Samsung Galaxy A34 | Android 13 | 6 GB |
| Low-end | Tecno Spark 10C | Android 13 | 4 GB |

### Run benchmarks on device

```bash
flutter drive \
  --driver=test_driver/benchmark_driver.dart \
  --target=integration_test/benchmark_runner.dart \
  --device-id <device_id> \
  2>&1 | tee flutter_drive.log
```

### Extract the JSON result

```bash
grep -A 99999 "BENCHMARK_JSON_START" flutter_drive.log \
  | grep -B 99999 "BENCHMARK_JSON_END" \
  | grep -v "BENCHMARK_JSON" \
  > ../podchain/benchmarks/results/flutter-midrange.json
```

Repeat on the second device and save as `flutter-lowend.json`.

### Run Dart vector tests

```bash
flutter test benchmark/vectors_test.dart
```

These must also pass and produce the same SHA-256 digests as the TypeScript vector test.

---

## 3. Generate the Chapter 5 Table

Once at least the server results are available:

```bash
cd podchain
bun run bench:report
```

This reads:
- `benchmarks/results/report.json`           (required)
- `benchmarks/results/flutter-midrange.json` (optional — columns blank if absent)
- `benchmarks/results/flutter-lowend.json`   (optional)

And writes:
- `benchmarks/results/table-5-1.md`  ← paste directly into thesis Section 5.2.3
- `benchmarks/results/table-5-1.txt` ← plain-text version for review

---

## 4. Performance Thresholds

These thresholds are defined in the thesis (Chapter 5) and verified by the formatter.

| Operation | Source | Threshold |
|---|---|---|
| ECDSA key generation (first launch) | Mobile | < 500 ms |
| Payload construction | Mobile | < 50 ms |
| ECDSA payload signing | Mobile | < 500 ms |
| Full signDelivery() end-to-end | Mobile | < 500 ms |
| Canonical serialisation (isolated) | Mobile | < 5 ms |
| Signature verification | Server | < 20 ms |
| RecipientToken generation — Tier 1 | Server | < 50 ms |
| RecipientToken generation — Tier 2 | Server | < 50 ms |
| Full verifyAndStore() — Tier 1 | Server | < 100 ms |
| Proof Certificate retrieval | Server | < 50 ms |
| Chain hash computation (per record) | Server | < 10 ms |
| Chain verification — 100 records | Server | < 500 ms |
| Chain verification — 1,000 records | Server | < 2,000 ms |

---

## 5. Pinning the Serialisation Test Vectors

On first run, the vector tests log SHA-256 digests rather than asserting them. After confirming both the TypeScript and Dart outputs are identical, pin the digests in both `vectors.ts` and `vectors_test.dart` by replacing `"COMPUTE_AND_PIN_ON_FIRST_RUN"` with the actual hex value. Re-run both test suites to confirm pinned assertions pass.

---

## 6. Notes on Statistical Method

- Each operation is measured over **50 iterations** (20 for key generation, 10 for 1,000-record chain).
- **5 warmup runs** precede measurement to allow JIT and lazy initialisation to settle.
- The **median** is the primary reported value — it is resistant to outliers caused by OS scheduling jitter and garbage collection pauses.
- Mean, min, max, p95, and p99 are also recorded for completeness.
- Network latency is explicitly excluded from all reported figures. The end-to-end proof submission figures in Chapter 5 annotate network time separately as `N/A` for the protocol's local operations.
