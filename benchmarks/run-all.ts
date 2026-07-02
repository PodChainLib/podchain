// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Master Benchmark Runner
//
// Runs all three server-side benchmark suites in sequence and writes a
// combined JSON report to benchmarks/results/report.json.
//
// Usage:
//   bun run benchmarks/run-all.ts
//
// For thesis reproduction: run on the target hardware, collect report.json,
// and use the median values for the Chapter 5 performance table.
//
// Environment:
//   BENCH_ITERATIONS=50   Override default iteration count (default: 50)
// ─────────────────────────────────────────────────────────────────────────────

import { $ } from "bun";

console.log("╔══════════════════════════════════════════════════════════════════════╗");
console.log("║           PODCHAIN SERVER-SIDE BENCHMARK SUITE                      ║");
console.log("║  Reproducing Chapter 5 performance results                          ║");
console.log("╚══════════════════════════════════════════════════════════════════════╝\n");

// Ensure output directory exists
await $`mkdir -p benchmarks/results`;

console.log("━━━ Suite 1/3: Cryptographic Operations ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
await import("./crypto.bench.ts");

console.log("━━━ Suite 2/3: Hash Chain Operations ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
await import("./chain.bench.ts");

console.log("━━━ Suite 3/3: End-to-End Pipeline ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
await import("./pipeline.bench.ts");

// Merge all three result files into a single combined report
const crypto   = JSON.parse(await Bun.file("benchmarks/results/crypto-server.json").text());
const chain    = JSON.parse(await Bun.file("benchmarks/results/chain-server.json").text());
const pipeline = JSON.parse(await Bun.file("benchmarks/results/pipeline-server.json").text());

const combined = {
  title: "PODCHAIN Server-Side Benchmark Report",
  generated: new Date().toISOString(),
  runtime: `Bun ${Bun.version}`,
  platform: process.platform,
  arch: process.arch,
  suites: [crypto, chain, pipeline],
};

await Bun.write("benchmarks/results/report.json", JSON.stringify(combined, null, 2));

console.log("✓ Combined report written to benchmarks/results/report.json");
console.log("  Use the median values from each result for the Chapter 5 table.\n");
