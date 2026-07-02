// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Benchmark Runner Utility
//
// Provides the core timing harness used by all server-side benchmarks.
// Each operation is measured over a configurable number of iterations.
// The result set reports: min, max, mean, median, p95, and p99.
//
// Median is the primary reported value in Chapter 5 — it is resistant to
// outliers caused by OS scheduling jitter and garbage collection pauses,
// which matter particularly for operations on constrained hardware.
// ─────────────────────────────────────────────────────────────────────────────

export interface BenchmarkResult {
  name: string;
  iterations: number;
  min: number;
  max: number;
  mean: number;
  median: number;
  p95: number;
  p99: number;
  unit: "ms" | "µs";
}

export interface BenchmarkSuiteResult {
  suite: string;
  timestamp: string;
  runtime: string;
  results: BenchmarkResult[];
}

/**
 * Runs a single benchmark operation.
 *
 * @param name        Human-readable name for the operation
 * @param iterations  Number of times to run (default: 50, as per Chapter 5)
 * @param warmup      Warmup runs before measurement begins (default: 5)
 * @param fn          The async operation to benchmark
 */
export async function benchmark(
  name: string,
  fn: () => Promise<void>,
  iterations = 50,
  warmup = 5
): Promise<BenchmarkResult> {
  // Warmup — allow JIT and any lazy initialisation to settle
  for (let i = 0; i < warmup; i++) {
    await fn();
  }

  const samples: number[] = [];

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await fn();
    const end = performance.now();
    samples.push(end - start);
  }

  samples.sort((a, b) => a - b);

  const min    = samples[0]!;
  const max    = samples[samples.length - 1]!;
  const mean   = samples.reduce((a, b) => a + b, 0) / samples.length;
  const median = percentile(samples, 50);
  const p95    = percentile(samples, 95);
  const p99    = percentile(samples, 99);

  // Express sub-millisecond results in microseconds for readability
  const allSubMs = max < 1;
  const unit: "ms" | "µs" = allSubMs ? "µs" : "ms";
  const factor = allSubMs ? 1000 : 1;

  return {
    name,
    iterations,
    min:    round(min    * factor),
    max:    round(max    * factor),
    mean:   round(mean   * factor),
    median: round(median * factor),
    p95:    round(p95    * factor),
    p99:    round(p99    * factor),
    unit,
  };
}

function percentile(sorted: number[], p: number): number {
  const index = (p / 100) * (sorted.length - 1);
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) return sorted[lower]!;
  const fraction = index - lower;
  return sorted[lower]! * (1 - fraction) + sorted[upper]! * fraction;
}

function round(n: number): number {
  return Math.round(n * 100) / 100;
}

/**
 * Prints a formatted benchmark result table to stdout.
 */
export function printResults(suite: BenchmarkSuiteResult): void {
  console.log("\n" + "═".repeat(80));
  console.log(` PODCHAIN BENCHMARK SUITE: ${suite.suite}`);
  console.log(` ${suite.timestamp}  |  Runtime: ${suite.runtime}`);
  console.log("═".repeat(80));
  console.log(
    padEnd(" Operation", 42) +
    padStart("Median", 10) +
    padStart("Mean", 10) +
    padStart("Min", 10) +
    padStart("Max", 10) +
    padStart("p95", 10)
  );
  console.log("─".repeat(80));

  for (const r of suite.results) {
    const u = r.unit;
    console.log(
      padEnd(` ${r.name}`, 42) +
      padStart(`${r.median}${u}`, 10) +
      padStart(`${r.mean}${u}`, 10) +
      padStart(`${r.min}${u}`, 10) +
      padStart(`${r.max}${u}`, 10) +
      padStart(`${r.p95}${u}`, 10)
    );
  }

  console.log("═".repeat(80) + "\n");
}

/**
 * Serialises results to JSON for machine-readable output.
 * Write to file for inclusion in the thesis appendix.
 */
export function serialiseResults(suite: BenchmarkSuiteResult): string {
  return JSON.stringify(suite, null, 2);
}

function padEnd(s: string, n: number): string {
  return s.length >= n ? s.slice(0, n) : s + " ".repeat(n - s.length);
}

function padStart(s: string, n: number): string {
  return s.length >= n ? s : " ".repeat(n - s.length) + s;
}
