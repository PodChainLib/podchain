// ─────────────────────────────────────────────────────────────────────────────
// PODCHAIN — Benchmark Report Formatter
//
// Reads the JSON results produced by the server-side benchmark suites
// and the Flutter device benchmark, then formats them into:
//
//   1. A plain-text table for terminal review
//   2. A Markdown table matching Table 5.1 in Chapter 5 of the thesis
//   3. A JSON summary for archiving with the thesis
//
// Usage:
//   bun run benchmarks/format-report.ts
//
// Expected input files (produced by bun run bench and flutter drive):
//   benchmarks/results/report.json          ← server suites
//   benchmarks/results/flutter-midrange.json ← mid-range Android device
//   benchmarks/results/flutter-lowend.json   ← low-end Android device
//
// If a Flutter result file is absent, the formatter will note the gap
// and leave those columns blank rather than failing.
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "fs";

// ── Types ─────────────────────────────────────────────────────────────────────

interface BenchmarkResult {
  name: string;
  iterations: number;
  median_ms?: number;
  medianMs?: number;
  median?: number;
  unit?: string;
  min_ms?: number;
  max_ms?: number;
  mean_ms?: number;
  p95_ms?: number;
}

interface Suite {
  suite: string;
  results: BenchmarkResult[];
}

interface ServerReport {
  title: string;
  generated: string;
  runtime: string;
  suites: Suite[];
}

interface FlutterReport {
  title: string;
  generated: string;
  device: string;
  results: BenchmarkResult[];
}

// ── Chapter 5 Table Rows ──────────────────────────────────────────────────────
//
// This defines the canonical set of operations that appear in the thesis
// performance table (Table 5.1). Each row maps a display label to the
// benchmark name used in the JSON results, the source (server or flutter),
// and the performance threshold defined in the thesis.

interface TableRow {
  label: string;
  source: "server" | "flutter";
  benchmarkName: string;
  threshold: string;
  unit: "ms" | "µs";
}

const TABLE_ROWS: TableRow[] = [
  {
    label:         "ECDSA key generation (first launch)",
    source:        "flutter",
    benchmarkName: "ECDSA P-256 key generation",
    threshold:     "< 500 ms",
    unit:          "ms",
  },
  {
    label:         "Payload construction (coord hash + serialise)",
    source:        "flutter",
    benchmarkName: "Payload construction (coord hash + serialise)",
    threshold:     "< 50 ms",
    unit:          "ms",
  },
  {
    label:         "ECDSA payload signing",
    source:        "flutter",
    benchmarkName: "ECDSA P-256 payload signing",
    threshold:     "< 500 ms",
    unit:          "ms",
  },
  {
    label:         "Full signDelivery() end-to-end",
    source:        "flutter",
    benchmarkName: "Full signDelivery() — coord hash + sign",
    threshold:     "< 500 ms",
    unit:          "ms",
  },
  {
    label:         "Canonical serialisation (isolated)",
    source:        "flutter",
    benchmarkName: "Canonical payload serialisation (isolated)",
    threshold:     "< 5 ms",
    unit:          "ms",
  },
  {
    label:         "Signature verification (server)",
    source:        "server",
    benchmarkName: "ECDSA P-256 signature verification",
    threshold:     "< 20 ms",
    unit:          "ms",
  },
  {
    label:         "RecipientToken generation — Tier 1",
    source:        "server",
    benchmarkName: "RecipientToken generation — Tier 1 (passive)",
    threshold:     "< 50 ms",
    unit:          "ms",
  },
  {
    label:         "RecipientToken generation — Tier 2",
    source:        "server",
    benchmarkName: "RecipientToken generation — Tier 2 (OTP)",
    threshold:     "< 50 ms",
    unit:          "ms",
  },
  {
    label:         "Full verifyAndStore() pipeline — Tier 1",
    source:        "server",
    benchmarkName: "Full verifyAndStore() — Tier 1 (9-step pipeline)",
    threshold:     "< 100 ms",
    unit:          "ms",
  },
  {
    label:         "Proof Certificate retrieval",
    source:        "server",
    benchmarkName: "Proof Certificate retrieval (SQLite read)",
    threshold:     "< 50 ms",
    unit:          "ms",
  },
  {
    label:         "Chain hash computation (per record)",
    source:        "server",
    benchmarkName: "Chain hash computation (single record)",
    threshold:     "< 10 ms",
    unit:          "ms",
  },
  {
    label:         "Chain verification — 100 records",
    source:        "server",
    benchmarkName: "Chain verification — 100 records",
    threshold:     "< 500 ms",
    unit:          "ms",
  },
  {
    label:         "Chain verification — 1,000 records",
    source:        "server",
    benchmarkName: "Chain verification — 1,000 records",
    threshold:     "< 2,000 ms",
    unit:          "ms",
  },
];

// ── Load Result Files ─────────────────────────────────────────────────────────

function loadJson<T>(path: string): T | null {
  if (!existsSync(path)) return null;
  return JSON.parse(Bun.file(path).toString()) as T;
}

const serverReport  = loadJson<ServerReport>("benchmarks/results/report.json");
const midrangeReport = loadJson<FlutterReport>("benchmarks/results/flutter-midrange.json");
const lowendReport   = loadJson<FlutterReport>("benchmarks/results/flutter-lowend.json");

// ── Index Results for Fast Lookup ─────────────────────────────────────────────

function indexResults(results: BenchmarkResult[]): Map<string, number> {
  const map = new Map<string, number>();
  for (const r of results) {
    // Support both camelCase (server) and snake_case (flutter) median fields
    const median = r.median_ms ?? r.medianMs ?? r.median;
    if (median !== undefined) {
      map.set(r.name, median);
    }
  }
  return map;
}

// Flatten all server suite results into one index
const serverResults: BenchmarkResult[] = [];
if (serverReport) {
  for (const suite of serverReport.suites) {
    serverResults.push(...suite.results);
  }
}
const serverIndex   = indexResults(serverResults);
const midrangeIndex = midrangeReport ? indexResults(midrangeReport.results) : new Map<string, number>();
const lowendIndex   = lowendReport   ? indexResults(lowendReport.results)   : new Map<string, number>();

// ── Value Formatters ──────────────────────────────────────────────────────────

function fmtMs(v: number | undefined): string {
  if (v === undefined) return "—";
  return `${v.toFixed(2)} ms`;
}

function passThreshold(v: number | undefined, threshold: string): string {
  if (v === undefined) return "—";
  // Parse the numeric threshold from the string, e.g. "< 500 ms" → 500
  const match = threshold.match(/([\d,]+)/);
  if (!match) return "—";
  const limit = parseFloat(match[1]!.replace(",", ""));
  return v <= limit ? "✓ Pass" : "✗ FAIL";
}

// ── Table Rendering ───────────────────────────────────────────────────────────

function renderPlainText(rows: typeof TABLE_ROWS): string {
  const lines: string[] = [];

  const divider = "═".repeat(110);
  const thin    = "─".repeat(110);

  lines.push("\n" + divider);
  lines.push("  TABLE 5.1 — PODCHAIN Performance Benchmarking Results");
  lines.push("  Median values across 50 iterations (20 for key gen, 10 for 1,000-record chain)");

  if (serverReport) {
    lines.push(`  Server: ${serverReport.runtime}  |  Generated: ${serverReport.generated}`);
  }
  if (midrangeReport) {
    lines.push(`  Mobile (mid-range): ${midrangeReport.device}  |  Generated: ${midrangeReport.generated}`);
  }
  if (lowendReport) {
    lines.push(`  Mobile (low-end): ${lowendReport.device}  |  Generated: ${lowendReport.generated}`);
  }

  lines.push(divider);
  lines.push(
    pad("Operation", 46) +
    pad("Mid-range", 14) +
    pad("Low-end", 14) +
    pad("Server", 14) +
    pad("Threshold", 14) +
    "Status"
  );
  lines.push(thin);

  let allPassed = true;

  for (const row of rows) {
    let midVal: number | undefined;
    let lowVal: number | undefined;
    let srvVal: number | undefined;

    if (row.source === "flutter") {
      midVal = midrangeIndex.get(row.benchmarkName);
      lowVal = lowendIndex.get(row.benchmarkName);
    } else {
      srvVal = serverIndex.get(row.benchmarkName);
    }

    // For threshold check, use the worst-case value (low-end for flutter, server for server ops)
    const checkVal = row.source === "flutter"
      ? (lowVal ?? midVal)
      : srvVal;

    const status = passThreshold(checkVal, row.threshold);
    if (status.includes("FAIL")) allPassed = false;

    lines.push(
      pad(row.label, 46) +
      pad(row.source === "flutter" ? fmtMs(midVal) : "—", 14) +
      pad(row.source === "flutter" ? fmtMs(lowVal) : "—", 14) +
      pad(row.source === "server"  ? fmtMs(srvVal) : "—", 14) +
      pad(row.threshold, 14) +
      status
    );
  }

  lines.push(divider);
  lines.push(
    allPassed
      ? "  ✓ All benchmarked operations within defined thresholds."
      : "  ✗ One or more operations exceeded their threshold — review results."
  );
  lines.push(divider + "\n");

  return lines.join("\n");
}

function renderMarkdown(rows: typeof TABLE_ROWS): string {
  const lines: string[] = [];

  lines.push("## Table 5.1 — PODCHAIN Performance Benchmarking Results\n");
  lines.push("_Median values across 50 iterations per operation (20 for key generation, 10 for 1,000-record chain verification). Mobile results measured on physical Android devices. Server results measured on local Bun runtime._\n");
  lines.push("| Operation | Mid-range Android | Low-end Android | Server | Threshold | Status |");
  lines.push("|---|---|---|---|---|---|");

  for (const row of rows) {
    let midVal: number | undefined;
    let lowVal: number | undefined;
    let srvVal: number | undefined;

    if (row.source === "flutter") {
      midVal = midrangeIndex.get(row.benchmarkName);
      lowVal = lowendIndex.get(row.benchmarkName);
    } else {
      srvVal = serverIndex.get(row.benchmarkName);
    }

    const checkVal = row.source === "flutter" ? (lowVal ?? midVal) : srvVal;
    const status   = passThreshold(checkVal, row.threshold);
    const icon     = status.includes("Pass") ? "✓" : status === "—" ? "—" : "✗";

    lines.push(
      `| ${row.label} ` +
      `| ${row.source === "flutter" ? fmtMs(midVal) : "—"} ` +
      `| ${row.source === "flutter" ? fmtMs(lowVal) : "—"} ` +
      `| ${row.source === "server"  ? fmtMs(srvVal) : "—"} ` +
      `| ${row.threshold} ` +
      `| ${icon} |`
    );
  }

  lines.push("\n_— : not applicable for this environment._");

  return lines.join("\n");
}

// ── Per-Suite Detail Tables ───────────────────────────────────────────────────

function renderSuiteDetail(suite: Suite): string {
  const lines: string[] = [];
  const thin = "─".repeat(90);

  lines.push(`\n  Suite: ${suite.suite}`);
  lines.push(thin);
  lines.push(
    pad("  Operation", 48) +
    pad("Median", 10) +
    pad("Mean", 10) +
    pad("Min", 10) +
    pad("Max", 10) +
    "p95"
  );
  lines.push(thin);

  for (const r of suite.results) {
    const u      = r.unit ?? "ms";
    const median = r.median ?? r.medianMs ?? r.median_ms ?? 0;
    const mean   = (r as Record<string, number>)["mean"] ?? r.mean_ms ?? 0;
    const min    = (r as Record<string, number>)["min"] ?? r.min_ms ?? 0;
    const max    = (r as Record<string, number>)["max"] ?? r.max_ms ?? 0;
    const p95    = (r as Record<string, number>)["p95"] ?? r.p95_ms ?? 0;

    lines.push(
      pad(`  ${r.name}`, 48) +
      pad(`${median}${u}`, 10) +
      pad(`${mean.toFixed(2)}${u}`, 10) +
      pad(`${min}${u}`, 10) +
      pad(`${max}${u}`, 10) +
      `${p95}${u}`
    );
  }

  return lines.join("\n");
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function pad(s: string, n: number): string {
  return s.length >= n ? s.slice(0, n) : s + " ".repeat(n - s.length);
}

// ── Main ──────────────────────────────────────────────────────────────────────

console.log("\nPODCHAIN Benchmark Report Formatter");
console.log("════════════════════════════════════\n");

if (!serverReport) {
  console.warn("⚠  Server report not found at benchmarks/results/report.json");
  console.warn("   Run: bun run bench\n");
}
if (!midrangeReport) {
  console.warn("⚠  Mid-range device results not found at benchmarks/results/flutter-midrange.json");
  console.warn("   Run: flutter drive ... then rename the output file\n");
}
if (!lowendReport) {
  console.warn("⚠  Low-end device results not found at benchmarks/results/flutter-lowend.json");
  console.warn("   Run: flutter drive ... on the low-end device then rename the output file\n");
}

// Chapter 5 table
const plainText = renderPlainText(TABLE_ROWS);
const markdown  = renderMarkdown(TABLE_ROWS);

console.log(plainText);

// Detailed suite breakdowns (server only — Flutter detail is in the device log)
if (serverReport) {
  console.log("DETAILED SERVER RESULTS");
  console.log("═".repeat(90));
  for (const suite of serverReport.suites) {
    console.log(renderSuiteDetail(suite));
  }
  console.log("\n");
}

// Write outputs
await Bun.write("benchmarks/results/table-5-1.md",   markdown);
await Bun.write("benchmarks/results/table-5-1.txt",  plainText);

console.log("✓ Markdown table written to  benchmarks/results/table-5-1.md");
console.log("✓ Plain-text table written to benchmarks/results/table-5-1.txt");
console.log("\n  Copy the Markdown table directly into Chapter 5, Section 5.2.3.\n");
