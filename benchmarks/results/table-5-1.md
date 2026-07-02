## Table 5.1 — PODCHAIN Performance Benchmarking Results

_Median values across 50 iterations per operation (20 for key generation, 10 for 1,000-record chain verification). Mobile results measured on physical Android devices. Server results measured on local Bun runtime._

| Operation | Mid-range Android | Low-end Android | Server | Threshold | Status |
|---|---|---|---|---|---|
| ECDSA key generation (first launch) | — | — | — | < 500 ms | — |
| Payload construction (coord hash + serialise) | — | — | — | < 50 ms | — |
| ECDSA payload signing | — | — | — | < 500 ms | — |
| Full signDelivery() end-to-end | — | — | — | < 500 ms | — |
| Canonical serialisation (isolated) | — | — | — | < 5 ms | — |
| Signature verification (server) | — | — | — | < 20 ms | — |
| RecipientToken generation — Tier 1 | — | — | — | < 50 ms | — |
| RecipientToken generation — Tier 2 | — | — | — | < 50 ms | — |
| Full verifyAndStore() pipeline — Tier 1 | — | — | — | < 100 ms | — |
| Proof Certificate retrieval | — | — | — | < 50 ms | — |
| Chain hash computation (per record) | — | — | — | < 10 ms | — |
| Chain verification — 100 records | — | — | — | < 500 ms | — |
| Chain verification — 1,000 records | — | — | — | < 2,000 ms | — |

_— : not applicable for this environment._