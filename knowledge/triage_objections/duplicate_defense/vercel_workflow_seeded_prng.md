---
target: Vercel Workflow (vercel/workflow)
finding: seedrandom_seeded_with_runId_enables_hook_token_prediction
date_submitted: 2026-02-11
date_resolved: 2026-02-11
platform: HackerOne
report_id: 3548838
verdict: Closed / Duplicate
severity_claimed: Medium (6.3)
duplicate_of: 3530676
bounty: 0
---

# Triage Feedback: Vercel Workflow — seeded PRNG hook-token prediction

## Our Prediction
- Verdict: SUBMIT
- Severity: Medium 6.3
- Key claim: vm/index.ts seeds seedrandom(runId) and replaces Math.random / crypto.getRandomValues / crypto.randomUUID; runId is leaked in HTTP response headers/body/URL; nanoid + ULID hook tokens become predictable; webhook route has no HMAC/TTL/single-use/rate-limit.

## Actual Outcome
- Status: CLOSED (Duplicate)
- Duplicate of: #3530676 (submitted 2026-01-30) — "[Vercel Workflow] Seeded PRNG in vercel workflow generates predictable hook tokens from leaked run IDs, enabling approval bypass"
- Resolution Time: same-day

## Mismatch Analysis
- Category: DUPLICATE_MISS (obvious, well-known pattern)
- Root Cause: seedrandom + attacker-visible-seed is one of the most widely known JS patterns in bug bounty training — the original was filed 12 days before ours. Our target-evaluator ran Phase 0 on Vercel without scraping recent Hacktivity / disclosed reports / public GitHub commits referencing seedrandom. A one-line `git log --since=3months -- 'packages/core/src/vm/*'` or Hacktivity filter "program=vercel age<90d" would have surfaced the duplicate.
- Which destruction test would have caught this: Gate 1 Q3 (DUPLICATE CHECK) with the "high-prior-art-risk" class flagged: seeded PRNG, JWT alg=none, Prototype Pollution, path traversal, HTML injection — all auto-HIGH duplicate risk.

## Rule Update
- Mode affected: target-evaluator (Phase 0) + Gate 1 Q3
- Specific change:
  - target-evaluator must ingest the last 90 days of Hacktivity for the target + last 90 days of security-relevant commits on any file later flagged in Phase 1. Duplicate risk auto-raises to HIGH if either source shows a related report.
  - Vulnerability class allowlist: if finding class ∈ {seeded PRNG, alg:none, Prototype Pollution, open redirect, directory listing, clickjacking, password-in-URL}, require Gate 1 Q3 to cite at least one unique differentiator from every hit in the last 18 months. No unique differentiator = KILL before Gate 2.
- Confidence: HIGH
