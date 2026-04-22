---
target: Vercel AI SDK (vercel/ai) v6.0.78
finding: download_assets_ssrf_redirect_pivot_cve_2025_48985_duplicate
date_submitted: 2026-02-11
date_resolved: 2026-02-11
platform: HackerOne
report_id: 3547315
verdict: Closed / Duplicate
severity_claimed: Critical (9.2)
duplicate_of: 3500968
cve_already_assigned: CVE-2025-48985
bounty: 0
---

# Triage Feedback: Vercel AI SDK — download_assets SSRF (CVE-2025-48985 already exists)

## Our Prediction
- Verdict: SUBMIT
- Severity: Critical (9.2) — chain of (1) asset URL downloader + (2) OAuth discovery chain SSRF
- Key claim: download-function.ts fetches image/file/audio URLs without SSRF protection; AWS IMDSv1 + ECS metadata reachable; OAuth discovery chain makes 5 hops per 401.

## Actual Outcome
- Status: CLOSED (Duplicate)
- Duplicate of: #3500968 (submitted 2026-01-08) — already resolved, CVE-2025-48985 assigned
- Same-day closure

## Mismatch Analysis
- Category: DUPLICATE_MISS (CVE already assigned — unforgivable)
- Root Cause: CVE-2025-48985 was already assigned to the same file before our submission. patch-hunter never queried CVE feeds (MITRE, GitHub Advisory Database, Snyk) for the package name + version we were auditing. A basic `curl -s https://api.github.com/advisories?ecosystem=npm&package=ai` would have returned the advisory.
- This is the worst kind of duplicate: the CVE was public, with fix commits, and we still submitted.
- Which destruction test would have caught this: Gate 1 Q3 with a CVE lookup requirement, not just a commit-log check.

## Rule Update
- Mode affected: patch-hunter + Gate 1 Q3 hard requirement
- Specific change:
  - patch-hunter Phase 1 must emit a `known_cve_table.json` for every package/component in scope, queried from MITRE + GitHub Security Advisory + Snyk + Nuclei CVE templates.
  - Gate 1 Q3 hard requirement: if finding file path or package matches any row in known_cve_table.json within the last 24 months → report must explicitly cite every such CVE in a "Prior Art Differentiator" section and show a concrete behavioral diff. Absent section = auto-KILL.
  - Orchestrator rule: never queue a finding for exploiter work if patch-hunter did not complete CVE lookup for the affected file.
- Confidence: HIGH
