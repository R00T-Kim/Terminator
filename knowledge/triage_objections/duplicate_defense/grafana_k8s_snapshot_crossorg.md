---
target: Grafana OSS 12.4.1
finding: k8s_snapshot_crossorg_delete_variant_of_CVE-2024-1313
date_submitted: 2026-03-12
date_resolved: 2026-04-14
platform: Intigriti
code: GRAFANALABS-JGOSVPRN
verdict: Closed / Duplicate
severity_claimed: Medium (4.3)
bounty: 0
---

# Triage Feedback: Grafana — K8s API cross-org snapshot DELETE

## Our Prediction
- Verdict: SUBMIT (variant of CVE-2024-1313 on unified-storage K8s API path)
- Severity: Medium 4.3 CVSS 3.1 AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N
- Key claim: CVE-2024-1313 OrgID check is only on legacy REST path; SnapshotLegacyStore.Delete at snapshot_legacy_store.go:56-78 skips the same guard. Four control tests (A/B/C/D) differentiate org-ownership bypass from role-permission.

## Actual Outcome
- Status: CLOSED (Duplicate)
- Triager Comment: "this issue has already been found earlier by another researcher"
- Prior triage request: "your report lacks some information. Can you please provide a full video PoC?"
- Resolution Time: 33 days

## Mismatch Analysis
- Category: DUPLICATE_MISS
- Root Cause: The patch-hunter phase found CVE-2024-1313 but never queried Grafana's own public security advisories or commit log for follow-up advisories on the same file after the original fix. A single `grep -r "NamespaceInfoFrom" pkg/registry/apis/` + `git log --all -- snapshot_legacy_store.go` would have revealed prior fix/advisory traffic.
- Secondary cause: No video PoC attached when triager asked — reporter delivered control-test text output but no screencast showing the cross-org deletion.
- Which destruction test would have caught this: Gate 1 Q3 (DUPLICATE CHECK) with a stricter rule: "same file + same class as a prior CVE in the last 24 months = HIGH duplicate risk".

## Rule Update
- Mode affected: Gate 1 Q3 (DUPLICATE CHECK)
- Specific change:
  - Before Gate 1 GO on any variant-class finding: run patch-hunter's duplicate-graph-check (already in v12) but extend to query the program's own Hacktivity/disclosure feed AND the last 6 months of security fix commits on the same file/package.
  - For Intigriti Grafana-class programs, auto-generate a 60-second video PoC (asciinema or OBS) for any IDOR/BOLA/cross-tenant finding — text output + control tests alone are below the platform bar.
- Confidence: HIGH
