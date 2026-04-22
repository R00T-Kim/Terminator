---
target: OPPO ColorOS (com.heytap.openid KmsDaemonService)
finding: normal_permission_plus_shared_binder_state_race
date_submitted: 2026-02-10
date_resolved: 2026-02-11
platform: HackerOne
report_id: 3546997
verdict: Closed / Informative
severity_claimed: originally C:H (~High) → corrected to Medium 5.9 mid-review
bounty: 0
---

# Triage Feedback: OPPO KmsDaemonService — protectionLevel=normal + shared state race

## Our Prediction
- Verdict: SUBMIT (as compound: CWE-732 permission level + CWE-362 race + oracle)
- Severity: initially CVSS 3.1 C:H ~ High; downgraded to 5.9 Medium mid-review after admitting kernel-enforced whitelist blocks key extraction.

## Actual Outcome
- Status: Needs-more-info → rebuttal submitted → CLOSED (Informative)
- Triager (@h1_analyst_shawn, final): "implements multiple layers of security controls that function as designed. While the service uses normal permission protection, it enforces application whitelisting through kernel-level caller validation and certificate verification. Critical operations remain protected by signature verification requiring OPPO's signing key. The theoretical race condition on session variables does not compromise the primary security boundaries, as Tier 2 methods maintain proper authorization checks. The information disclosure regarding KMS initialization status represents expected functional behavior rather than a security vulnerability, and the rate limit bypass affects non-critical whitelist fetching without enabling unauthorized access to protected resources."
- Resolution Time: <1 day from submission to closure

## Mismatch Analysis
- Category: SEVERITY_OVER (claimed C:H without evidence) + COMPOUND_FINDING (three weak findings bundled) + FEATURE_MISS (oracle is documented)
- Root Cause: Three compounding mistakes:
  1. Started CVSS at C:H (key extraction) but had to retract mid-review because Binder.getCallingUid() + cert hash check blocks non-whitelisted callers. Once a reporter downgrades severity during the triage cycle, credibility collapses.
  2. Bundled "normal permission" + "race on session fields" + "rate-limit bypass on whitelist fetch" + "oracle" into a single report. All three weak. Triager closes the one weakest finding, the others fall with it.
  3. The oracle (5300 vs 5301) is expected behavior — KMS APIs return distinct error codes for distinct states; documenting cloud-encryption usage via an error code is not disclosure in the CVSS C sense.
- Which destruction test would have caught this: Gate 2 Section C Q7 (RAW CVSS — based purely on PoC evidence, not claimed severity) + Gate 1 Q1 (oracle = documented state reporting).

## Rule Update
- Mode affected: Gate 1, Gate 2, reporter
- Specific change:
  - reporter rule: one primary finding per report. Supporting findings only when they share the SAME CVE-eligible root cause. Different CWEs → different reports.
  - Gate 2 Section C Q7: CVSS must be derived mechanically from PoC evidence, not from reporter's intuition. Any C/I/A metric claimed without a matching evidence artifact = auto-downgrade to N.
  - "No mid-review severity downgrades": if reporter needs to downgrade severity after triage starts, Phase 4.5 must be re-run with the new severity before resuming the thread.
  - Kill compound findings at Gate 2 Section A: if a single PoC script proves 1 of 3 claims, keep 1, delete the other 2 or move them to explore_candidates.md.
- Confidence: HIGH
