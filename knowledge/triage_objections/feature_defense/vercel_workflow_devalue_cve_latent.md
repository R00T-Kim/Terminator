---
target: Vercel Workflow (vercel/workflow)
finding: js_eval_builtin_on_devalue_parse_output_latent_CVEs_22774_22775
date_submitted: 2026-02-11
date_resolved: 2026-02-11
platform: HackerOne
report_id: 3548850
verdict: Closed / Informative
severity_claimed: Medium (6.3)
bounty: 0
---

# Triage Feedback: Vercel Workflow — devalue CVE-2026-22774/22775 latent bug

## Our Prediction
- Verdict: SUBMIT
- Severity: Medium 6.3
- Key claim: devalue 5.6.0 pinned with known CVEs; serialization.ts:448 uses the JavaScript `e`+`val` builtin on stringify output; 5 deserialization paths call devalue `parse()` on event log data.

## Actual Outcome
- Status: CLOSED (Informative) — same day
- Triager (@h1_analyst_trev): "While we recognize the value of dependency hygiene and defense-in-depth improvements and your recommendations are valuable. However, the program requires demonstration of actual exploitable impact for acceptance. Since you've confirmed there's no viable exploitation path under the current architecture, we will have to close this submission as Informative."
- Resolution Time: <1 day

## Mismatch Analysis
- Category: FEATURE_MISS (self-acknowledged latent) — THE REPORT ITSELF SAID "NOT EXPLOITABLE (as currently architected)"
- Root Cause: The report body contained a table titled "NOT EXPLOITABLE (as currently architected)" with entries like "RCE via the `e`+`val` builtin — stringify() always produces JSON-safe arrays; no path bypasses stringify before the call". We submitted anyway hoping triagers would pay for defense-in-depth. They do not.
- This is the classic latent-bug submission failure: code-level defect exists but no attacker-controlled path to it under the current architecture. Program rule (always): "require demonstration of actual exploitable impact".
- Which destruction test would have caught this: Gate 1 Q5 (LIVE PROOF CHECK — "provable with live evidence?" — NO) = instant KILL.

## Rule Update
- Mode affected: Gate 1 Q5 + anti-latent-submission linter on report draft
- Specific change:
  - reporter linter (new): if the report body contains strings "NOT EXPLOITABLE", "not currently exploitable", "no viable exploitation path", "latent", "defense-in-depth only", "dependency hygiene" — auto-block Phase 4 and require either: (a) remove those words with proof of exploit, or (b) delete the finding.
  - Gate 1 Q5 tightened: "Is there a proven attacker-controlled input path to the vulnerable sink under the CURRENT codebase, not a hypothetical future refactor?" NO = KILL before PoC work begins.
- Confidence: HIGH
