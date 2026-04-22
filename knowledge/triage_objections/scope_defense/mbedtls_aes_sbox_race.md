---
target: Arm Trusted Firmware (MbedTLS 3.6 LTS)
finding: aes_init_done_race_condition_on_ARM
date_submitted: 2026-03-10
date_resolved: 2026-04-03
platform: Intigriti
code: ARM-X63LG185
verdict: Archived / Not applicable
severity_claimed: Medium (5.6)
bounty: 0
---

# Triage Feedback: Trusted Firmware — AES S-box lazy-init race

## Our Prediction
- Verdict: SUBMIT
- Severity: Medium / CVSS 5.6 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L)
- Key claim: TSan-confirmed data race on AES global tables + ARM objdump missing DMB barrier → silent ciphertext corruption on first-call contention.

## Actual Outcome
- Status: NOT APPLICABLE / Archived
- Triager Comment: "As explained in our triage standards we require submissions to come with a step-by-step demonstration of an attack scenario. As this is not included, we've decided to close this submission. It's not clear how to use the files in your attachments, what these demonstrate, etc. Please also read up on our rules regarding AI usage in our code of conduct."
- Resolution Time: 24 days

## Mismatch Analysis
- Category: SCOPE_MISS (standalone harness) + AI-SLOP flag
- Root Cause: (1) TSan on a synthetic multi-thread harness is not "legitimate use of the software" — Trusted Firmware's rule is that the PoC must trigger through a real deployment path (e.g., a MCUboot image, a TF-A BL stage, or a PSA Crypto API caller on a real ARM target). We delivered a standalone C program that linked libmbedcrypto and called mbedtls_aes_setkey_enc() from multiple pthreads — this is exactly "calling individual functions out of context". (2) Long-form report + dense CVSS tables + perfect structure triggered Intigriti's AI-usage heuristic.
- Which destruction test would have caught this: Gate 2 Section A Q1 (LIVE vs MOCK) and A Q3 (ENVIRONMENT MATCH).

## Rule Update
- Mode affected: Gate 2 (poc-destruction), Phase 4.5 AI slop check
- Specific change:
  - Add "standalone-harness detector": if PoC source imports the target as a library and calls its functions directly (no real platform/service stack), auto-KILL unless program brief explicitly permits "library-level PoC".
  - For Intigriti/Trusted-Firmware style programs, require an attack-scenario section that names: the real consumer (e.g., TF-A, MCUboot, PSA client), the invocation path, and the observable real-world effect.
  - Run slop-check before Intigriti submission — AI-slop score >2 = rewrite.
- Confidence: HIGH
- Cross-ref: knowledge/triage_objections/scope_defense/tf_m_mailbox_outvec.md
