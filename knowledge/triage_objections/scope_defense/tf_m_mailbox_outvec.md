---
target: Arm Trusted Firmware-M v2.2.2
finding: multicore_mailbox_outvec_writeback_without_tfm_hal_memory_check
date_submitted: 2026-03-11
date_resolved: 2026-03-16
platform: Intigriti
code: ARM-NANKVYOJ
verdict: Archived / Out of scope
severity_claimed: Medium (6.8)
bounty: 0
---

# Triage Feedback: TF-M — mailbox outvec write-back without tfm_hal_memory_check

## Our Prediction
- Verdict: SUBMIT
- Severity: Medium 6.8 (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L)
- Key claim: tfm_spe_mailbox.c:238 stores NS-supplied out_vec descriptor pointer without tfm_hal_memory_check; the TrustZone single-core path (psa_call_api.c:78-83) does the check; TFMV-8/CVE-2024-45746 only added PSA_SUCCESS guard, not bounds check; standalone harness confirms 3 scenarios (stale-pool, shared-NS, S_DATA-blocked).

## Actual Outcome
- Status: ARCHIVED (Out of scope)
- Triager Comment: "Note: The proof-of-concept must demonstrate that the vulnerability is exploitable through legitimate use of the software. Calling individual functions out of context or copying code into a PoC is not sufficient. Therefore I will have to close the report as out of scope."
- Resolution Time: 5 days (+archive 19 days later)

## Mismatch Analysis
- Category: SCOPE_MISS (standalone harness — program-specific OOS clause)
- Root Cause: Trusted Firmware program has an explicit OOS rule: library-level PoCs are invalid. Our harness directly called tfm_spe_mailbox.c functions from userspace — not executed on a real multi-core platform (Cypress PSoC64, Corstone-1000 + TFM_PLAT_SPECIFIC_MULTI_CORE_COMM=OFF). Identical failure class to the MbedTLS AES race.
- Which destruction test would have caught this: Gate 2 Section A Q1 (LIVE vs MOCK).

## Rule Update
- Mode affected: Gate 2 + program-rules fetch (Phase 0.2)
- Specific change:
  - Phase 0.2 must now cache program OOS clauses as structured flags. For Trusted Firmware, set `requires_legitimate_use_poc=true`. Any PoC not satisfying that flag auto-KILLs at Gate 1.
  - Orchestrator rule: firmware / TEE / bootloader programs default to `requires_platform_runtime_evidence=true` until explicitly overridden by the program brief.
- Confidence: HIGH
- Cross-ref: knowledge/triage_objections/scope_defense/mbedtls_aes_sbox_race.md
