---
target: DEXX (dexx.ai)
finding: absent_OTP_verification_controls_enable_preemptive_account_control
date_submitted: 2026-03-05
date_resolved: 2026-03-06
platform: HackenProof
verdict: Out of Scope
severity_claimed: (not scored — OOS before rating)
bounty: 0
---

# Triage Feedback: DEXX — OTP rate-limit + preemptive account control

## Our Prediction
- Verdict: SUBMIT
- Key claim: /v1/register_code has no rate-limit; 100+ consecutive OTP sends accepted; attacker registers target email before victim can → preemptive account control; OTP verification has no failed-attempt lockout.

## Actual Outcome
- Status: Out of Scope
- Triager Comment (HackenProof @HP-Triage0x06-dxcv): "both missing rate limiting and account pre-takeover vulnerabilities are out of scope for this program. While you've demonstrated the absence of rate controls on OTP verification leading to preemptive account control, these types of findings do not qualify for bounty eligibility."
- Resolution Time: <1 day

## Mismatch Analysis
- Category: SCOPE_MISS (program-explicit exclusion)
- Root Cause: HackenProof DEXX program explicitly excludes (a) missing rate limiting and (b) account pre-takeover. This is documented in the OOS section of the program brief. Our target-evaluator and Phase 0.2 rules-check both failed to fetch and inject this exclusion — or did fetch it but agents did not halt on keyword match.
- Which destruction test would have caught this: Gate 1 Q2 (SCOPE CHECK).

## Rule Update
- Mode affected: Phase 0.2 (rules-check), exclusion-filter injection
- Specific change:
  - bb_preflight.py exclusion-filter must emit a structured keyword list ["rate limit", "rate limiting", "account pre-takeover", "preemptive account", "user enumeration", "SIM swap", "OTP abuse", "toll fraud"] that Gate 1 auto-matches against finding title + key-claim.
  - Any match = SCOPE_MISS auto-KILL without spawning triager-sim.
  - Rules-check v3: require the program brief's Out-of-Scope list to be parsed into structured flags during init (not just pasted into a markdown summary).
- Confidence: HIGH
- Cross-ref: scope_defense/namuhx_force_change_password_ato.md (same policy-exclusion pattern)
