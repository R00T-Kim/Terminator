# Endpoint Map — <TARGET_NAME>

Generated: <DATE>
Total: 0 endpoints
Tested: 0
Coverage: 0.0%

## Status Legend
- **UNTESTED**: Not yet analyzed
- **TESTED**: Analyzed, no vulnerability found
- **VULN**: Vulnerability confirmed (include finding ID)
- **SAFE**: Explicitly verified as secure (auth checks present, input validated)
- **EXCLUDED**: Out of scope per program rules

## Endpoint Table

| Endpoint | Method | Auth | Status | Notes |
|----------|--------|------|--------|-------|

## Coverage Gate
Run `python3 tools/bb_preflight.py coverage-check <target_dir>` to validate.
Threshold: 80% — Phase 2 blocked until coverage >= 80%.

## How to Update
After testing each endpoint, update Status column:
1. Scout: Initial population (all UNTESTED)
2. Analyst: Mark EXCLUDED (per program rules), begin TESTED/SAFE
3. Exploiter: Mark VULN (with finding reference) or SAFE
4. Orchestrator: Run coverage-check before Phase 2 transition
