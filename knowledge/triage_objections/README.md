# Triage Objections — Feedback Learning Directory (v12)

This directory stores actual triage feedback from bug bounty platform submissions. Used by `triager-sim` Mode 4 (replay) to calibrate future predictions.

## Structure

```
triage_objections/
├── README.md                    # This file
├── duplicate_defense/           # "Already reported" / "Same as CVE-XXXX" rejections
├── scope_defense/               # "Out of scope" rejections
├── severity_defense/            # "This is Low, not High" downgrades
├── prereq_vs_impact_defense/    # "Prerequisites too high for impact" rejections
└── feature_defense/             # "This is intended behavior" rejections
```

## File Format

Each feedback file: `<target>_<finding_slug>.md`

```markdown
---
target: <target_name>
finding: <finding_slug>
date_submitted: YYYY-MM-DD
date_resolved: YYYY-MM-DD
platform: Bugcrowd/Immunefi/H1/Intigriti
---

# Triage Feedback: <target> — <finding>

## Our Prediction
- Verdict: SUBMIT
- Severity: PX / CVSS X.X
- Key claim: [1-sentence]

## Actual Outcome
- Status: CLOSED (Informative) / TRIAGED (PX) / DUPLICATE / NOT APPLICABLE
- Triager Comment: "<exact comment>"
- Resolution Time: X days

## Mismatch Analysis
- Category: FEATURE_MISS / SCOPE_MISS / DUPLICATE_MISS / SEVERITY_OVER / PREREQ_UNDER / EVIDENCE_WEAK
- Root Cause: [Why our prediction was wrong]
- Which destruction test question would have caught this: [Q1-Q5 / Section A-C]

## Rule Update
- Mode affected: [1/2/3]
- Specific change: [Add check / Modify threshold / Add example]
- Confidence: [HIGH / MEDIUM / LOW]
```

## Usage

- **triager-sim Mode 4 (replay)**: Reads these files to calibrate predictions
- **triager-sim Modes 1-3**: Pre-checks this directory for same-program feedback before running destruction tests
- **Orchestrator**: Archives kill reasons here after Gate kills (Explore Lane Recycling)

## Rationale

Self-Consistency (Wang et al., 2023) — comparing predictions against ground truth improves calibration. With 37+ submissions tracked, this transforms triager-sim from a generic critic into a calibrated predictor tuned to actual platform behavior.
