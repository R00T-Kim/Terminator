---
target: VMware Workstation/Fusion
finding: serial0.fileName_guest_to_host_file_write
date_submitted: 2026-04-07
date_resolved: 2026-04-18
platform: Intigriti
code: VMWARE-D5P0EHPB
verdict: Closed / Informative
severity_claimed: High (8.2)
bounty: 0
---

# Triage Feedback: VMware — .vmx serial file redirection

## Our Prediction
- Verdict: SUBMIT
- Severity: High / CVSS 8.2 (AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)
- Key claim: malicious .vmx serial0.fileName writes arbitrary host file on VM boot → .bashrc / authorized_keys ACE

## Actual Outcome
- Status: CLOSED (Informative)
- Triager Comment: "by design, the serial port can be configured to write to a file of the user's choice, if they have chosen a file that they shouldn't be writing to. Also, if the serial port file already exists, a prompt appears to ask the user if they want to replace the original file or append new data onto the end of it."
- Resolution Time: 11 days

## Mismatch Analysis
- Category: FEATURE_MISS
- Root Cause: Treated "configurable serial backing file" as a vulnerability. Vendor documents the behavior AND shows an explicit OS-level append/replace prompt — which we did not screenshot. Our PoC also needed UI:R (victim opens .vmx), which on a configurable-by-design feature is indistinguishable from "user chose to redirect serial to .bashrc".
- Which destruction test would have caught this: Gate 1 Q1 (FEATURE CHECK — "is this documented/intended?"). Vendor help pages for serial ports explicitly describe file-backed output and append/truncate prompts.

## Rule Update
- Mode affected: Gate 1 (finding-viability)
- Specific change: Any config-driven I/O behavior (serial, parallel, shared folder, isolated VM toggle) requires a CITED vendor doc stating "undocumented" or "never prompts user"; absence of that citation triggers auto-FEATURE_MISS suspicion.
- Also: UI:R + config-file-opened attacks must enumerate every OS-level prompt the victim sees; if even one is missing from the PoC log, report is not submit-ready.
- Confidence: HIGH
