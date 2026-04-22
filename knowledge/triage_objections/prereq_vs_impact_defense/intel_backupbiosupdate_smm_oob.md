---
target: Intel Server Board M50FCP (BackupBiosUpdate.efi)
finding: ExtHeaderOffset_SMM_OOB_read_write_variant_of_CVE-2025-20034
date_submitted: 2026-03-16
date_resolved: 2026-04-16
platform: Intigriti
code: INTEL-OPD1IICX
verdict: Closed / Informative
severity_claimed: Medium (5.7)
bounty: 0
---

# Triage Feedback: Intel M50FCP — BackupBiosUpdate.efi OOB R/W

## Our Prediction
- Verdict: SUBMIT
- Severity: Medium / CVSS 5.7
- Key claim: Unicorn-emulated OOB read (977 deref) + OOB write (sentinel 0xDEADBEEF→0x0) in SMM via unchecked ExtHeaderOffset — distinct field from CVE-2025-20034 DataSize path.

## Actual Outcome
- Status: CLOSED (Informative)
- Triager Comment (Intel PSIRT via Intigriti): "SPI flash is locked at the end of DXE. SPI flash data is signed and protected by PFR. BackupBiosUpdate.efi is a dxe driver. It is not available in any operation system. In conclusion, Intel does not believe that the issue is exploitable."
- Resolution Time: 31 days

## Mismatch Analysis
- Category: PREREQ_UNDER (prerequisite blocked by existing mitigation) + FEATURE_MISS (module is DXE-only)
- Root Cause: Our attack path required (a) ring-0 write to backup SPI region at 0xFFC00000, and (b) triggering SW SMI 0x200 from OS. Intel showed: SPI is locked at end-of-DXE (blocks (a)), PFR signs the flash (blocks attacker-modified content from reaching the parser), and BackupBiosUpdate.efi is a DXE driver that "is not available in any operation system" (blocks (b) entirely). The whole chain evaporates.
- Which destruction test would have caught this: Gate 1 Q4 (PREREQUISITE CHECK — "attacker prerequisite ≥ impact?"). We never proved either prerequisite was reachable post-DXE; we assumed both.
- Also notable: our report flagged "SMM_BWP is not claimed to be universally absent" in "What This Report Does NOT Claim" — we knew the prerequisite was unverified and submitted anyway.

## Rule Update
- Mode affected: Gate 1 (finding-viability), Phase 4 critic
- Specific change:
  - For any UEFI/SMM/DXE finding, required evidence tier raises to E1 "demonstrates on real firmware in an OS-reachable execution state". Emulation-only → E3 at best → explore_candidates, not submit.
  - Mandatory DXE driver reachability check: does the module load in OS runtime, or only during boot? If only boot, the attacker-from-OS threat model is invalid unless bootkit persistence is proven.
  - Mandatory mitigation-scan: BIOS_CNTL.SMM_BWP, PFR presence, SPI lock-before-EOP, Boot Guard — each must be CHECKED on target hardware, not assumed.
- Confidence: HIGH
