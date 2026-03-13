# Keeper Security Campaign Retrospective (2026-03-13)

## Campaign Summary

**Target**: Keeper Security (Bugcrowd)
**Duration**: 2026-03-04 to 2026-03-13 (~10 days)
**Findings attempted**: 11 (R1-R11)
**Submitted**: 9 (R1-R6, R8, R9, R11)
**DUPLICATE**: 2 (R1, R3) — $0
**HOLD**: 1 (R7 — caller chain unproven)
**KILL**: 1 (R10 — documented feature)
**TRIAGED**: 1 (R5 P2 by Tal_Bugcrowd)
**Expected bounty**: $8K-$20K realistic, $15K-$40K optimistic

---

## What Worked

### 1. Deep single-target strategy beats shallow multi-target
- Commander rotation plugins yielded R8 (SQLi, CWE-89) + R9 (CmdI, CWE-78) from the same unsanitized extraction point (`plugin_manager.py:174-176`)
- EPM Linux yielded R5 (MQTT) + R6 (PAM) + R11 (Kestrel API) — three different protocols/ports/binaries
- **One product deeply analyzed > 5 products shallowly scanned**
- Keeper yielded 9 submissions from one program; prior 23 DeFi programs yielded 0 bounties

### 2. Unpatched Linux builds of security products = gold mine
- EPM Linux v1.0.4.8 last-modified 2025-11-17, while Windows v1.1 had KPAM-612/614 fixes
- Security products that manage privilege escalation are high-value targets — any bypass is P2+
- **Rule: Check if vendor patches one platform but not another. Unpatched platform = immediate ROI**

### 3. External adversarial review (Judge.md) caught critical issues
- Driver mismatch: evidence used mysql-connector-python, Keeper uses pymysql → nearly killed R8
- R10 is a documented feature (`connect:xxx:env:PGPASSWORD` in PostgreSQL plugin docs) → KILL
- CVSS inflation: 8.0→7.3 (A:H→A:N, no proven availability impact)
- plugin_manager.py path error (commands/plugins/ vs plugins/)
- **Rule: Before every submission, run external adversarial review. Prompt: "Find every reason to reject this report."**

### 4. Non-claims section = best defense against triager pushback
- R11's "What this report does NOT claim" section was praised by critic, triager-sim, and Judge
- Explicitly stating: no code exec, no remote, no DoS, no root-equiv
- **Rule: Every report MUST have a "What this report does NOT claim" section**

### 5. Three-user access control matrix
- Testing with root/enrolled/unenrolled proved the ACL inconsistency empirically
- Creating `testunpriv` (uid=1001) proved "truly unauthenticated" access
- **Rule: ACL vulnerabilities require minimum 3 privilege contexts for testing**

### 6. Conservative CVSS builds trust
- R8: Dropping A:H to A:N (unproven availability impact) increased credibility
- R11: Self-assigning P4 with honest limitations → triager respects the researcher
- **Rule: CVSS conservatism > aggression. Triagers upgrade honest reports, downgrade inflated ones**

---

## What Failed

### 1. Driver mismatch nearly destroyed R8
- Initial PoC used `mysql-connector-python` (CMySQLCursor)
- Keeper imports `pymysql` at `mysql.py:13`
- Judge caught this; re-running through pymysql saved the finding
- **Rule: PoC MUST use the target's actual driver/library. Verify with `pip show` or import statements in source**

### 2. R10 = documented feature — insufficient research
- `connect:xxx:env:PGPASSWORD` is documented in Keeper's PostgreSQL plugin docs
- `connect` command deprecated since Commander 16.5.8
- Agent-generated finding without docs verification
- **Rule: Before claiming any "injection via configuration" finding, check if it's a documented feature. Especially: env var injection, config override, CLI parameter forwarding**

### 3. File path error undermined credibility
- Wrote `keepercommander/commands/plugins/plugin_manager.py` (wrong)
- Actual: `keepercommander/plugins/plugin_manager.py`
- Caught by Judge, critic, and triager-sim independently
- **Rule: Verify ALL file paths with glob/find before including in reports. Never trust memory**

### 4. R9 missing Windows cmd.exe evidence → Silver downgrade
- Evidence shows bash `$(id)` injection, but vulnerability targets Windows `cmd.exe` `&` separator
- "FALLBACK" framing in evidence file looked like a failed test
- Source code is unambiguous, but strict triager may demand target-OS evidence
- **Rule: Evidence must match the target environment. If vulnerability targets Windows, test on Windows (VM or Docker). Bash-only evidence = Tier 2 at best**

### 5. R1/R3 DUPLICATE — simple findings get scooped
- Someone submitted the same IP ACL bypass and dry-run file read on 2/24
- We submitted 3/4 — 8 days too late
- Simple, obvious vulnerabilities have high duplicate probability on popular targets
- **Rule: "Easy to find" = "easy for others to find". Complex multi-step findings survive; simple one-liners get duplicated**

### 6. R7 HOLD — sink without source chain
- Found `system()` call in `libkpm.so` but couldn't prove who calls it
- Ghidra xref analysis would have proven the chain but was skipped for time
- **Rule: Source→sink chain MUST be complete. A sink alone is not a finding. HOLD until chain is proven**

---

## Strategic Insights

### Same-codebase multi-CWE strategy
```
plugin_manager.py:174-176 (unsanitized extraction)
  ├── → mysql.py cursor.execute(f-string SQL)    → CWE-89 (R8)
  ├── → mssql.py cursor.execute(f-string SQL)    → CWE-89 (R8 variant)
  ├── → oracle.py cursor.execute(f-string SQL)   → CWE-89 (R8 variant)
  └── → ssh.py exec_command(f-string command)    → CWE-78 (R9)
```
One unsanitized data flow, four sinks, two CWEs, two separate reports. Each has different interpreter (SQL parser vs cmd.exe), different fix location, different impact. Bugcrowd typically accepts these as separate findings.

### Vendor direct response = strong positive signal
- R6: SLong-Keeper (vendor) responded directly → serious review in progress
- R5: Triaged as P2 within 2 days → EPM findings get attention
- Bugcrowd Staff-only responses are weaker signals than vendor engagement

### Consolidation risk management
- R8+R9 share `plugin_manager.py:174-176` root cause
- Defense: different CWE (89 vs 78), different sink, different interpreter, different plugin file, different remediation technique
- Document independence proactively in every report's "Distinction" section
- Worst case: vendor consolidates → one bounty instead of two

### Endpoint security products as targets
- EPM, EDR, PAM products run as root and manage privilege boundaries
- Any bypass of their enforcement = automatic P2+
- They often have local management APIs (Kestrel on 6889, MQTT on 8675) with inconsistent ACL
- **Pattern: localhost management API + inconsistent access control = common finding in endpoint security products**

---

## Pipeline Improvements Derived

### Phase 2 additions (exploiter)
1. **Driver verification gate**: Before running any PoC against a library/framework, verify the exact driver/library the target uses (check import statements in source)
2. **Target-OS evidence requirement**: If vulnerability targets a specific OS (Windows cmd.exe, Linux bash), evidence must be from that OS. Cross-OS evidence = automatic Tier 2 downgrade

### Phase 3 additions (reporter)
1. **Non-claims section mandatory**: Every report must include "What this report does NOT claim" with explicit boundaries
2. **File path verification**: All file:line references must be verified against actual source before report finalization

### Phase 4 additions (critic)
1. **Documented feature check**: Critic must verify that the exploit primitive is not a documented/intended feature of the product
2. **Driver/library match check**: Verify PoC uses the same driver as the target application

### Phase 4.5 additions (triager-sim)
1. **Evidence-target alignment check**: Flag if evidence OS/environment doesn't match the claimed attack target
2. **Path verification**: Verify all file paths in the report exist at the claimed locations
