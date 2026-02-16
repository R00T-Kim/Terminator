# Terminator Knowledge Base

풀이한 문제, 실패한 시도, 발견한 기법, 버그 바운티 결과를 구조화하여 저장.
새 세션이 과거 경험을 참조할 수 있도록 함.

## Directory Structure

```
knowledge/
+-- README.md          <- 이 파일 (사용법)
+-- index.md           <- 전체 인덱스 (CTF + Bug Bounty 현황)
+-- challenges/        <- CTF 챌린지별 풀이/실패 기록
|   +-- level10_1_dhcc.md
|   +-- pwnablekr_fd.md
|   +-- nordvpn_kill_switch_bypass.md  (BB finding도 여기에 기록)
|   +-- ...
+-- techniques/        <- 재사용 가능한 기법 모음
|   +-- efficient_solving.md
|   +-- ssh_interaction_patterns.md
|   +-- bug_bounty_report_quality.md
|   +-- installed_tools_reference.md
|   +-- gdb_oracle_reverse.md
|   +-- ...
+-- bugbounty/         <- 버그 바운티 프로그램별 노트
|   +-- vercel_oss_bbp.md
|   +-- nordsecurity_bbp_scope.md
|   +-- oppo_bbp.md
|   +-- twilio_bbp_analysis.md
|   +-- ...
+-- contracts/         <- 에이전트간 계약/인터페이스 정의
```

## CTF Challenge Template

```markdown
# [Challenge Name]
- **Status**: SOLVED / FAILED / IN_PROGRESS
- **Type**: Reversing / Pwn / Web / Crypto / Misc
- **Difficulty**: Easy / Medium / Hard
- **Flag**: `FLAG{...}` (solved only)

## Analysis
- Binary characteristics, protections, key algorithms

## Solution
1. Approach and result
2. Successful approach details

## Failed Attempts (important!)
- Why it failed, lessons for next time

## Key Techniques
- Reusable techniques learned from this challenge

## solve.py Location
- `tests/wargames/extracted/<dir>/solve.py`
```

## Bug Bounty Finding Template

```markdown
# [Finding Name]
- **Status**: SUBMITTED / DUPLICATE / INFORMATIVE / ACCEPTED / DROPPED
- **Program**: HackerOne / YesWeHack / etc.
- **H1 ID**: #NNNNNNN
- **Severity**: CVSS score + vector
- **Bounty**: $X (or $0)

## Root Cause
- Exact code path, file:line

## PoC
- Script location, reproduction steps

## Lessons Learned
- What worked, what didn't, what to do differently
```

## Usage Rules (all sessions MUST follow)

1. **Before starting**: Read `knowledge/index.md` to check already solved/attempted challenges
2. **On failure**: Immediately record failure details in the challenge file
3. **On success**: Update challenge file + index.md + MEMORY.md
4. **New technique**: Save to `techniques/` as a separate file
5. **Before compaction**: Save current analysis state to the challenge file
