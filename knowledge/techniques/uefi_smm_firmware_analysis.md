# UEFI SMM Firmware Analysis — Intel Bug Bounty Methodology

> Learned from Intel M50FCP BackupBiosUpdate.efi analysis (2026-03-14)

## Overview

UEFI SMM (System Management Mode) 펌웨어의 보안 취약점 분석 방법론. Intel Bug Bounty 프로그램 대상 실전 적용.

## Target Acquisition

### 펌웨어 다운로드
- Intel Download Center에서 Server Board BIOS 패키지 다운로드
- UEFIExtract NE (LongSoft/UEFITool GitHub) 로 SMM 모듈 추출
- PE32 body: `<module>/1 PE32 image section/body.bin` 경로

### SMM 모듈 우선순위 (공격면 기준)
1. **Flash write 관련**: BackupBiosUpdate, SmmRuntimUpdate, FwBlockServiceSmm
2. **PFR (Platform Firmware Resilience)**: PfrSmmDriver, PfrSmiUpdateFw
3. **Variable 처리**: SmiVariable, VariableSmm, PlatformSecureVariableSmm
4. **HECI/ME 통신**: HeciAccessSmm, HeciControlSmm
5. **IPMI/BMC**: SmmGenericIpmi
6. **TPM**: Tcg2Smm
7. **Error handling**: WheaERST, CrashLogSmm, ImcErrorHandler

## Analysis Methodology

### Phase 1: Ghidra MCP 정적 분석
```
1. open_file(module.efi)
2. analyze()
3. list_functions() → SWSMI 핸들러 식별
4. get_pseudocode(handler) → CommBuffer 트레이싱
```

### Phase 2: SWSMI Handler 패턴
- `gSmst->SmiHandlerRegister(SW_SMI_VALUE, type, handler, ...)` 찾기
- CommBuffer = ring-0에서 전달, 공격자 제어
- 핵심 체크: `SmmIsBufferOutsideSmmValid` 호출 여부

### Phase 3: 취약점 패턴
| 패턴 | CWE | 설명 |
|------|-----|------|
| Offset/size → pointer without bounds check | CWE-20/125/787 | **확인된 패턴** (BackupBiosUpdate) |
| CommBuffer → protocol vtable without SMRAM check | CWE-822 | SmmRuntimUpdate에서 시도 (crypto chain으로 무효) |
| TOCTOU (double-fetch from non-SMRAM) | CWE-367 | WheaERST에서 시도 (duplicate 리스크) |
| Integer overflow in allocation | CWE-190 | CrashLogSmm에서 시도 (오버플로 없음 확인) |
| CpuIndex 미검증 | CWE-129 | PfrSmmDriver (PiSmmCpuDxeSmm이 bounds check → MITIGATED) |

### Phase 4: Unicorn 에뮬레이션 (E2 증거)
```python
# 핵심 교훈:
# 1. PE SectionAlignment 작으면 전체 이미지 한 블록 매핑
# 2. 외부 의존성(gSmst) 패치 → 이유 문서화 필수
# 3. OOB 영역을 traversable entries로 채움 (0x00=무한루프, 0xCC=13MB점프)
# 4. 매칭 타입 엔트리를 OOB에 배치 → pointer propagation 증명
# 5. TEST A(정상) vs TEST B(악의적) differential 필수
# 6. instruction limit 제거, timeout-only
# 7. Snippet execution으로 write path 증명 시 UC_ERR 선제 해명
```

## Intel Program OOS 주의사항
- NUC BIOS = OOS (Licensed product)
- UEFI shell 접근 공격 = OOS (Owner-Attacker)
- Physical access = OOS
- Third-party (Phoenix, AMI, Insyde) = OOS
- EOL = 바운티 없음
- **IN SCOPE**: CSME/BMC, Malicious Kernel (ring-0), Intel Reference UEFI FW

## CVSS 교훈
- SC/SI/SA: SMM code execution chain 미완성이면 **전부 None**
- VC: exfiltration path 없으면 **Low** (SMM 내부 소비만)
- VI: OOB write 확인되면 **High** 유지 가능
- "솔직한 MEDIUM이 부풀린 HIGH보다 낫다" — Judge 피드백

## 도구
- **Ghidra MCP**: PRIMARY (r2 금지)
- **UEFIExtract NE**: 펌웨어 추출 (`~/tools/uefiextract`)
- **Unicorn 2.1.2 + pefile**: 에뮬레이션 PoC
- **strings/objdump**: 보조
- **CodeQL 2.24.1**: 커널 드라이버용 (UEFI에는 소스 없어서 불가)

## 결과
- **확인됨**: BackupBiosUpdate.efi OOB R/W (CWE-20/125/787), CVSS 5.7 MEDIUM
- **DROPPED**: SmmRuntimUpdate (crypto chain), CrashLogSmm (no overflow), PfrSmmDriver (callee bounds check)
- **커널 드라이버 (ivpu/xe/ice)**: 0 findings (well-hardened, 14 IOCTLs 전수 검사)
- **총 커버리지**: 17 SMM 모듈 + 3 커널 드라이버 = 20개
