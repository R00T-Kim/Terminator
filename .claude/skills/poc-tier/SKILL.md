---
name: poc-tier
description: PoC 파일의 품질을 Tier 1-4로 분류. exploiter 완료 후 triager_sim 전에 실행. "PoC tier", "PoC 품질", "poc quality", "exploit 검증" 키워드 매칭
user-invocable: true
argument-hint: <poc-file-path>
allowed-tools: [Read, Bash, Grep]
---

# PoC Quality Tier Classification

PoC 파일의 품질을 Tier 1-4로 자동 분류한다.
Tier 3-4 finding 제출로 인한 실패 방지 (Veda, Katana 등 4건 실패).

## 입력
- `$ARGUMENTS`: PoC 파일 경로 (예: `evidence/ssrf/poc.py`, `poc/foundry-test/test/Exploit.t.sol`)

## Tier 정의

| Tier | Name | Requirements | H1 Outcome |
|------|------|-------------|------------|
| **1** | Gold | 런타임 검증 + Integration test + 증거 캡처 + UA 핑거프린트 | ACCEPT (high confidence) |
| **2** | Silver | 실행 가능한 스크립트 + 출력 캡처, integration test 없음 | ACCEPT (moderate confidence) |
| **3** | Bronze | 스크립트 존재하지만 출력이 이론적/목업 | **DROPPED — 제출 불가** |
| **4** | Reject | PoC 없음, 의사코드만, "left as exercise" | **DROPPED — 제출 불가** |

## 실행 절차

### Step 1: PoC 파일 읽기
```
Read $ARGUMENTS
```

### Step 2: 양성 시그널 탐지 (+1 tier 각각)

**네트워크 호출 존재 여부**:
!`grep -cE "requests\.|fetch\(|curl |remote\(|cast send|cast call|axios\.|http\.|urllib" "$ARGUMENTS" 2>/dev/null || echo "0"`

**실제 응답 캡처 존재 여부**:
!`grep -cE "response\.|status_code|\.json\(\)|recvline|recvuntil|interactive|200 OK|HTTP/" "$ARGUMENTS" 2>/dev/null || echo "0"`

**테스트 프레임워크 사용**:
!`grep -cE "forge test|npm test|pytest|unittest|assert|vm\.expect|console\.log" "$ARGUMENTS" 2>/dev/null || echo "0"`

### Step 3: 음성 시그널 탐지 (-1 tier 각각)

**미완성 마커**:
!`grep -ciE "TODO|FIXME|theoretical|hypothetical|would work|should work|left as exercise|mock|placeholder" "$ARGUMENTS" 2>/dev/null || echo "0"`

**하드코딩 mock 데이터**:
!`grep -cE "fake_|mock_|dummy_|example\.com|0xdead|placeholder" "$ARGUMENTS" 2>/dev/null || echo "0"`

**실행 불가 마커** (주석 처리된 핵심 로직):
!`grep -cE "^#.*exploit|^#.*send|^#.*remote|^//.*attack" "$ARGUMENTS" 2>/dev/null || echo "0"`

### Step 4: Tier 계산
```
base_tier = 2  (Silver 기본)

# 양성 시그널
if 네트워크 호출 > 0: tier -= 0  (유지)
else: tier += 1  (Silver→Bronze)

if 응답 캡처 > 0: tier -= 1  (상승 가능)
if 테스트 프레임워크 > 0: tier -= 0.5

# 음성 시그널
if 미완성 마커 > 0: tier += 1
if mock 데이터 > 2: tier += 1
if 실행 불가 > 0: tier += 1

# 범위 제한
tier = clamp(tier, 1, 4)
```

### Step 5: 결과 출력
```
[POC-TIER] File: <path>
[POC-TIER] Positive signals: network_calls=N, response_capture=N, test_framework=N
[POC-TIER] Negative signals: incomplete=N, mock_data=N, commented_out=N
[POC-TIER] Tier: N (<name>)
[POC-TIER] Result: PASS (Tier 1-2) / BLOCK (Tier 3-4, 제출 불가)
```

### BLOCK 시 행동
- **Tier 3**: "스크립트는 있지만 실제 실행 증거 없음. 실행 후 output.txt 캡처 필요"
- **Tier 4**: "PoC 없음. exploit 코드 작성 필수. 이론적 설명만으로는 100% Informative"

## DeFi PoC 추가 체크
Foundry test인 경우:
- `vm.deal()` 사용 + honest disclosure 없음 → Tier 3으로 하락
- `fork-url` + 실제 블록 넘버 → Tier 1 시그널
- `assert` 문으로 profit 증명 → Tier 1 시그널
