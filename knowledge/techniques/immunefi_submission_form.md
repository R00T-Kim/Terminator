# Immunefi Bug Bounty Submission Form Template
**Last Updated**: 2026-02-18 (Kiln DeFi 제출 시 캡처)

---

## 양식 구조 (5 Steps)

### Step 1: Assets and Impact
- **Program 선택**: 드롭다운에서 타겟 프로그램 선택
- **Asset 선택**: 프로그램의 in-scope 컨트랙트 목록에서 선택 (주소 + 체인)
- **Impact 선택** (1개 이상):
  - Theft of unclaimed yield
  - Permanent freezing of unclaimed yield
  - Temporary freezing of funds (> 2 days)
  - Direct theft of any commission
  - **Griefing** (no profit motive, damage to users/protocol)
  - Direct theft of any user funds
  - Permanent freezing of funds
  - Protocol insolvency
  - "Impact not in list?" 옵션도 있음

### Step 2: Severity Level
- Critical / High / Medium / Low / Informational 중 선택
- Immunefi Impact 정의에 맞춰야 함

### Step 3: Main Report

#### 3-1. Title (필수)
- 짧고 명확하게
- 패턴: "[취약점 분류] in [함수/컴포넌트] leads to [영향]"
- 예: "Reentrancy in withdraw function leads to total loss of funds"
- 예: "Broken _checkPartialShares Logic Prevents Safe offset>0 Vault Deployment"

#### 3-2. Description (필수, Markdown 지원)
권장 구조:
```markdown
## Brief/Intro
1단락. 문제 + 영향 요약.

## Vulnerability Details
- Root Cause (코드 스니펫 포함)
- Trigger Sequence (단계별)
- 기존 Known Issue와의 차별화 (해당 시)

## Impact Details
- 영향받는 함수/자산/사용자
- 자금 위험 분석
- Severity 근거

## References
- EIP/표준 링크
- 코드 라인 참조 (Vault.sol:403 등)
- 감사 선례 링크
```

#### 3-3. Proof of Concept (필수)
```markdown
## Proof of Concept
- 환경 설정 (Foundry, Hardhat 등)
- 테스트 결과 (PASS/FAIL)
- Key Evidence 테이블
- How to Run 섹션
```

#### 3-4. Secret Gist (선택)
- GitHub Gist URL 입력란
- **반드시 Secret Gist** (Public 금지)
- PoC 코드 파일 전체를 Gist에 업로드
- `gh gist create --desc "설명" file1.sol file2.sol`

#### 3-5. Attachments (선택)
- PNG/JPEG 스크린샷
- 최대 20개, 개당 8MB 이하
- ZIP 파일은 첨부 불가 → Gist 사용

#### 3-6. Acknowledgment (필수)
- "I confirm that my submission includes a clear, original explanation and a working PoC" 체크

### Step 4: Wallet Address
- 바운티 수령용 지갑 주소 입력
- 체인별 주소 (ETH, MATIC 등)

### Step 5: Review
- 전체 검토 후 Submit

---

## 주의사항

### AI-Generated 경고 (2026년 기준)
- Immunefi가 AI-generated 보고서를 적극 탐지 중
- "automated scanner output" 판정 시 즉시 닫힘 + 계정 경고
- 대응: specific block/tx, 매번 다른 구조, 관찰적 언어, 템플릿 문구 0개

### Severity 선택 전략
- **자체 평가를 약간 낮게** 잡는 게 안전 (High 대신 Medium)
- "조건부 High" 같은 표현으로 업사이드 여지 남기기
- 트리아저가 올려주는 건 OK, 내려야 하면 신뢰 하락

### Known Issue 주의
- 프로그램 페이지의 "Known Issues" 반드시 확인
- Known Issue와 겹치면 즉시 OOS 처리
- 차별화 테이블로 명확히 구분

### Description vs PoC 분리
- Description: 취약점 설명 + 영향 + 참조
- PoC: 실행 가능한 코드 + 결과 + 재현 방법
- 두 필드를 명확히 분리 (중복 최소화)

---

## 제출 후 프로세스
1. 제출 → "Under Review" 상태
2. 트리아저 배정 (1-7일)
3. 트리아저 리뷰 → Accept / Need More Info / Reject
4. Accept → 프로젝트팀 리뷰 → 바운티 결정
5. 바운티 지급 → KYC 필요 (Immunefi 정책)
