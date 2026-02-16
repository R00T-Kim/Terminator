# Bug Bounty 보고서 품질 교훈 (Vercel AI SDK 세션에서 도출)

> 날짜: 2026-02-10 | 타겟: Vercel AI SDK (HackerOne)

## 1. Integration Test가 "돈 되는 증거"

**단위 테스트(reproduction function)만으로는 부족하다.** 심사관이 가장 먼저 묻는 것:
> "실제 npm 패키지에서도 똑같이 동작하나요?"

- `npm install ai@6.0.78` → 실제 `generateText()` 호출 → SSRF listener에 요청 도착
- **User-Agent 핑거프린트**(`ai-sdk/6.0.78 runtime/node.js/22`)가 SDK 코드 경로를 증명
- 단위 PoC는 "Supplementary Evidence"로 격하, Integration Test가 Primary

**패턴**: 항상 `npm install <target>` → 실제 API 호출 → listener 캡처 순서로 증거 확보.

## 2. CVSS 버전 확인 필수

- Vercel은 **CVSS 4.0** 사용 (CVSS 3.1 아님!)
- 프로그램 페이지를 꼼꼼히 읽지 않으면 점수 체계가 맞지 않아 신뢰도 하락
- CVSS 4.0은 "Attack Requirements", "Subsequent System" 개념이 추가됨
- **제출 전 반드시 프로그램 스코프 페이지의 severity 기준 확인**

## 3. V8 Prototype Pollution은 죽었다

- `JSON.parse('{"__proto__":{"polluted":true}}')` → `({}).polluted === undefined`
- **Modern V8 (Node.js 22+)에서 글로벌 prototype pollution 불가**
- `__proto__` 키는 parsed object의 own property로만 존재, Object.prototype에 영향 없음
- **보고서에서 "prototype pollution" 단독으로 주장하면 즉시 Info/Low로 판정**
- 대안: "token override via spread", "property injection via .passthrough()" 같은 **구체적 공격 시나리오**로 리프레임

## 4. 외부 리뷰어 피드백이 보고서를 구한다

초기 4개 보고서 → 외부 리뷰 후 전략 완전 변경:
- R1 (SSRF): Strong High → **Report A의 앵커**
- R2 (Proto Pollution): Info/Low → Token Override로 **리프레임하여 생존**
- R3 (OAuth SSRF): Derivative → **R1에 번들하여 가치 증대**
- R4 (Tool Injection): "Feature not bug" → **Informational로 격하**

**교훈**: 제출 전 반드시 "이걸 왜 거절할까?" 관점에서 검토. Critic agent가 이 역할 수행.

## 5. LLM 에코는 주장하지 마라

- "LLM이 stolen data를 응답에 포함한다" → 심사관: "모델 동작은 보장 안 됨"
- **대신**: "SSRF 데이터가 base64로 인코딩되어 provider API POST body에 포함된다"
- 이것은 **네트워크 캡처로 증명 가능**한 사실 (모델 행동에 의존하지 않음)
- provider API 요청 자체가 exfiltration 채널 (api.openai.com으로 데이터가 나감)

## 6. 302 Redirect 테스트 추가

- 초기 URL 검증이 있어도 redirect로 우회 가능
- `fetch()`는 기본적으로 redirect를 따라감 (`redirect: "follow"`)
- **모든 SSRF 보고서에 redirect 우회 테스트 포함** → 방어 복잡도 증가 = 심각도 상승

## 7. 프로젝트 자체 보안 규칙 위반 찾기

- Vercel AI SDK의 `CLAUDE.md`에 "Never use JSON.parse directly" 명시
- 실제로 22곳에서 위반 → **프로젝트가 자기 규칙을 안 지킴**
- 이것만으로도 "security hardening gap" 보고서가 됨
- **가장 강력한 근거**: 타겟이 스스로 정한 보안 기준 위반

## 8. ZIP 아티팩트 + Affected Version 필수

- HackerOne 프로그램 대부분이 ZIP PoC 첨부 요구
- "Affected version(s)" 필드 필수 → `ai@6.0.78` 같이 정확한 버전 명시
- 재현 가능한 `package.json` + 실행 스크립트 포함

## 9. Root Cause Consolidation 대비

- "같은 root cause의 여러 취약점 = 바운티 1개"
- R1(download SSRF)과 R3(OAuth SSRF)은 둘 다 "URL 검증 부재"
- **미리 번들해서 하나의 강력한 보고서로 제출** → 분리 제출 시 consolidation 당할 위험 제거

## 10. Critic → PoC → Integration Test → Report 순서

최적 워크플로우:
```
1. 초기 보고서 작성 (소스코드 분석 기반)
2. Critic 교차검증 (line numbers, function names, counts)
3. 단위 PoC 개발 + 실행
4. Integration Test (실제 패키지)
5. 외부 리뷰어 피드백
6. 보고서 리프레이밍 + evidence 삽입
7. CVSS 재계산 + ZIP 준비
8. 최종 proofread (사람이)
```

**절대 하지 말 것**:
- 보고서만 쓰고 PoC 없이 제출 (즉시 Needs More Info)
- 단위 테스트만으로 제출 (Integration Test 요구받음)
- prototype pollution을 단독 claim (V8에서 불가)
- LLM 에코를 exfiltration 채널로 주장 (검증 불가)

---

## Vercel Workflow/Skills 바운티 추가 교훈 (2026-02-11)

> 타겟: Vercel Workflow DevKit (`@workflow/core`) + Agent Skills (`vercel-labs/agent-skills`)

### 11. 전문가 리뷰 3라운드 사이클이 보고서 품질을 결정한다

- **V1 (Critic)**: 팩트체크 (CWE 번호, 날짜, 함수명). 가장 기본적이지만 자주 틀림
- **V2 (총평)**: "트리아저 입장에서 어디를 공격할까?" 관점. 프레이밍 전환 계기
- **V3 (정밀)**: 기술적 약점 각개격파. startedAt 타임스탬프 문제가 여기서 발견됨
- **교훈**: 최소 2라운드 리뷰 필수. 1라운드만으로는 프레이밍 이슈를 못 잡음

### 12. PoC에서 발견하는 "예상 밖의 강화 증거"

- V3 리뷰어가 "startedAt ≠ runId 타임스탬프" 약점을 지적
- PoC sweep 테스트를 작성하다가 **토큰이 startedAt과 완전 독립**임을 발견
- monotonicFactory의 첫 호출이 항상 동일한 PRNG 소비 → 타임스탬프 무관
- **PoC 작성 자체가 분석 도구**: 단순 검증이 아니라 새로운 발견을 만듦

### 13. 관찰적 언어(observational language)가 방어력을 높인다

- ❌ "Token-in-URL is the sole authentication" (단정적 → 반박 가능)
- ✅ "No additional authentication beyond the URL token was identified in the reviewed code" (관찰적)
- 인프라 통제(WAF, 엣지 레이트리밋)는 코드에서 검증 불가 → 항상 caveat 명시
- **"확인되지 않았다"가 "존재하지 않는다"보다 훨씬 안전**

### 14. 의도된 설계 vs 취약점 — 프레이밍이 생존의 핵심

- 무인증 엔드포인트 → "missing auth" 주장 시 "의도적 설계"로 반박당함
- **"abuse risk and operational security concern"으로 리프레임** → 의도 여부와 무관하게 유효
- CWE 매핑에 "intent-dependent" caveat 추가 → 트리아저가 고맙게 여김
- **unsafe defaults를 primary finding으로** → 의도 논쟁을 회피

### 15. 조건부 CVSS가 점수 싸움을 예방한다

- 고정 점수 하나만 제시 → 트리아저가 "너무 높다/낮다" 논쟁
- **조건부 테이블** 제시: "이 조건이면 HIGH, 저 조건이면 LOW"
- 트리아저가 자기 환경에 맞는 행을 골라 수용할 수 있음
- 점수를 보수적으로 두되, "상향 트리거"를 문서화해두면 나중에 올릴 근거도 깔림

### 16. eval() → JSON.parse() 권고가 devalue.parse()보다 안전하다

- `revive()` 함수가 "flattened intermediate representation"을 기대
- `devalue.parse()`는 full type reconstruction → 동작 다를 수 있음
- `JSON.parse()`는 JSON-safe 배열 그대로 반환 → 동작 동일성 보장
- **가장 보수적인 대체안 = 가장 수용률 높은 권고**

### 17. 대형 코드베이스 Bug Bounty는 단계별 클러스터링

Vercel 바운티에서 7개 보고서가 2개 클러스터로 나뉨:
- **Cluster A**: AI SDK (download SSRF + Token Override) — 기존 CVE 인접
- **Cluster B**: Workflow DevKit + Agent Skills (PRNG + eval/devalue + deploy secrets) — 신규 코드

**클러스터별로 제출 타이밍을 분리**하면:
- 트리아저 부담 감소 (7개 동시 제출 → 2~3개씩)
- 한 클러스터가 거절당해도 다른 클러스터에 영향 없음

### 18. 3-layer remediation이 1-liner보다 설득력 있다

- 단순 `--exclude='.env*'` → "빠지는 패턴 생김" 반박
- **3-layer**: (1) .vercelignore/.gitignore 존중 (2) 강제 차단 목록 (3) git ls-files 기반
- 트리아저가 "아 이건 실제로 패치하면 좋겠다" 느낌 → 수용률 상승
- **HMAC-derived seed > eval→parse** 같은 구조적 대안도 같은 맥락

### 19. 보고서 최상단에 "Executive Conclusion" 3문장

- 트리아저는 스크롤 많이 안 함. 첫 화면에서 판단
- **문장 1**: 현재 직접 exploit 가능 여부 (정직하게)
- **문장 2**: 핵심 수정 권고 (원라인 패치)
- **문장 3**: 왜 이 보고서가 가치가 있는지 (CVE 제거, defense-in-depth)
- 상세는 아래에 두되, 결론은 최상단에 고정

### 20. Serverless + Event Sourcing 시스템의 특수 위험: Poison Pill

- replay 기반 시스템에서 malformed event → 무한 재시도 → 비용 폭증
- 일반 웹앱과 다른 threat model
- **circuit breaker 권고**가 트리아저에게 "이 사람은 우리 시스템을 이해한다" 인상
- defense-in-depth 섹션에 운영 현실 반영 → 채택률 상승
