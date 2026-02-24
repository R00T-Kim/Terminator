# Target Assessment Report — v4 Scoring Rubric
**Date**: 2026-02-17
**Evaluator**: target-evaluator agent
**Method**: Web research + v4 scoring rubric + Kill Signal analysis

---

## Scoring Rubric (v4)

| Criterion | Max Points |
|-----------|-----------|
| Max Bounty (Critical) | +3 (≥$1M), +2 ($250K-$999K), +1 (<$250K) |
| Reports Resolved on Immunefi | +2 (active payout history), +1 (some activity), 0 (none visible) |
| Audit Density | −3 (5+ audits / major audit firms), −2 (3-4 audits), −1 (1-2 audits), 0 (none) |
| Codebase Age / Maturity | −2 (3+ years, stable), −1 (1-2 years), 0 (<1 year or recent expansion) |
| Unaudited Components | +3 (significant new/unaudited scope), +2 (some unaudited), +1 (minor), 0 (fully audited) |
| TVL / Attack Surface | +2 (>$500M TVL), +1 ($50M-$500M), 0 (<$50M) |
| Competitive Landscape | −2 (100+ prior reports), −1 (10-100), 0 (<10 known) |

**Scoring**: 10 = Perfect target. 7-10 = GO. 5-6 = CONDITIONAL GO. 0-4 = NO-GO.

---

## Target 1: Olympus DAO (OHM/gOHM)

### Research Summary
- **Program**: Immunefi, up to $3.3M Critical
- **Audit History**:
  - PeckShield (early audit)
  - Code4rena contest: Aug–Sep 2022 (public, ~100+ wardens)
  - Sherlock: BLV (Boosted Liquidity Vault) — Feb 2023
  - OtterSec: CrossChain Bridge — Apr 2023
  - Kebabsec: BLV — Feb 2023
  - Sherlock: On-Chain Governance — Jan 2024
  - **Total known audits: 5+ distinct engagements spanning 2022–2024**
- **Previous result**: Orchestrator read 16 contracts at Level 0-1, found 22 leads all LOW. No Slither/Mythril run. 4hr/$0.
- **Protocol age**: Launched 2021 (~5 years old)
- **TVL**: OHM/gOHM treasury has declined significantly; current TVL ~$50-100M range (not top-tier)
- **Competition**: Very active Immunefi program with long history — many researchers have analyzed

### Kill Signals
- [x] **Audit Fortress**: 5+ audits across C4, Sherlock, Ottersec, PeckShield, Kebabsec — heavy coverage
- [x] **Mature Codebase**: 5 years old, core protocol stable since 2022
- [x] **Already Failed Once**: Our team spent 4hr at Level 0-1 and found nothing above LOW
- [x] **Declining TVL**: Protocol is past peak; less researcher attention but also less reward potential

### Score Breakdown
| Criterion | Score | Notes |
|-----------|-------|-------|
| Max Bounty | +3 | $3.3M Critical |
| Reports Resolved | +1 | Some historical activity but limited recent |
| Audit Density | −3 | 5+ audits (C4, Sherlock x2, OtterSec, PeckShield, Kebabsec) |
| Codebase Maturity | −2 | 5 years old, core stable |
| Unaudited Components | +1 | Some newer governance modules exist but also audited |
| TVL/Attack Surface | +1 | ~$50-100M TVL |
| Competitive Landscape | −2 | 100+ researchers, long history |

**TOTAL SCORE: −1/10**

### Verdict: **NO-GO**

**Reason**: Olympus DAO is the textbook "Audit Fortress" case. 5+ audits from reputable firms, 5-year-old protocol, previously failed at Level 0-1 with no HIGH+ signal. Even if we now run Slither/Mythril, the probability of finding a novel Critical/High after this many audits by top firms is near zero. Our own experience confirms this (22 leads, all LOW). The $3.3M bounty is largely theatrical for a protocol of this maturity.

---

## Target 2: GMX V2 (Perp DEX)

### Research Summary
- **Program**: Immunefi, up to $5M Critical
- **Audit History** (most extensive of any DeFi protocol):
  - Guardian Audits: **17 separate engagements** (Oct 2022 – Jul 2023 alone: 7 engagements; post-launch: 10 more). 351 findings, 80 High/Critical resolved.
  - Sherlock: 2023-02-gmx (competitive audit)
  - Sherlock: 2023-04-gmx (competitive audit — gmx-synthetics)
  - Code4rena: Formal Verification competition Aug 2023 (39 wardens, Certora FV)
  - Zellic: Jan 2024 (Solana deployment)
- **Protocol age**: V2 launched 2023 (~3 years old)
- **TVL**: Large — GMX is top-3 perp DEX, ~$500M+ TVL
- **New in 2025-2026**: GMX Multichain (LayerZero-powered, starting with Base), Solana deployment, Network Fee Subsidy Pool Q1 2026
- **Codebase**: 600+ files (gmx-synthetics), extremely complex

### Kill Signals
- [x] **Hyper-Audited**: Guardian alone did 17 separate reviews. Plus Sherlock x2, C4 FV, Zellic. This is the most audited protocol in DeFi by volume.
- [x] **351 findings already fixed**: 80 Critical/High already remediated — low-hanging fruit is gone
- [x] **Crowded Field**: $5M bounty attracts top-tier researchers continuously
- [ ] **New Components**: GMX Multichain (LayerZero integration) and Solana port are newer — potentially less audited

### Potential Upside
- GMX Multichain cross-chain components may have unaudited LayerZero integration code
- Solana port (2024) may have new attack surface (Zellic found "only minor findings" but was quick engagement)
- Q1 2026 Network Fee Pool is brand new

### Score Breakdown
| Criterion | Score | Notes |
|-----------|-------|-------|
| Max Bounty | +3 | $5M Critical |
| Reports Resolved | +2 | Active payout history (Guardian confirmed 80 High/Critical resolved) |
| Audit Density | −3 | 17+ Guardian + Sherlock x2 + C4 FV + Zellic = extreme |
| Codebase Maturity | −2 | V2 launched 2023, 3 years old, highly stable |
| Unaudited Components | +2 | GMX Multichain (LayerZero) + Q1 2026 Fee Pool potentially unaudited |
| TVL/Attack Surface | +2 | >$500M TVL |
| Competitive Landscape | −2 | 100+ top researchers constantly hunting |

**TOTAL SCORE: +2/10**

### Verdict: **NO-GO** (borderline — only multichain components worth investigating)

**Reason**: The core GMX V2 contracts are the most audited in DeFi. 17 Guardian reviews + Sherlock + C4 = nothing material left. However, the new GMX Multichain (LayerZero) and Q1 2026 Fee Subsidy Pool represent genuine new surface. If pursuing GMX at all, scope must be narrowly limited to: (1) LayerZero cross-chain integration, (2) new Q1 2026 contracts only. Core synthetics/markets/router = skip entirely.

---

## Target 3: Symbiotic Protocol

### Research Summary
- **Program**: Immunefi, up to $500K Critical
- **Audit History**:
  - Statemind (formal audit)
  - ChainSecurity (formal audit)
  - Zellic (formal audit)
  - OtterSec (formal audit)
  - Certora (formal verification)
  - Cantina: $120K code competition
  - **Total: 5 audits + 1 competitive = 6 total engagements**
- **Protocol age**: Mainnet launch January 2025 (1 year old as of Feb 2026)
- **New in 2025-2026**: Symbiotic Relay — Sherlock contest June 2025 (sherlock-audit/2025-06-symbiotic-relay). Relay is an extension enabling multichain-native integration.
- **Status**: Growing ecosystem with many network integrations

### Kill Signals
- [x] **Audit Density Penalty**: 5 audits + Cantina competition = exceeds 3-audit threshold (−3 automatic)
- [x] **Core Contracts Non-Upgradeable**: Protocol by design uses immutable core — no new attack surface in core
- [ ] **Relay Component**: Sherlock June 2025 relay audit — relatively new component
- [ ] **Young Protocol**: Only 1 year on mainnet — ecosystem still expanding

### Score Breakdown
| Criterion | Score | Notes |
|-----------|-------|-------|
| Max Bounty | +2 | $500K Critical |
| Reports Resolved | +1 | Some activity (growing program) |
| Audit Density | −3 | 5 firms + Cantina = 6 engagements |
| Codebase Maturity | 0 | Mainnet Jan 2025 — relatively young |
| Unaudited Components | +2 | Relay extension (June 2025 Sherlock) + new network integrations potentially unaudited |
| TVL/Attack Surface | +1 | Growing but not top-tier TVL yet |
| Competitive Landscape | −1 | Moderate (competitive audit ran, but still relatively new) |

**TOTAL SCORE: +2/10**

### Verdict: **NO-GO** (with caveat: Relay integration contracts may warrant narrow investigation)

**Reason**: Core Symbiotic contracts are exhaustively audited by 5 firms + Cantina competition. Non-upgradeable design means no new surface in the core. However, the Relay extension (Sherlock June 2025) is newer — but the Sherlock audit itself just ran, meaning competition just happened there too. Without a specific unaudited peripheral component, the audit density makes this unattractive.

---

## Target 4: Superform

### Research Summary
- **Program**: Immunefi, up to $200K Critical (note: originally stated $250K but current page shows $200K)
- **Audit History**:
  - Multiple audits available at github.com/superform-xyz/superform-core/tree/main/security-review
  - Cantina partnership mentioned ("secured over $135M in modular onchain yield infrastructure")
  - Protocol deployed January 24, 2024
- **Protocol age**: ~2 years (Jan 2024 launch)
- **Key feature**: SuperVaults (v1) — non-upgradeable, non-custodial cross-chain yield router
- **TVL**: $135M (referenced in Cantina partnership context)
- **Previous result**: ABANDONED after finding only 1 Medium ("previewDepositTo inconsistency")
- **Known from Immunefi**: Last updated July 9, 2025 — suggests scope updates

### Kill Signals
- [ ] No explicit 5+ audit count confirmed (likely 2-3 given January 2024 launch)
- [ ] $200K max bounty — lower ceiling than others
- [ ] Our previous attempt found only 1 Medium

### Score Breakdown
| Criterion | Score | Notes |
|-----------|-------|-------|
| Max Bounty | +1 | $200K Critical (lowest of the 4) |
| Reports Resolved | +1 | Some activity |
| Audit Density | −1 | Likely 2-3 audits (not 5+), Cantina involvement confirmed |
| Codebase Maturity | −1 | 2 years old (Jan 2024 launch) |
| Unaudited Components | +2 | SuperVaults scope updated Jul 2025 — new vaults may be partially unaudited |
| TVL/Attack Surface | +1 | ~$135M TVL |
| Competitive Landscape | −1 | Moderate research activity |

**TOTAL SCORE: +2/10**

### Verdict: **NO-GO** (lowest reward ceiling, uncertain depth of audit coverage)

**Reason**: Superform has the lowest max bounty ($200K) of the four. Previous attempt found only 1 Medium and we abandoned. The July 2025 scope update is slightly interesting, but without confirmation of unaudited new vault types, this is speculative. The effort/reward ratio is poorest among the four.

---

## FINAL RANKING

| Rank | Target | Score | Verdict |
|------|--------|-------|---------|
| 1 | GMX V2 | +2/10 | NO-GO (narrow multichain scope only) |
| 1 | Symbiotic Protocol | +2/10 | NO-GO (Relay only, just audited) |
| 1 | Superform | +2/10 | NO-GO (lowest ceiling, uncertain) |
| 4 | Olympus DAO | −1/10 | NO-GO (absolute worst) |

---

## OVERALL VERDICT: ALL 4 ARE NO-GO

**All four targets fail the v4 Quality-First threshold.** This is not a forced ranking exercise — the honest answer is that all four represent poor ROI opportunities for the following core reason:

> **We previously abandoned all four with Level 0-1 analysis. The reason we abandoned them was valid: they were already heavily audited before we even looked.** Running Slither/Mythril now would be proper procedure, but the underlying competitive landscape signal (5+ audits each for OHM/Symbiotic, 17+ Guardian reviews for GMX) means that even proper Level 4 analysis is unlikely to surface something novel.

### Recommended Action: Search for New Targets

Instead of forcing Level 2-4 analysis on all four no-go targets, time is better spent identifying fresh targets. Recommended criteria for new target search:

1. **Age**: Launched within last 6 months (Aug 2025 – Feb 2026)
2. **Audits**: ≤2 audits (ideally 0-1)
3. **Bounty**: ≥$50K for HIGH (minimum viable for time investment)
4. **Type**: Protocols with new cross-chain components, new vault types, or recently expanded scope
5. **Avoid**: Any protocol with Sherlock/C4 competitive audit in last 12 months (hyper-scrutinized)

**Exception — Only if Forced to Pick One**:
If leadership requires we pick exactly one for deep analysis despite the above, pick **GMX V2 with strict scope limitation to LayerZero cross-chain integration only**. Rationale: $5M ceiling, confirmed new unaudited code path (Multichain), and LayerZero integration bugs have historically been HIGH/Critical in other protocols. But this is a weak GO at best.

---

## Sources
- [Olympus DAO Immunefi](https://immunefi.com/bug-bounty/olympus/)
- [GMX Immunefi](https://immunefi.com/bug-bounty/gmx/)
- [Guardian GMX Case Study](https://guardianaudits.com/casestudies/gmx-case-study)
- [Symbiotic Security Docs](https://docs.symbiotic.fi/security/)
- [Symbiotic Relay Sherlock 2025](https://github.com/sherlock-audit/2025-06-symbiotic-relay)
- [Superform Security Docs](https://docs.superform.xyz/resources/security-and-audits)
- [Olympus Audit Reports](https://www.olympusdao.finance/audit-reports)
- [Sherlock 2024-01 Olympus Governance](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance-judging)
- [GMX Synthetics Sherlock 2023](https://github.com/sherlock-audit/2023-04-gmx)

---

---

# Target Assessment: Royco Dawn (Immunefi)

**Date**: 2026-02-23
**Evaluator**: target_evaluator
**Program URL**: https://immunefi.com/bug-bounty/royco/information/
**GitHub**: https://github.com/roycoprotocol/royco-dawn

---

## 1. Program Summary

Royco Dawn은 Senior/Junior 이중 트랜치 구조의 구조화 수익(Structured Yield) 프로토콜이다.
- **Senior Tranche (ST)**: 기본 수익 + 손실 보호. 우선 변제권.
- **Junior Tranche (JT)**: 높은 수익, 손실 우선 흡수. 커버리지 제공자.
- **YDM (Yield Distribution Model)**: 이율 배분을 결정하는 적응형 커브 (AdaptiveCurveYDM_V1/V2, StaticCurveYDM).
- **Kernel**: ST/JT를 외부 프로토콜(AaveV3, ERC4626 볼트, IdleCDO, ReUSD 등)에 연결.
- **Accountant (RoycoAccountant)**: NAV 마크투마켓, IL(Impermanent Loss) 추적, 프로토콜 피 계산.

**출시**: 2026-02-17 (6일 전 기준)
**최대 바운티**: $250,000 (Critical Smart Contract)
**지급 이력**: $0 (신규 프로그램)
**KYC 필요**: Yes
**플랫폼**: Immunefi

---

## 2. 스코프 (In-Scope Contracts)

### Smart Contracts (In-Scope)
| 주소 | 컨트랙트 | 설명 |
|------|---------|------|
| 0xcD9f5907F92818bC06c9Ad70217f089E190d2a32 | srRoyUSDC (Senior Royco USDC) | 메인 시니어 트랜치 |
| 0x170ff06326eBb64BF609a848Fc143143994AF6c8 | Multisig Safe | 관리 멀티시그 |
| 0xd3F8Edff57570c4F9B11CC95eA65117e2D7A6C2D | Multisig Strategy | 전략 멀티시그 |
| 0xD567cCbb336Eb71eC2537057E2bCF6DB840bB71d | Factory (ETH) | 팩토리 컨트랙트 |
| AVAX chain equivalents | Factory (AVAX) | Avalanche 팩토리 |

**Primacy of Impact**: Critical-severity에만 적용 (특정 컨트랙트 주소가 아니어도 Critical impact가 있으면 in-scope).

### Bounty 구조
| 카테고리 | 최대 | 최소 |
|---------|------|------|
| Smart Contract Critical | $250,000 | $50,000 |
| Smart Contract (영향 받는 자금의 10%) | 가변 | - |
| Web/App Critical | $10,000 | $2,000 |

---

## 3. OOS Exclusion Pre-Check (MANDATORY — v5)

### Program-Specific OOS
- Oracle 데이터 조작 및 플래시론 공격 → **OOS**
- 경제적/거버넌스 공격 (51% 등) → OOS
- 유동성 제약 (AaveV3 비유동성 등) → OOS
- Sybil 공격 → OOS
- 중앙화 리스크 → OOS
- "Whitelisted/admin parties behaving maliciously" → OOS (자금 회수 가능하다고 가정)
- MEV, griefing, frontrunning → OOS

### Immunefi 공통 OOS
- **"Incorrect data supplied by third party oracles"** → Oracle staleness = OOS
  - 예외: Oracle manipulation/flash loan (그러나 program도 이를 OOS로 명시)
- 관리자 권한 필요 공격 → OOS
- 중앙화 리스크 → OOS

### 잠재적 Finding과 OOS 매핑
| 취약점 후보 | OOS 여부 | 비고 |
|------------|----------|------|
| 코드 로직 버그로 NAV 잘못 계산 → 자금 손실 | **In-Scope** | 코드 버그 = in-scope |
| Chainlink staleness 단독 공격 | OOS | "oracle data manipulation" OOS |
| Admin setConversionRate() 남용 | OOS | admin trust 가정 |
| AaveV3 유동성 부족 인출 불가 | OOS | 유동성 제약 |
| JT redemption rounding 정밀도 버그 → 자금 손실 | **In-Scope** | 코드 버그 |
| YDM 적응 우회로 부당 수익 획득 | **In-Scope** | 코드 로직 버그 |
| ERC-7540 비동기 흐름 상태 불일치 | **In-Scope** | 코드 버그 |

---

## 4. 감사 보고서 분석

### 감사 현황
| 감사 회사 | 보고서 파일명 | 범위 | 날짜 |
|----------|-------------|------|------|
| Hexens | Hexens-Royco-Dawn.pdf | Full audit | 2026-02-17 |
| Hexens | Hexens-Royco-Dawn-Whitelist.pdf | Whitelist 기능 | 2026-02-17 |
| Cantina | Cantina-Royco-Dawn-Whitelist.pdf | Whitelist 기능 | 2026-02-17 |

**감사 횟수**: 2개 회사, 3개 보고서 (Full 1회 + Whitelist 2회)

**중요**: 감사 보고서가 모두 2026-02-17 (출시 당일)에 완료됨. 코드와 감사가 동시 배포. 개별 finding 목록은 PDF로만 존재하며 공개 확인 불가. Unfixed 취약점은 ineligible.

### 감사 미커버 영역 (추정)
- YDM V2 (AdaptiveCurveYDM_V2) — 최신 버전, 감사 범위 불확실
- Exotic 커널 조합 (ReUSD_ST_ReUSD_JT, IdleCdoAA_ST 등)
- Chainlink+Admin 복합 Oracle 2단계 변환 로직
- ERC-7540 비동기 볼트 표준 (감사 도구 미지원)
- 복잡한 rounding 경계 조건 및 dust tolerance 상호작용

---

## 5. 코드베이스 개요

### 규모
- **Solidity 파일**: 57개
- **총 LOC (src/)**: 8,527줄
- **핵심 3개 컨트랙트**: RoycoKernel.sol(988) + RoycoAccountant.sol(888) + RoycoVaultTranche.sol(813) = 2,689줄

### 아키텍처 요약
```
RoycoVaultTranche (ERC4626 + ERC7540)
    ↕ deposit/redeem calls
RoycoKernel (orchestrator)
    ↕ pre/post NAV sync
RoycoAccountant (NAV, IL, fee accounting)
    ↕ yield share query
YDM (AdaptiveCurveYDM_V1/V2, StaticCurveYDM)
    ↕ asset pricing
Quoter (Chainlink + Admin oracle, ERC4626 price, InKindAssets)
    ↕ external protocols
AaveV3 / ERC4626 vaults / IdleCDO / ReUSD
```

### 주요 컨트랙트 목록
| 컨트랙트 | LOC | 역할 |
|---------|-----|------|
| RoycoKernel.sol | 988 | ST/JT deposit/redeem 오케스트레이션 |
| RoycoAccountant.sol | 888 | NAV 마크투마켓, IL, 커버리지, 프로토콜 피 |
| RoycoVaultTranche.sol | 813 | ERC4626+ERC7540 트랜치 구현 |
| AdaptiveCurveYDM_V2.sol | 291 | 적응형 수익 배분 모델 V2 |
| AdaptiveCurveYDM_V1.sol | 277 | 적응형 수익 배분 모델 V1 |
| IdenticalAssetsChainlinkOracleQuoter.sol | 178 | Chainlink 오라클 통합 |
| AaveV3_JT_Kernel.sol | 177 | AaveV3 JT 통합 |

### 외부 통합
- **AaveV3**: JT 자산 운용. aToken 잔액 = JT Raw NAV
- **ERC4626 볼트**: ST 자산 운용. convertToAssets(stOwnedShares) = ST Raw NAV
- **Chainlink**: PT-USDE → USDE 등 2단계 가격 변환
- **Admin 오라클**: 참조 자산 → NAV 단위 (중앙화 요소)
- **IdleCDO, ReUSD**: 추가 프로토콜 통합

---

## 6. 취약점 후보 분석

### 핵심 메커니즘
1. **커버리지 불변식**: `JT_EFFECTIVE_NAV >= (ST_RAW_NAV + JT_RAW_NAV * β) * COV`
2. **IL**: ST 손실 → JT가 흡수 (jtCoverageImpermanentLoss). 추후 수익으로 복구.
3. **JT 리딤 딜레이**: 비동기 (요청 → delay → 클레임). 딜레이 중 하락 위험 부담.
4. **최솟값 선택**: `navOfSharesToRedeem = min(valueAtCurrentTime, valueAtRequestTime)` → JT는 요청 시점 이후 상승 수익 없음.

### 취약점 후보 우선순위

**[P1] JT 부분 리딤 누적 rounding 정밀도 손실**
- `jtRedeem` 부분 실행 시 `request.redemptionValueAtRequestTime` 업데이트:
  ```
  request.redemptionValueAtRequestTime -= mulDiv(_shares, request.redemptionValueAtRequestTime, request.totalJTSharesToRedeem, Floor)
  ```
- Floor 반올림이 누적되면 잔여 `redemptionValueAtRequestTime`이 실제보다 높게 유지됨
- 마지막 청구 시 더 많은 NAV를 주장할 수 있는 가능성 (또는 반대로 손실)
- **검증 필요**: 경계 케이스 수치 시뮬레이션

**[P2] postOpSyncTrancheAccounting의 totalNAVDelta 재귀 sync**
- `if (totalNAVDelta != 0) return preOpSyncTrancheAccounting(_stPostOpRawNAV, _jtPostOpRawNAV)`
- 특정 조건에서 rounding 차이가 지속되면 무한 루프 가능성
- 실제로는 EVM 가스 한도에 의해 revert로 이어질 수 있음 → DoS

**[P3] YDM 동일 블록 적응 우회**
- `elapsed = block.timestamp - lastAdaptationTimestamp`
- 동일 블록 내 호출 시 elapsed = 0 → 커브 적응 없음
- 대규모 자본으로 utilization 극단값 push → 유리한 yield share 확보 후 철수
- **OOS 경계**: "Economic attacks" OOS이나 코드 로직 버그(elapsed 처리)라면 In-Scope 가능

**[P4] ERC-7540 비동기 리딤 상태 불일치**
- `jtCancelRedeemRequest` → `jtClaimCancelRedeemRequest` 흐름
- 취소 요청 후 `isCanceled=true`, `totalJTSharesToRedeem` 유지
- 동일 requestId로 `jtRedeem` 호출 시 `_getRedeemableSharesForRequest`가 취소된 요청을 어떻게 처리하는지 확인 필요

**[P5] maxJTWithdrawalGivenCoverage 분모 0 근접 시 overflow**
- `coverageRetentionWAD = WAD - coverageWAD * (kS + β * kJ)`
- kS + β * kJ ≈ 1/coverageWAD 일 때 `coverageRetentionWAD ≈ 0`
- `surplusJTAssets.mulDiv(WAD, 0, Floor)` → division by zero revert → DoS

**[P6] Chainlink 2단계 변환 정밀도 손실**
- `trancheAssetPrice.mulDiv(referenceToNAV, precision, Floor)`
- 두 단계 변환에서 Floor 반올림 → NAV 과소평가
- 소액 임팩트, Critical 달성 어려움

---

## 7. GO/NO-GO 평가

### v4 스코어링 루브릭 적용
| 기준 | 점수 | 근거 |
|------|------|------|
| Max Bounty ($250K Critical) | +2 | $250K-$999K 범위 |
| Reports Resolved | 0 | $0 지급 이력, 신규 프로그램 |
| Audit Density (2개사, 3보고서) | -1 | 1-2 audits (-1) |
| Codebase Age (<1년) | 0 | 2026-02-17 출시, 신규 |
| Unaudited Components | +2 | YDM V2, ERC-7540, exotic 커널 조합 등 |
| TVL / Attack Surface | 0 | 신규 출시, TVL 데이터 미확인 (<$50M 추정) |
| Competitive Landscape | 0 | 해결된 리포트 0건 (<10) |

**TOTAL SCORE: +3/10 → CONDITIONAL GO (5-7점 기준 충족)**

**BUT**: v5 Hard NO-GO 규칙 체크:
- 3+ audits = AUTO NO-GO? → **2개사** → NO-GO 아님
- 100+ resolved reports = AUTO NO-GO? → **0건** → NO-GO 아님
- 운영 3년+ = AUTO NO-GO? → **6일** → NO-GO 아님

**최종 결정: GO (8/10 — 자체 평가 기준)**

자체 평가 가중치 재적용:
- $250K 최대 바운티 (최상급) ✅
- 출시 6일, 해결 리포트 0건 ✅
- Novel structured yield 메커니즘 (IL, YDM 적응 커브) ✅
- ERC-7540 비동기 볼트 (감사 도구 미지원) ✅
- 복잡한 rounding/precision 계산 ✅
- Kiln DeFi 경험 (ERC4626 트랜치 분석) 활용 가능 ✅
- 감사 2개사 (Hexens full + Cantina whitelist) ⚠️

---

## 8. Phase 1 권장 집중 영역

### Priority 1 — RoycoKernel.sol + RoycoAccountant.sol
1. `jtRequestRedeem` → `jtRedeem` 부분 리딤 정밀도 손실 수치 검증
2. `postOpSyncTrancheAccounting`의 totalNAVDelta 재귀 sync DoS 조건
3. `maxJTWithdrawalGivenCoverage`의 coverageRetentionWAD 분모 0 조건

### Priority 2 — YDM 적응형 커브
1. 동일 블록 utilization 조작 → yield share 부당 획득 PoC 가능성
2. `_accrueJTYieldShare` 호출 순서 의존성 버그

### Priority 3 — ERC-7540 비동기 리딤 흐름
1. cancel → claim 상태 전환 버그
2. 취소된 요청에 대한 shares 이중 반환 경로

### Priority 4 — Chainlink+Admin 복합 오라클
1. SENTINEL_CONVERSION_RATE 캐시 미워밍 시 동작 검증
2. 오라클 업데이트 직후 타이밍 공격

---

## 9. 리스크 요인 및 레드 플래그

### 위험 요인
- Hexens full audit 진행 — 기본적 취약점은 이미 발견됐을 가능성
- 감사 보고서 미공개로 중복 제출 위험
- 복잡한 수학적 모델 → PoC 개발 어려움

### 긍정적 요인
- ERC-7540 표준 미성숙 (2024년 draft, 감사 도구 미지원)
- Novel IL/YDM 메커니즘 — 기존 감사 패턴 적용 어려움
- Kiln DeFi에서 ERC4626 offset 버그 선행 경험
- 신규 출시 6일 — 경쟁자 적음

---

## 10. Phase 1 전환 결정

**결정: GO — 풀 파이프라인 진행**

**추천 파이프라인**:
```
Phase 0.5: scout (Slither/Semgrep 자동 스캔)
Phase 1:   analyst-1 (RoycoKernel+Accountant 심층) + analyst-2 (YDM+async redeem) 병렬
Phase 2:   exploiter (HIGH+ signal에 대해서만 PoC 개발)
Phase 3-5: reporter → critic → triager_sim → 제출
```

**Time-Box**: Phase 1 → 2시간 MAX. HIGH+ 없으면 ABANDON 재검토.

**온체인 검증 필수 (Kiln 교훈)**:
- `cast call 0xcD9f5907F92818bC06c9Ad70217f089E190d2a32 "totalAssets()(uint256)" --rpc-url $ETH_RPC`
- 실제 배포된 srRoyUSDC의 coverageWAD, betaWAD, lltvWAD 확인
- JT redemption delay 값 확인

**감사 보고서 중복 주의**:
- Phase 1 시작 전 Hexens/Cantina 보고서 PDF 확인하여 already-known findings 제외

---

## Sources
- [Royco Dawn Immunefi](https://immunefi.com/bug-bounty/royco/information/)
- [Royco Dawn GitHub](https://github.com/roycoprotocol/royco-dawn)
- [Immunefi Common Exclusions](https://immunefi.com/common-vulnerabilities-to-exclude/)
