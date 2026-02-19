# Moonwell $1.78M Hack — AI "Vibe Coding" Oracle Bug (2026-02-15)

## IRON RULE: AI가 생성한 Smart Contract 코드는 절대 무검증 배포 금지

## 사건 요약
- **프로토콜**: Moonwell (DeFi lending, Base + Optimism)
- **손실**: $1,779,044.83 (bad debt)
- **날짜**: 2026-02-15 18:01 UTC (MIP-X43 실행 직후)
- **탐지**: 4분 후 (18:05 UTC) 모니터링 시스템 알림
- **대응**: supply/borrow cap을 0.01로 긴급 축소
- **원인**: Claude Opus 4.6가 co-authored한 oracle formula 오류

## 기술적 세부사항

### Oracle Formula 오류
```
❌ 잘못된 구현: price = cbETH/ETH exchange rate (≈1.12)
✅ 올바른 구현: price = (cbETH/ETH exchange rate) × (ETH/USD price) (≈$2,200)
```

ETH/USD 곱셈을 누락하여 cbETH가 $2,200 대신 $1.12로 가격 책정됨.
**99.95% 가격 오류.**

### 공격 메커니즘
1. MIP-X43이 Chainlink OEV wrapper contracts를 Base + Optimism에 활성화
2. 새 oracle config에서 cbETH 가격이 $1.12로 설정됨
3. Liquidator가 ~$1 상당을 갚고 1,096.317 cbETH (≈$2.4M 시가) 청산
4. 총 bad debt: $1,779,044.83
   - cbETH: $1,033,393.71
   - WETH: $478,998.02
   - 기타: ~$267K

### AI 역할
- Pashov (보안 감사인): "Claude Opus 4.6 wrote vulnerable code, leading to a smart contract exploit with $1.78M loss"
- GitHub PR commit history에 "Co-Authored-By: Claude" 기록
- **"Vibe coding"의 첫 번째 대형 DeFi 해킹 사례**로 기록됨

## 핵심 교훈

### 1. AI 생성 코드의 Oracle/가격 로직 = 최고 위험 등급
- Oracle은 DeFi의 "단일 실패 지점" — 1줄 오류 = 수백만 달러 손실
- AI는 "그럴듯한" 코드를 생성하지만 **수학적 정확성을 보장하지 않음**
- 특히 다중 피드 조합 (cbETH/ETH × ETH/USD) 같은 **compound 가격 계산**에서 취약

### 2. Vibe Coding ≠ Production Code
- AI가 생성한 코드를 "잘 돌아가니까 OK" 하고 배포하는 것은 자살 행위
- **모든 AI 생성 스마트컨트랙트 코드는 반드시**:
  - 수동 수학 검증 (특히 oracle, 가격, 스케일링)
  - Foundry fork test로 온체인 실제 가격과 비교
  - 최소 1명의 인간 감사인 리뷰
  - 정적 분석 (Slither/Mythril) 통과

### 3. 우리 파이프라인에 적용
- **Terminator가 생성한 코드도 동일한 위험** — 우리도 AI agent
- exploit/PoC 코드: 로컬 테스트 + 원격 검증 (이미 규칙 있음)
- **보고서의 수학적 주장**: 반드시 Foundry/cast로 독립 검증
- **Oracle 관련 finding**: price feed formula를 수동으로 단계별 검증

### 4. Bug Bounty 관점 — 새로운 공격 표면
- "Vibe coded" 프로토콜 = 감사 품질 낮을 가능성 높음
- GitHub commit에 "Co-Authored-By: Claude/GPT" 있으면 = 취약점 확률 상승
- Oracle/가격 로직이 AI 생성인지 확인하는 것이 새로운 정찰 기법

## 참고 자료
- [Moonwell Governance Forum — MIP-X43 Incident Summary](https://forum.moonwell.fi/t/mip-x43-cbeth-oracle-incident-summary/2068)
- [Crypto.news — Moonwell AI-coded oracle glitch](https://crypto.news/moonwells-ai-coded-oracle-glitch-misprices-cbeth-at-1-drains-1-78m/)
- [CryptoTimes — Moonwell Loses $1.78M](https://www.cryptotimes.io/2026/02/18/moonwell-loses-1-78m-following-claude-opus-4-6-code-bug/)
- [ForkLog — Vibe Coding via Claude Opus](https://forklog.com/en/vibe-coding-via-claude-opus-leads-to-moonwell-defi-project-breach/)
- [Decrypt — Oracle Error Leaves Moonwell With $1.8M Bad Debt](https://decrypt.co/358374/oracle-error-leaves-defi-lender-moonwell-1-8-million-bad-debt)
- Pashov tweet: https://x.com/pashov/status/2023872510077616223
