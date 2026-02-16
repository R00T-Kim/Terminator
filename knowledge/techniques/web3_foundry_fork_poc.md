# Web3: Foundry Fork PoC Methodology

> Derived from stake.link sandwich attack analysis (2026-02-17)

## Core Principle: Foundry Fork > Python Simulation

**Python 시뮬레이션은 AMM 취약점에서 신뢰할 수 없다.** stake.link에서 Python으로 7+시나리오를 테스트했을 때 모두 LOSS를 보여줬지만, 동일한 공격을 Foundry mainnet fork로 테스트했을 때 모두 PROFIT이었다.

이유:
- Python은 AMM invariant를 근사치로 계산 (StableSwap D 계산 정밀도 차이)
- Curve NG의 fee 단위 (1e10 denominator)를 잘못 해석할 수 있음
- `get_dy()` / `exchange()` 내부 반올림이 Python 재구현과 다름
- 실제 on-chain state (잔고, A, fee)를 100% 정확히 가져오지 못할 수 있음

## Foundry Fork PoC 표준 패턴

### 1. 프로젝트 구조
```
poc/foundry-test/
├── foundry.toml          # via_ir=true, optimizer=true
├── test/
│   └── Attack.t.sol      # 모든 테스트
└── lib/forge-std/        # forge install
```

### 2. foundry.toml 설정
```toml
[profile.default]
src = "test"
out = "out"
libs = ["lib"]
via_ir = true
optimizer = true
optimizer_runs = 200
```

### 3. 테스트 구조 (4-test 패턴)
```solidity
contract AttackTest is Test {
    // test_01_baseline: 공격 없는 기준선
    // test_02_dirB_various: Direction B (대조군, 손실 증명)
    // test_03_dirA_various: Direction A (공격군, 수익 증명)
    // test_04_full_evidence: 완전한 증거 (잔고 before/after, 블록, bps)
}
```

### 4. Full Evidence 테스트 필수 요소
```solidity
function _full_evidence(uint256 reward, uint256 attackSize) internal {
    uint256 snap = vm.snapshot();

    // PHASE A: Baseline (공격 없음)
    // deal → add_liquidity → LP 기록 → revertTo(snap)

    // PHASE B: Attack
    uint256 snap2 = vm.snapshot();
    // deal 양쪽
    // 잔고 BEFORE 로그
    // Step 1: Front-run (블록 번호 로그)
    // Step 2: Victim tx (블록 번호 로그)
    // Step 3: Back-run (블록 번호 로그)
    // 잔고 AFTER 로그
    // NET PROFIT 계산
    // BASELINE vs ATTACKED LP 비교 (bps 손실)

    assert(atkAfter > atkBefore);      // 수익 증명
    assert(otherTokenAfter == 0);       // 단일 자산 정산

    vm.revertTo(snap2);
}
```

### 5. Direction Enumeration (AMM 필수)
- **Direction A**: token0 매도 → token1 매수 → victim → token1 매도 → token0 매수
- **Direction B**: token1 매도 → token0 매수 → victim → token0 매도 → token1 매수
- 풀 불균형 비율이 수익 방향을 결정
- **절대 한 방향만 테스트하지 말 것** — 반대 방향의 손실도 대조군으로 보여줘야 함

## On-Chain Feasibility Check (PoC 전 필수)

```bash
# 1. 토큰 총 공급량 & 분포
cast call <token> "totalSupply()(uint256)" --rpc-url <rpc>
cast call <token> "balanceOf(address)(uint256)" <pool> --rpc-url <rpc>
# locked_ratio = pool_balance / total_supply
# > 95% locked → 공격 자본 확보 극히 어려움

# 2. Flash loan 가능 여부
# Aave V3, Balancer Vault, dYdX 등 체크
# 토큰이 어느 대출 프로토콜에도 없으면 → flash loan 불가

# 3. 외부 DEX 유동성
# Uniswap/SushiSwap/Curve에서 해당 토큰 페어 체크
# 외부 유동성 = 0이면 → sandwich/arbitrage 자본 조달 불가
```

**stake.link 교훈**: PoC가 profit-positive여도 wstPOL 98.7% locked + flash loan 0 = Medium ceiling. 이 체크를 PoC 작성 **전에** 했으면 ~50K 토큰 절약 가능.

## Curve-Specific 참고사항

| 파라미터 | 의미 | stake.link 값 |
|----------|------|--------------|
| A | Amplification coefficient | 500 (높을수록 peg 근처 유동성 집중) |
| fee() | 1e10 denominator | 1000000 = 0.01% |
| balances(i) | 풀 내 토큰 i 잔고 | token0: 41K, token1: 69.7K |
| exchange(i,j,dx,min_dy) | i→j 스왑 | int128 인덱스 주의 |
| add_liquidity(amounts, min_mint) | LP 추가 | min_mint=0 = 슬리피지 보호 없음 |

## RPC 관리
- polygon-rpc.com: rate limit 빠름, 대량 테스트 부적합
- polygon-bor-rpc.publicnode.com: 더 안정적
- `--fork-retries 15 --fork-retry-backoff 25000` 추가 권장
- 특정 블록 고정: `--fork-block-number <block>` (재현성)

## Immunefi 보고서 작성 팁
- **Honest disclosure 섹션 필수**: 유동성 제약, deal() 사용 사실 명시
- **"Growing risk" 프레이밍**: "fix now while cheap" — 프로토콜 성장 시 공격 비용 0 수렴
- **State-dependent 언어**: "under observed pool conditions" (매번 가능한 것처럼 쓰지 말 것)
- **관찰적 CCIP 언어**: "appear in public mempool" (단정적 "no MEV protection" 지양)
- **극단 시나리오는 부록으로**: 47% LP 손실 같은 극단 케이스는 메인 테이블보다 보조 증거
- **assert() 2개가 리포트의 핵심**: `profit > 0` + `net zero other token`
