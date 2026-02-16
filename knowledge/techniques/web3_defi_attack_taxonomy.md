# Web3/DeFi Attack Taxonomy (2024-2026)

**Last Updated**: 2026-02-16
**Research Status**: Comprehensive analysis based on real-world incidents, academic research, and industry reports

## Table of Contents

1. [Major DeFi Hacks Timeline (2024-2026)](#major-defi-hacks-timeline-2024-2026)
2. [Flash Loan Attacks](#flash-loan-attacks)
3. [Oracle Manipulation](#oracle-manipulation)
4. [Reentrancy Variants](#reentrancy-variants)
5. [ERC4626 Vault Attacks](#erc4626-vault-attacks)
6. [Access Control Vulnerabilities](#access-control-vulnerabilities)
7. [Logic Bugs](#logic-bugs)
8. [Token Standard Issues](#token-standard-issues)
9. [Cross-Chain/Bridge Attacks](#cross-chainbridge-attacks)
10. [MEV/Frontrunning](#mevfrontrunning)
11. [Precision/Rounding Errors](#precisionrounding-errors)
12. [Governance Attacks](#governance-attacks)
13. [Upgrade Attacks](#upgrade-attacks)
14. [Solidity 0.8.x Specific Pitfalls](#solidity-08x-specific-pitfalls)

---

## Major DeFi Hacks Timeline (2024-2026)

### 2024 Overview

Total stolen in 2024: **~$2.2 billion** (21% increase vs 2023)
Primary cause: **Faulty input verification/validation**

### 2025 Major Incidents

Total stolen in 2025: **$3.4+ billion** (new record, 37% increase vs 2024)
Over half linked to North Korea

| Date | Protocol | Amount | Root Cause | Attack Vector |
|------|----------|--------|------------|---------------|
| **Feb 2025** | **Bybit Exchange** | **$1.4B** | Compromised developer laptop | Supply chain attack, malicious Safe wallet transaction |
| **Jan 2025** | Phemex | $73M | Private key compromise | Hot wallet drain across 16 blockchains |
| **Apr 2025** | UPCX | $70M | Off-chain infrastructure | Private key compromise |
| **May 2025** | Cetus Protocol (Sui DEX) | $223M | Spoofed token + protocol logic flaw | Token impersonation attack, ~$162M recovered |
| **Jun 2025** | Nobitex (Iran) | $90M | Politically-motivated attack | Gonjeshke Darande hacking group |
| **Jul 2025** | GMX | $42M | Unknown | USDC freeze failure by Circle |
| **Sep 2025** | SwissBorg | $41.5M | Compromised staking partner (Kiln) | Supply chain attack, malicious unstaking transaction |
| **Sep 2025** | Bunni (Uniswap v4 DEX) | $8M | Rounding error in smart contracts | Mathematical precision vulnerability |
| **Nov 2025** | Balancer | $128M | Rounding-error bug in pool math | Multi-chain exploit |

**Key Trends**:
- **Off-chain attacks dominate top hacks**: Private key compromise, supply chain attacks
- **Cross-chain bridges** funnel 50.1% of stolen funds ($1.5B+)
- **Hooks predicted to drive new wave** of exploits through 2025-2026

**Sources**:
- [The Top 100 DeFi Hacks Report 2025](https://www.halborn.com/reports/top-100-defi-hacks-2025)
- [Crypto hacks hit $3.4 billion in 2025 - Chainalysis](https://www.theblock.co/post/382477/crypto-hack-2025-chainalysis)
- [From Bybit to GMX: The 10 biggest crypto hacks of 2025](https://www.theblock.co/post/380992/biggest-crypto-hacks-2025)
- [Year in Review: The Biggest DeFi Hacks of 2025](https://www.halborn.com/blog/post/year-in-review-the-biggest-defi-hacks-of-2025)

---

## Flash Loan Attacks

### Description
Uncollateralized loans borrowed and repaid within a single transaction, used to manipulate protocol state or prices.

### Prerequisites
- Protocol relies on spot price or manipulable state
- Liquidity available for flash loans (Aave, dYdX, Uniswap v2/v3)
- Single-transaction atomicity guarantee

### Attack Mechanisms

#### 1. Price Manipulation
```solidity
// Vulnerable pattern: Using spot price from AMM
uint256 price = (reserve0 * 1e18) / reserve1;  // ❌ Manipulable

// Attack flow:
1. Flash loan large amount of tokenA
2. Swap tokenA → tokenB in AMM pool (distorts price)
3. Exploit protocol using inflated/deflated price
4. Reverse swap
5. Repay flash loan + fee
```

#### 2. Collateral Manipulation
Temporarily inflate collateral value to borrow maximum, then deflate before liquidation.

#### 3. Governance Takeover
Borrow governance tokens to pass malicious proposals (see [Governance Attacks](#governance-attacks)).

### Typical Impact
- **Critical**: Protocol drainage, governance takeover
- **Historical losses**: $954K (bZx 2020), $197M (Euler Finance 2023)

### Detection Method
```solidity
// ✅ Defense: TWAP oracle instead of spot price
IUniswapV3Pool pool = IUniswapV3Pool(poolAddress);
(int24 arithmeticMeanTick,) = pool.observe(secondsAgos);
uint256 twapPrice = OracleLibrary.getQuoteAtTick(
    arithmeticMeanTick,
    baseAmount,
    baseToken,
    quoteToken
);
```

### Real Example
**Euler Finance (2023)**: Attacker used flash loan to manipulate debt/collateral calculations through donation attack, draining $197M.

**Prevention**:
- Use TWAP oracles (minimum 10-30 minute window)
- Implement reentrancy guards
- Add deposit/withdrawal delays
- Check for balance changes outside expected operations

**Sources**:
- [Flash Loan Attacks: Understanding DeFi Security Risks](https://www.startupdefense.io/cyberattacks/flash-loan-attack)
- [Flash Loan Exploits: A Developer's Guide](https://speedrunethereum.com/guides/flash-loan-exploits)
- [The Full Guide to Price Oracle Manipulation Attacks](https://www.cyfrin.io/blog/price-oracle-manipulation-attacks-with-examples)

---

## Oracle Manipulation

### Description
Attacking or deceiving price oracles to exploit protocols that rely on them for critical decisions (lending, liquidations, minting).

### Attack Vectors

#### 1. Spot Price Manipulation (AMM as Oracle)

**Vulnerable Pattern**:
```solidity
// ❌ DANGEROUS: Using AMM reserves directly
function getPrice() public view returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    return (reserve0 * 1e18) / reserve1;
}
```

**Why it's vulnerable**: Single large swap in low liquidity pool = instant price manipulation.

**Fix**: Use TWAP (Time-Weighted Average Price)

#### 2. TWAP Manipulation (Ethereum PoS)

**New vulnerability since Merge**: Validators control block sequencing, enabling multi-block manipulation.

**Attack mechanics**:
```
Block N (validator controls):   Manipulate price up
Block N+1 (validator controls): Manipulate price down
Block N+2 (validator controls): TWAP now includes fake data point
```

**Cost**: 2-block attack still expensive, but 3+ block attacks are **technically feasible** if validator controls multiple consecutive blocks.

**Mitigation**: Wide-range liquidity. Adding $1M wide-range mint on USDC/WETH 5bps makes 2-block attack cost ~$360B more.

#### 3. Chainlink Stale Prices

**Vulnerability**: Not checking for stale data from Chainlink feeds.

**Chainlink Update Triggers**:
- **Deviation threshold**: Price moves ≥ X% (e.g., 0.5% for ETH/USD)
- **Heartbeat**: Maximum time between updates (e.g., 1 hour for ETH/USD)

**Vulnerable code**:
```solidity
// ❌ No staleness check
(, int256 answer,,,) = priceFeed.latestRoundData();
return uint256(answer);
```

**Secure implementation**:
```solidity
// ✅ Check for stale prices
(uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    = priceFeed.latestRoundData();

require(answeredInRound >= roundId, "Stale price");
require(updatedAt >= block.timestamp - HEARTBEAT_THRESHOLD, "Stale price");
require(answer > 0, "Invalid price");
```

**Real issues**:
- Projects using 3-day staleness threshold when Chainlink heartbeat is 24 hours
- rETH/ETH feed: 24h heartbeat + 2% deviation = price can be outdated by 2% for 24 hours

#### 4. L2 Sequencer Downtime

When L2 sequencer is down, Chainlink prices become stale but appear fresh.

**Fix**: Check sequencer uptime feed
```solidity
// ✅ L2 Sequencer check (Arbitrum, Optimism)
(, int256 answer, uint256 startedAt,,) = sequencerUptimeFeed.latestRoundData();
require(answer == 0, "Sequencer is down");
require(block.timestamp - startedAt > GRACE_PERIOD, "Grace period not over");
```

### Typical Impact
- **Critical**: Unfair liquidations, protocol drainage
- **Historical losses**: $403.2M in 41 oracle attacks (2022)

### Detection Method
- Static analysis: Detect `reserves()` or `getPrice()` calls without TWAP
- Runtime monitoring: Compare oracle price vs market aggregator (>5% deviation = suspicious)

### Real Example
**bZx (Feb 2020)**: Two flash loan attacks exploiting bZx's pricing oracles, $954K total loss.

**Sources**:
- [What are Price Oracle Manipulation Attacks in DeFi?](https://www.halborn.com/blog/post/what-are-price-oracle-manipulation-attacks-in-defi)
- [Uniswap v3 TWAP Oracles in Proof of Stake](https://blog.uniswap.org/uniswap-v3-oracles)
- [Chainlink Oracle Security Considerations](https://medium.com/cyfrin/chainlink-oracle-defi-attacks-93b6cb6541bf)
- [L2 Sequencer and Stale Oracle Prices Bug](https://medium.com/@lopotras/l2-sequencer-and-stale-oracle-prices-bug-54a749417277)

---

## Reentrancy Variants

### 1. Classic Reentrancy

**Pattern**:
```solidity
// ❌ Vulnerable: External call before state update
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}("");  // Reenters here
    require(success);
    balances[msg.sender] -= amount;  // Too late!
}
```

**Fix**: Checks-Effects-Interactions (CEI) pattern + ReentrancyGuard

```solidity
// ✅ Secure: Update state before external call
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // State updated first
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
}
```

### 2. Cross-Function Reentrancy

**Pattern**: Reenter through different function sharing same state.

```solidity
function withdraw() external {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;
    msg.sender.call{value: amount}("");  // Reenter via transfer()
}

function transfer(address to, uint256 amount) external {
    require(balances[msg.sender] >= amount);  // Still vulnerable!
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

**Fix**: Use `nonReentrant` on ALL state-changing functions.

### 3. Cross-Contract Reentrancy

Attack one protocol through callback, then exploit another protocol that relies on the first's state.

### 4. Read-Only Reentrancy (⚠️ Emerging Threat)

**Description**: Reentering a **view function** when state is temporarily inconsistent.

**Critical insight**: View functions are often unguarded because they don't modify state. But if state is inconsistent during external call, wrong values can be read.

**Real-world example: Curve/Balancer (April 2023)**

```solidity
// Curve pool's get_virtual_price() is a view function
function remove_liquidity_one_coin(uint256 amount, int128 i) external {
    // 1. Burn LP tokens (state change)
    _burn(msg.sender, amount);

    // 2. Calculate amount to return
    uint256 dy = _calc_withdraw_one_coin(amount, i);

    // 3. Transfer tokens (EXTERNAL CALL - attacker reenters here!)
    ERC20(coins[i]).transfer(msg.sender, dy);

    // 4. Update reserves
    reserves[i] -= dy;

    // Between step 3 and 4, get_virtual_price() returns INFLATED value!
}
```

**Attack flow**:
1. Call `remove_liquidity_one_coin()`
2. In ERC777/ERC223 receive hook, call another protocol's `getPrice()`
3. That protocol calls Curve's `get_virtual_price()` → returns inflated value
4. Attacker profits from mispriced collateral/debt

**Affected protocols** (disclosed April 2023):
- Curve pools
- Balancer pools
- All integrations: MakerDAO, Enzyme, Abracadabra, TribeDAO, Opyn

**dForce Hack (Feb 2023)**: Read-only reentrancy in Curve pool, $3.7M loss.

**Mitigation**:
```solidity
// ✅ Use reentrancy guard even on view functions
function get_virtual_price() public view nonReentrant returns (uint256) {
    return (total_supply > 0) ? (reserves * PRECISION) / total_supply : PRECISION;
}
```

Or: Use Balancer's query protection
```solidity
// Balancer V2 solution: Prevent queries during state changes
if (inRecoveryMode) {
    _ensureNotInVaultContext(vault);
}
```

**ERC4626 Read-Only Reentrancy**:
ERC4626 vaults are vulnerable if `totalAssets()` or `convertToShares()` are called during reentrant withdrawal.

**Sources**:
- [Curve LP Oracle Manipulation: Post Mortem](https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/)
- [Reentrancy Vulnerability Scope Expanded - Balancer](https://forum.balancer.fi/t/reentrancy-vulnerability-scope-expanded/4345)
- [dForce Attack via Read-Only Reentrancy - CertiK](https://www.certik.com/resources/blog/curve-conundrum-the-dforce-attack-via-a-read-only-reentrancy-vector-exploit)
- [Where to find solidity reentrancy attacks - RareSkills](https://rareskills.io/post/where-to-find-solidity-reentrancy-attacks)

---

## ERC4626 Vault Attacks

### 1. Inflation/Donation Attack (First Depositor Attack)

**Vulnerability**: Empty vault susceptible to share price manipulation.

**Attack flow**:
```solidity
// Attacker: First depositor
vault.deposit(1);  // Receive 1 share (1:1 ratio)

// Attacker: Direct transfer to vault (donation)
asset.transfer(address(vault), 10000e18);
// Now: totalAssets = 10000e18 + 1, totalShares = 1
// Exchange rate: 1 share = 10000e18 assets

// Victim: Deposits 19999e18
// Shares minted: (19999e18 * 1) / 10000e18 = 1.9999 → rounds to 1 share
// Victim gets only 1 share for 19999 tokens!

// Attacker: Redeems 1 share
// Gets: (1 * 30000e18) / 2 = 15000e18
// Profit: 15000e18 - 10000e18 - 1 = 5000e18 (from victim's deposit)
```

**Root cause**: Rounding in `convertToShares()` favors vault when donation inflates exchange rate.

**OpenZeppelin Mitigation (v4.9+)**: Virtual shares and assets

```solidity
function _convertToShares(uint256 assets, Math.Rounding rounding)
    internal view virtual returns (uint256)
{
    return assets.mulDiv(
        totalSupply() + 10 ** _decimalsOffset(),  // Virtual shares
        totalAssets() + 1,                        // Virtual assets
        rounding
    );
}
```

**How it works**:
- `_decimalsOffset()` defaults to 0, but can be overridden
- Default (offset=0): Virtual shares capture donation, making attack unprofitable even for multiple victims
- Larger offset (e.g., 3): Attack becomes orders of magnitude more expensive

**Analysis**: With offset=3, attacker must donate 1000x more to achieve same rounding effect.

**Alternative mitigations**:
1. **Dead shares** (Uniswap V2 style): Mint 1000 shares to 0x0 on first deposit
2. **Internal balance tracking**: Ignore direct transfers
3. **Minimum first deposit**: Require first depositor to mint at least 1e6 shares

### 2. Share Price Manipulation via Yield

**Attack**: Donate yield-generating tokens, manipulate `totalAssets()` calculation.

### 3. Rounding Errors

**Systematic losses**: Small deposits consistently round down to 0 shares.

**Mitigation**: Minimum deposit amount enforced.

### 4. ERC7540 Async Vault Risks

**Standard**: Extension for ERC4626 with asynchronous deposit/redemption (for RWAs, cross-chain, undercollateralized lending).

**Key risks**:
- **Exchange rate uncertainty**: Shares received may not equal `convertToShares(assets)` at request time
- **Pending requests non-yielding**: Redemption requests may not accrue yield
- **Cancellation complexity**: May be synchronous or asynchronous, non-standardized
- **Composability challenges**: Variable request handling (ERC-20, ERC-721, internal accounting)

**Use cases**: Real-world assets (RWAs), undercollateralized lending, cross-chain protocols, liquid staking tokens.

**Sources**:
- [Address EIP-4626 inflation attacks](https://ethereum-magicians.org/t/address-eip-4626-inflation-attacks-with-virtual-shares-and-assets/12677)
- [A Novel Defense Against ERC4626 Inflation Attacks - OpenZeppelin](https://blog.openzeppelin.com/a-novel-defense-against-erc4626-inflation-attacks)
- [ERC-4626 | OpenZeppelin Docs](https://docs.openzeppelin.com/contracts/5.x/erc4626)
- [ERC-7540: Asynchronous ERC-4626 Tokenized Vaults](https://eips.ethereum.org/EIPS/eip-7540)
- [ERC-7540 vs ERC-4626: Async Settlement](https://www.zealynx.io/blogs/erc-7540-asynchronous-settlement)

---

## Access Control Vulnerabilities

### Description
Unauthorized access to privileged functions due to missing, misconfigured, or bypassable access checks.

### Common Patterns

#### 1. Missing Access Modifiers

```solidity
// ❌ CRITICAL: Anyone can drain contract
function withdraw() external {
    payable(owner).transfer(address(this).balance);
}

// ✅ Fixed
function withdraw() external onlyOwner {
    payable(owner).transfer(address(this).balance);
}
```

**Functions commonly left exposed**:
- `withdraw()`, `mint()`, `burn()`, `pause()`, `setFee()`, `setOracle()`, `upgradeTo()`

#### 2. Role Confusion

```solidity
// ❌ Inconsistent role checks
contract Vault {
    address public owner;
    address public admin;

    function setFee(uint256 fee) external {
        require(msg.sender == owner);  // Uses owner
    }

    function withdraw() external {
        require(msg.sender == admin);  // Uses admin - inconsistent!
    }
}
```

#### 3. Uninitialized Proxy

**Vulnerability**: Proxy pattern's `initialize()` function not protected.

```solidity
// ❌ Anyone can initialize and become owner
function initialize(address _owner) external {
    owner = _owner;
}

// ✅ Use OpenZeppelin's initializer modifier
function initialize(address _owner) external initializer {
    owner = _owner;
}
```

**Real-world example**: Audius hack (July 2022) - uninitialized proxy allowed attacker to call `initialize()` and take control.

#### 4. Constructor vs Initializer Confusion

**Issue**: Proxy patterns can't use constructors (only execute in implementation context).

```solidity
// ❌ Constructor logic doesn't run in proxy context
contract Implementation {
    constructor() {
        owner = msg.sender;  // Never executes for proxy users!
    }
}

// ✅ Use initialize function
contract Implementation {
    bool private initialized;

    function initialize() external {
        require(!initialized, "Already initialized");
        initialized = true;
        owner = msg.sender;
    }
}
```

**Historical incident**: Parity multisig (2017) - uninitialized library, $150M frozen.

### Typical Impact
- **Critical**: Complete protocol takeover, fund drainage
- **Ease of exploitation**: Often single function call, cheap to execute

### Detection Method
- Static analysis: Find public/external functions without access modifiers
- Review: Check all functions modifying state or transferring value
- Test: Attempt to call privileged functions from non-privileged account

### Prevention
1. Use OpenZeppelin's `Ownable`, `AccessControl`, or `AccessControlEnumerable`
2. Apply principle of least privilege
3. Use `initializer` modifier for proxy initialization
4. Comprehensive test coverage for access control

**Sources**:
- [Why Access Control Failures Are Still the #1 Attack Vector](https://www.quillaudits.com/blog/web3-security/access-control-flaw-remain-top-crypto-attack-vector)
- [Uninitialized Smart Contract Vulnerability in BadgerDAO](https://www.cyberark.com/resources/threat-research-blog/how-to-write-a-poc-for-an-uninitialized-smart-contract-vulnerability-in-badgerdao-using-foundry)
- [A01 Broken Access Control - OWASP Top 10:2021](https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/)

---

## Logic Bugs

### 1. Off-By-One Errors

```solidity
// ❌ Loop skips last element
for (uint i = 0; i < array.length - 1; i++) {
    process(array[i]);
}

// ❌ Boundary check allows overflow
require(amount <= maxAmount);  // Should be '<'
```

### 2. Incorrect Comparison Operators

```solidity
// ❌ Should be '>=' but used '>'
require(collateral > debt, "Undercollateralized");  // Edge case: collateral == debt fails

// ❌ Integer division rounds down
uint256 fee = (amount * feePercent) / 100;  // 5.5% becomes 5%
```

### 3. Wrong Order of Operations

```solidity
// ❌ Division before multiplication (precision loss)
uint256 result = (a / b) * c;

// ✅ Multiply before divide
uint256 result = (a * c) / b;
```

See [Precision/Rounding Errors](#precisionrounding-errors) for details.

### 4. Unchecked Return Values

**Vulnerability**: Low-level calls (`call`, `delegatecall`, `send`) return `false` on failure instead of reverting.

```solidity
// ❌ Silent failure - contract assumes success
bool sent = payable(receiver).send(amount);
// continues execution even if sent == false!

// ✅ Check return value
(bool success,) = payable(receiver).call{value: amount}("");
require(success, "Transfer failed");

// ✅✅ Best: Use transfer() which auto-reverts
payable(receiver).transfer(amount);
```

**High-level vs low-level calls**:
- **High-level** (`ExternalContract.doSomething()`): Auto-revert on failure
- **Low-level** (`address.call()`, `.delegatecall()`, `.send()`): Return false, never throw

**Impact**: Silent failures → incorrect contract state → loss of funds.

**Real-world**: King of Ether (2016) - used `send()` without checking return value, contract became stuck.

### 5. Integer Overflow/Underflow (Pre-0.8.0)

**Note**: Solidity 0.8.0+ has built-in overflow checks (reverts on overflow).

```solidity
// Solidity < 0.8.0
uint256 a = 2**256 - 1;
a = a + 1;  // ❌ Wraps to 0 without revert

// Solidity >= 0.8.0
uint256 a = 2**256 - 1;
a = a + 1;  // ✅ Reverts with Panic(0x11)

// Bypass checks with unchecked {} (use carefully!)
unchecked {
    a = a + 1;  // Wraps to 0, no revert
}
```

### Typical Impact
- Varies: Logic bugs can range from minor inconsistencies to critical fund loss

### Detection Method
- Manual code review
- Unit tests with edge cases
- Formal verification (e.g., Certora, Halmos)
- Fuzzing (Foundry invariant tests, Echidna)

**Sources**:
- [Understanding Unchecked Return Values in Solidity](https://www.vibraniumaudits.com/post/understanding-unchecked-return-values-in-solidity-low-level-calls)
- [SC06:2025 Unchecked External Calls - OWASP](https://owasp.org/www-project-smart-contract-top-10/2025/en/src/SC06-unchecked-external-calls.html)
- [Security Considerations - Solidity Docs](https://docs.soliditylang.org/en/latest/security-considerations.html)

---

## Token Standard Issues

### 1. ERC777 Hooks

**Vulnerability**: `tokensToSend` and `tokensReceived` hooks enable reentrancy.

```solidity
// ERC777 automatically calls recipient's hook
function tokensReceived(
    address operator,
    address from,
    address to,
    uint256 amount,
    bytes calldata userData,
    bytes calldata operatorData
) external {
    // Attacker can reenter here!
    vulnerableContract.withdraw();
}
```

**Real attack**: imBTC (2020) - $25M+ stolen via ERC777 reentrancy.

**Why ERC777 is dangerous**:
- Calling sender hook **before** updating state violates CEI pattern
- Hooks enable reentrancy and DoS attacks
- Attacker can assign hook to victim contract

**Recommendation**: **DO NOT use ERC777**. Use ERC20 extensions instead:
- **ERC2612** (Permit): Gasless approvals via signatures
- **ERC1363**: Payable token with receiver callbacks (safer design)

### 2. Fee-on-Transfer Tokens

**Tokens**: USDT (on some chains), STA, PAXG, others

**Issue**: `transfer(amount)` deducts fee, recipient receives less than `amount`.

```solidity
// ❌ Assumes full amount arrives
token.transferFrom(user, address(this), 100);
balances[user] += 100;  // But only 98 actually arrived (2% fee)!

// ✅ Measure actual received amount
uint256 balanceBefore = token.balanceOf(address(this));
token.transferFrom(user, address(this), 100);
uint256 balanceAfter = token.balanceOf(address(this));
uint256 actualReceived = balanceAfter - balanceBefore;
balances[user] += actualReceived;
```

### 3. Rebasing Tokens

**Tokens**: stETH, aTokens (Aave), others

**Issue**: Balance changes automatically without `transfer()` calls.

```solidity
// ❌ Assumes balance is static
uint256 deposited = token.balanceOf(address(this));
// ... time passes, positive rebase occurs ...
uint256 current = token.balanceOf(address(this));
// current > deposited, but contract doesn't track this!
```

**Fix**: Store shares instead of balances, or use `balanceOf()` for all calculations.

### 4. Permit Replay (EIP-2612)

**Vulnerability**: Permit signatures can be replayed on forks or after `transferFrom`.

```solidity
// User signs permit for contract A
permit(owner, spender, value, deadline, v, r, s);

// Attacker: Replay on fork chain with same chainId
// Or: Replay after partial use of allowance
```

**Mitigation**:
- Check `chainId` in signature
- Use nonce tracking
- Consume full allowance or set to 0 after use

### 5. ERC20 approve() Race Condition

**Issue**: Changing approval from N to M can be frontrun.

```solidity
// User: Change approval from 100 to 50
approve(spender, 50);

// Attacker: Frontruns with transferFrom(100), then backruns with transferFrom(50)
// Total transferred: 150 instead of intended 50
```

**Fix**: Use `increaseAllowance()` / `decreaseAllowance()`, or set to 0 first.

### Typical Impact
- Reentrancy → Critical
- Fee-on-transfer → Accounting errors
- Rebasing → Incorrect balance tracking

### Detection Method
- Check token contract interface (view functions)
- Test with known problematic tokens (USDT, USDC, stETH)
- Review weird-erc20 list: [d-xo/weird-erc20](https://github.com/d-xo/weird-erc20)

**Sources**:
- [Exploring ERC777 Tokens: Vulnerabilities](https://medium.com/@JohnnyTime/exploring-erc777-tokens-vulnerabilities-and-potential-dos-attacks-on-smart-contracts-507d44604281)
- [imBTC & ERC777: DeFi Hack Explained](https://zengo.com/imbtc-defi-hack-explained/)
- [Ten issues with ERC20s that can ruin your Smart Contract](https://medium.com/@deliriusz/ten-issues-with-erc20s-that-can-ruin-you-smart-contract-6c06c44948e0)
- [GitHub: weird-erc20](https://github.com/d-xo/weird-erc20)

---

## Cross-Chain/Bridge Attacks

### Overview
2025 statistics: **$1.5B (50.1%)** of stolen funds funneled through cross-chain bridges.

### Attack Vectors

#### 1. Message Replay

**Vulnerability**: Cross-chain messages lack unique identifiers.

```solidity
// ❌ No replay protection
function processBridgeMessage(
    uint256 amount,
    address recipient
) external {
    // Attacker can replay this on different chain or multiple times
    _mint(recipient, amount);
}

// ✅ Include nonce + source chain ID
function processBridgeMessage(
    uint256 nonce,
    uint256 sourceChainId,
    uint256 destChainId,
    uint256 amount,
    address recipient
) external {
    bytes32 messageId = keccak256(abi.encode(nonce, sourceChainId, destChainId, amount, recipient));
    require(!processedMessages[messageId], "Already processed");
    processedMessages[messageId] = true;
    _mint(recipient, amount);
}
```

#### 2. Fake Deposit Messages

**Attack**: Forge deposit events on source chain or manipulate validators.

**Mitigation**:
- Require supermajority of validators to sign (e.g., 7/10)
- Use secure multisig (not EOA keys)
- Time delays for large withdrawals

#### 3. Hash Collision

**Vulnerability**: Using `abi.encodePacked()` with dynamic types.

```solidity
// ❌ Hash collision possible
bytes32 messageHash = keccak256(abi.encodePacked(chain, token, recipient));
// "chain1", "tokenArecipient" == "chain1token", "Arecipient"

// ✅ Use abi.encode()
bytes32 messageHash = keccak256(abi.encode(chain, token, recipient));
```

See [Solidity 0.8.x Specific Pitfalls](#solidity-08x-specific-pitfalls) for details.

#### 4. Validator/Relayer Compromise

**Real incidents (2024)**:
- **Orbit Chain (Jan 2024)**: 7/10 multisig keys compromised
- **ALEX bridge (May 2024)**: Deployer account private key compromised, $4.3M loss

**Mitigation**:
- Hardware security modules (HSMs) for keys
- Rate limiting
- Emergency pause mechanisms
- Bug bounties

#### 5. Cross-Chain Sandwich Attacks (NEW)

**Research finding (2025)**: Attackers exploit events emitted on source chain to learn transaction details on destination chain **before** they appear in mempool.

**Attack flow**:
1. Monitor source chain events
2. Predict destination chain transaction
3. Frontrun on destination chain (submit higher gas)
4. Victim transaction executes
5. Backrun (sandwich complete)

**Mitigation**: Private mempools, commit-reveal schemes.

### Real-World Incidents

| Date | Bridge | Amount | Root Cause |
|------|--------|--------|------------|
| Jan 2024 | Orbit Chain | Unknown | 7/10 multisig compromise |
| Jan 2024 | Socket Protocol | $4.3M | Smart contract flaw (infinite approvals) |
| May 2024 | ALEX | $4.3M | Private key compromise |

### Typical Impact
- **Critical**: Double-spending, fund drainage across chains

### Detection Method
- Audit message validation logic
- Review multisig security (key storage, quorum)
- Check for replay protection (nonces, chain IDs)
- Monitor for abnormal validator behavior

**Sources**:
- [How Cross-Chain Bridges are Hacked](https://officercia.medium.com/how-cross-chain-bridges-are-hacked-d6ddb448401e)
- [SoK: A Review of Cross-Chain Bridge Hacks in 2023](https://arxiv.org/html/2501.03423v1)
- [7 Cross-Chain Bridge Vulnerabilities Explained - Chainlink](https://chain.link/education-hub/cross-chain-bridge-vulnerabilities)
- [The Walls Have Ears: Cross-Chain Sandwich Attacks](https://arxiv.org/html/2511.15245v1)

---

## MEV/Frontrunning

### Overview
**MEV (Maximal Extractable Value)**: Value extracted by reordering, including, or excluding transactions in a block.

**2025 Statistics**:
- Total MEV volume: **$561.92M**
- Sandwich attacks: **$289.76M (51.56%)**
- Sandwich attacks are 2nd most common MEV strategy

### Attack Types

#### 1. Sandwich Attacks

**Mechanism**: Frontrun + Backrun victim's trade to profit from slippage.

```
Mempool: User submits swap 1000 USDC → WETH (slippage 1%)

Attacker sees transaction:
1. Frontrun: Buy WETH (pushes price up)
2. Victim: Buys WETH at inflated price
3. Backrun: Sell WETH (profit from price difference)

Victim receives: ~990 USDC worth of WETH (1% slippage utilized)
Attacker profit: ~10 USDC (minus gas)
```

**Mitigation**:
```solidity
// ✅ Set tight slippage tolerance
router.swapExactTokensForTokens(
    amountIn,
    amountOutMin,  // Set close to expected (e.g., 0.5% slippage)
    path,
    to,
    deadline
);
```

**Advanced**: Use intent-based protocols (Flashbots Protect, CoW Swap) that hide transactions from public mempool.

#### 2. JIT (Just-In-Time) Liquidity

**Mechanism**: Bot adds liquidity right before large trade, removes after, capturing fees without IL risk.

```
1. Bot detects large pending swap in mempool
2. Frontrun: Add concentrated liquidity at current price
3. User's swap executes (bot earns majority of fees)
4. Backrun: Remove liquidity
```

**Impact on LPs**: LPs lose fee revenue to JIT bots.

**Mitigation**: Uniswap V4 hooks can penalize/prevent JIT.

#### 3. Liquidation MEV

**Mechanism**: Compete to liquidate undercollateralized positions for liquidation bonus.

**Not necessarily malicious**, but creates priority gas auctions (PGAs).

#### 4. LVR (Liquidity Volatility Risk)

**Most damaging MEV type**: Costs LPs 5-7% of liquidity annually.

**Mechanism**: Arbitrageurs exploit price differences between DEX and external markets.

```
External market: ETH price jumps $1800 → $1850
DEX (Uniswap): Still at $1800
Arbitrageur: Buy cheap on DEX, sell high externally
LP: Suffers impermanent loss + no fee compensation for this loss
```

**Mitigation**: Dynamic fees, oracles, MEV-smoothing mechanisms.

### Cross-Chain Sandwich Attacks (NEW)

See [Cross-Chain/Bridge Attacks](#cross-chainbridge-attacks).

### Mitigation Strategies

| Method | Description | Trade-offs |
|--------|-------------|------------|
| **Flashbots Protect** | Private mempool, no frontrunning | Centralization concern |
| **CoW Swap** | Intent-based, batch auctions | Less immediate execution |
| **MEV-Boost** | Block builder separation | 90% Ethereum validator adoption |
| **Low slippage** | Tight `amountOutMin` | May revert in volatile markets |
| **Private RPCs** | Don't broadcast to public mempool | Limited builder access |

### Typical Impact
- **Moderate to High**: Sandwich victims lose 0.5-2% per trade
- **LVR**: Systematic 5-7% annual loss for LPs

**Sources**:
- [MEV: A 2025 guide to Maximal Extractable Value](https://info.arkm.com/research/beginners-guide-to-mev)
- [Implementing Effective MEV Protection in 2025](https://medium.com/@ancilartech/implementing-effective-mev-protection-in-2025-c8a65570be3a)
- [Understanding MEV attacks - CoW Protocol](https://cow.fi/learn/mev-attacks-explained)
- [Front-Running & MEV Mitigation: A DEX Developer's Guide](https://speedrunethereum.com/guides/front-running-mev-mitigation)

---

## Precision/Rounding Errors

### 1. Division Before Multiplication

**Problem**: Solidity rounds towards zero. Dividing before multiplying loses precision.

```solidity
// ❌ Precision loss
uint256 result = (x / z) * y;
// Example: x=5, z=2, y=10
// (5 / 2) * 10 = 2 * 10 = 20 (lost 0.5)

// ✅ Multiply before divide
uint256 result = (x * y) / z;
// (5 * 10) / 2 = 50 / 2 = 25 ✓
```

**Rule**: Always multiply before dividing (unless phantom overflow is a concern).

### 2. Phantom Overflow

**Problem**: Intermediate result overflows even though final result fits.

```solidity
// ❌ Phantom overflow
uint256 x = 2**200;
uint256 percent = 3;
uint256 result = (x * percent) / 100;  // x * percent overflows!

// ✅ Divide before multiply (but loses precision)
uint256 result = (x / 100) * percent;

// ✅✅ Use fixed-point math library
import "@prb/math/contracts/PRBMathUD60x18.sol";
uint256 result = x.mulDiv(percent, 100);  // Handles overflow safely
```

**Libraries**:
- **PRBMath**: 60x18 fixed-point, phantom overflow protection
- **DSMath**: wadMul, wadDiv (18 decimals)
- **OpenZeppelin SafeMath** (not needed in 0.8.0+)

### 3. Rounding Direction Matters

**In DeFi vaults**: Always round in favor of the vault.

```solidity
// Depositing: Round shares DOWN (user gets slightly less)
function deposit(uint256 assets) public returns (uint256 shares) {
    shares = (assets * totalSupply) / totalAssets;  // Rounds down ✓
}

// Withdrawing: Round assets DOWN (user gets slightly less)
function withdraw(uint256 shares) public returns (uint256 assets) {
    assets = (shares * totalAssets) / totalSupply;  // Rounds down ✓
}
```

**OpenZeppelin**: `Math.Rounding.Down` vs `Math.Rounding.Up`

### 4. Percentage Calculations

```solidity
// ❌ Loss of precision for small amounts
uint256 fee = (amount * feePercent) / 10000;  // 0.01% fee
// If amount = 50, feePercent = 1 (0.01%): (50 * 1) / 10000 = 0

// ✅ Use basis points (10000 = 100%) and multiply by 1e18
uint256 fee = (amount * feePercent * 1e18) / (10000 * 1e18);

// ✅✅ Or enforce minimum amount
require(amount >= 10000, "Amount too small");
```

### 5. Dust Attacks

**Attack**: Exploit rounding by sending tiny amounts repeatedly.

```solidity
// Vulnerable: No minimum deposit
function deposit(uint256 amount) external {
    uint256 shares = (amount * totalSupply) / totalAssets;
    // If amount=1, totalAssets=1e18: shares = 0
    // Attacker deposits 1 wei repeatedly, gets 0 shares each time
    _mint(msg.sender, shares);
}
```

**Fix**: Enforce minimum deposit

```solidity
require(amount >= MIN_DEPOSIT, "Below minimum");
```

### Real-World Incidents

- **Bunni (Sep 2025)**: Rounding error in Uniswap v4 DEX contracts, $8M loss
- **Balancer (Nov 2025)**: Rounding error in pool math, $128M multi-chain exploit

### Detection Method
- Fuzz testing with small/large values
- Check all divisions (ensure numerator > denominator for non-zero result)
- Static analysis: Flag division before multiplication

**Sources**:
- [Math in Solidity (Part 3: Percents and Proportions)](https://medium.com/coinmonks/math-in-solidity-part-3-percents-and-proportions-4db014e080b1)
- [Solidity Design Patterns: Multiply before Dividing](https://soliditydeveloper.com/solidity-design-patterns-multiply-before-dividing)
- [Precision Loss Errors - Dacian](https://dacian.me/precision-loss-errors)

---

## Governance Attacks

### 1. Flash Loan Governance Takeover

**Attack**: Borrow governance tokens via flash loan, pass malicious proposal, execute in same transaction.

**Real attack**: **Beanstalk DAO (April 2022)** - $182M drained

**Attack flow**:
```solidity
1. Flash loan 100M governance tokens
2. Create proposal: "Transfer all funds to attacker"
3. Vote with 100M tokens (instant majority)
4. Execute proposal (no timelock!)
5. Receive funds
6. Repay flash loan
All in single transaction!
```

**Why it worked**:
- No timelock delay between vote and execution
- No requirement for sustained token holding
- Quorum too low

**Mitigation**:
```solidity
// ✅ Voting power delay
mapping(address => uint256) public votingPowerSnapshotBlock;

function delegate(address delegatee) external {
    votingPowerSnapshotBlock[msg.sender] = block.number + VOTING_DELAY;
}

function castVote(uint256 proposalId) external {
    require(block.number >= votingPowerSnapshotBlock[msg.sender], "Must wait");
}

// ✅ Timelock between vote and execution
function execute(uint256 proposalId) external {
    Proposal storage proposal = proposals[proposalId];
    require(proposal.endBlock + TIMELOCK_DELAY < block.number, "Timelock active");
}

// ✅ Higher quorum
require(votesFor > (totalSupply * QUORUM_PERCENT) / 100, "Quorum not reached");
```

### 2. Quorum Manipulation

**Attack**: Reduce circulating supply to lower quorum threshold.

```
Total supply: 1M tokens
Quorum: 10% (100K tokens needed)

Attacker: Burns or locks 900K tokens (not really, just removes from circulation)
New effective quorum: 10% of 100K = 10K tokens (attacker already has this)
```

**Mitigation**: Base quorum on total minted supply, not circulating.

### 3. Proposal Spam

**Attack**: Submit many low-quality proposals to DoS governance.

**Mitigation**:
- Proposal deposit (refunded if not rejected)
- Rate limiting (1 proposal per address per N blocks)

### 4. Timelock Bypass

**Attack**: Exploit admin functions that bypass timelock.

```solidity
// ❌ Emergency function bypasses timelock
function emergencyPause() external onlyOwner {
    _pause();  // No timelock!
}
```

**Mitigation**: Separate emergency multisig (5/9) for true emergencies only.

### 5. Vote Buying

**Attack**: Buy votes off-chain (via bribes) or on-chain (via delegation markets).

**Not technically an exploit**, but governance risk.

### Typical Impact
- **Critical**: Complete protocol takeover, treasury drainage

### Detection Method
- Review timelock delays (minimum 24-48 hours)
- Check quorum requirements (10-20% minimum)
- Audit voting power snapshots

**Best Practices**:
1. **Snapshot voting** (off-chain) + on-chain execution
2. **Timelock** minimum 24-48 hours
3. **High quorum** (10-20% of supply)
4. **Voting power delay** (1-7 days after token acquisition)
5. **Tiered governance** (small changes → short timelock, large changes → long timelock)

**Sources**:
- [DeFi DAOs Explained: The Complete Guide](https://olympix.security/blog/defi-daos-explained-the-complete-guide-to-decentralized-autonomous-organizations-in-2025)
- [Flash Loan Attacks and the Manipulation of Governance Tokens](https://fastercapital.com/content/Governance-Tokens--Governance-Gone-Wrong--Flash-Loan-Attacks-and-the-Manipulation-of-Governance-Tokens.html)
- [Governance Attacks - DAO Security Vulnerabilities](https://www.acadictive.com/blockchain/modules/governance-attack/flash-loan-attacks)

---

## Upgrade Attacks

### 1. Storage Collisions

**Root cause**: Proxy and implementation use same storage slots.

**Vulnerable pattern**:
```solidity
// Proxy contract
contract Proxy {
    address public implementation;  // Slot 0
    address public admin;            // Slot 1
}

// Implementation V1
contract ImplementationV1 {
    uint256 public someValue;        // Slot 0 - COLLISION!
    bool public initialized;         // Slot 1 - COLLISION!
}
```

**Attack**: Writing to `someValue` overwrites `implementation` pointer!

**Real incident**: **Audius (July 2022)** - Storage collision after upgrade
- Proxy added new variable `proxyAdmin` to its storage
- Implementation layout no longer aligned
- Attacker called `initialize()` again (read wrong slot, thought uninitialized)

**Mitigation - Use ERC7201 Namespaced Storage**:
```solidity
// ✅ ERC7201: Isolated namespaces
contract Implementation {
    // keccak256(keccak256("myproject.storage.main") - 1) & ~0xff
    bytes32 private constant MAIN_STORAGE_LOCATION =
        0x1234...abcd;  // Calculated position, very unlikely to collide

    struct MainStorage {
        uint256 someValue;
        bool initialized;
    }

    function _getMainStorage() private pure returns (MainStorage storage $) {
        assembly {
            $.slot := MAIN_STORAGE_LOCATION
        }
    }
}
```

**ERC7201 benefits**:
- Each namespace has unique, collision-resistant slot
- Safe against collisions with Solidity/Vyper layouts
- `@custom:storage-location` NatSpec annotation for documentation

### 2. Uninitialized Implementation

**Attack**: Initialize implementation contract directly (not through proxy).

```solidity
// Implementation deployed at 0xAAA
contract Implementation {
    address public owner;

    function initialize(address _owner) external {
        require(owner == address(0), "Already initialized");
        owner = _owner;
    }

    function destroy() external {
        require(msg.sender == owner);
        selfdestruct(payable(owner));
    }
}

// Attack:
1. Call Implementation(0xAAA).initialize(attackerAddress)
2. Call Implementation(0xAAA).destroy()
3. Implementation code deleted
4. All proxies pointing to 0xAAA are now broken (delegatecall to empty address)
```

**Real incident**: **Parity multisig (Nov 2017)** - $150M frozen
- Library contract was uninitialized
- Attacker initialized it, became owner, called `kill()` (selfdestruct)
- All proxies using library became unusable

**Mitigation**:
```solidity
// ✅ Lock implementation in constructor
constructor() {
    _disableInitializers();
}

// ✅ Or: Initialize in deployment script immediately
// deploy() then initialize() in same transaction
```

### 3. Selfdestruct in Implementation

**Critical rule**: **NEVER** put `selfdestruct` in implementation contracts.

**Why**: Proxy's `delegatecall` executes in implementation context → destroys proxy.

```solidity
// ❌ NEVER DO THIS
contract Implementation {
    function destroy() external onlyOwner {
        selfdestruct(payable(owner));  // DESTROYS PROXY!
    }
}
```

**Note**: `selfdestruct` deprecated/changed in recent EIPs, but still dangerous in older contracts.

### 4. Storage Layout Changes

**Problem**: Adding variables in wrong position during upgrade.

```solidity
// V1
contract ImplementationV1 {
    uint256 public a;  // Slot 0
    uint256 public b;  // Slot 1
}

// V2 - WRONG
contract ImplementationV2 {
    uint256 public newVar;  // Slot 0 - OVERWRITES 'a'!
    uint256 public a;       // Slot 1 - Now points to old 'b' data
    uint256 public b;       // Slot 2 - Empty
}

// V2 - CORRECT
contract ImplementationV2 {
    uint256 public a;       // Slot 0 - Same
    uint256 public b;       // Slot 1 - Same
    uint256 public newVar;  // Slot 2 - NEW slot
}
```

**Tool**: OpenZeppelin Upgrades plugin validates storage layout.

### 5. Malicious Upgrades (Rug Pulls)

**Attack**: Upgrade to malicious implementation.

```solidity
// V1: Normal contract
// V2: Malicious
function withdraw() external onlyOwner {
    payable(owner).transfer(address(this).balance);  // Rug pull!
}
```

**Mitigation**:
- **Timelock** on upgrades (24-48 hours)
- **Multisig** for upgrade authority (5/9 or higher)
- **Immutable proxy** after stabilization (renounce upgrade rights)
- **Community governance** for upgrades

### Typical Impact
- **Critical**: Frozen funds, complete protocol destruction
- **Historical losses**: $400M+ across 37 incidents

### Detection Method
- Storage layout analysis (OpenZeppelin Upgrades plugin)
- Check for `selfdestruct` in implementations
- Verify initialization protection
- Review upgrade authorization mechanism

**Sources**:
- [Upgradeable Proxy Contract Security Best Practices - CertiK](https://www.certik.com/resources/blog/upgradeable-proxy-contract-security-best-practices)
- [ERC-7201: Namespaced Storage Layout](https://eips.ethereum.org/EIPS/eip-7201)
- [The Dark Side of Upgrades: Security Risks](https://arxiv.org/html/2508.02145v1)
- [Guide To Upgradable Smart Contracts - Cyfrin](https://www.cyfrin.io/blog/upgradeable-proxy-smart-contract-pattern)

---

## Solidity 0.8.x Specific Pitfalls

### 1. Checked Arithmetic (Default Behavior)

**Change from 0.7.x**: Arithmetic operations now **revert on overflow** instead of wrapping.

```solidity
// Solidity 0.8.0+
uint256 a = type(uint256).max;
a = a + 1;  // Reverts with Panic(0x11: Arithmetic overflow)

// If you WANT wrapping behavior:
unchecked {
    a = a + 1;  // Wraps to 0, no revert
}
```

**When to use `unchecked`**:
- Gas optimization (skips overflow checks)
- Known-safe operations (e.g., loop counters)
- Intentional wrapping behavior

**Caution**: Only use `unchecked` when you're **certain** overflow is impossible or desired.

### 2. Custom Errors vs Panic

**Solidity 0.8.0+**: Introduces Panic codes for runtime errors.

| Code | Meaning |
|------|---------|
| 0x01 | Assert failed |
| 0x11 | Arithmetic overflow/underflow |
| 0x12 | Division by zero |
| 0x21 | Invalid enum value |
| 0x22 | Invalid storage array access |
| 0x31 | Pop on empty array |
| 0x32 | Out of bounds array access |
| 0x41 | Out of memory |
| 0x51 | Invalid internal function call |

**Custom errors** (0.8.4+): More gas efficient than `require` strings.

```solidity
// ✅ Custom error (cheaper)
error InsufficientBalance(uint256 available, uint256 required);

function withdraw(uint256 amount) external {
    if (balance[msg.sender] < amount) {
        revert InsufficientBalance(balance[msg.sender], amount);
    }
}
```

### 3. Storage Layout in Upgradeable Contracts

**Issue**: Storage layout must be preserved across upgrades.

**Solution**: Use **ERC7201 Namespaced Storage** (see [Upgrade Attacks](#upgrade-attacks)).

### 4. abi.encodePacked() Hash Collisions

**Vulnerability**: Dynamic types can collide.

```solidity
// ❌ Hash collision
keccak256(abi.encodePacked("a", "bc"))  == keccak256(abi.encodePacked("ab", "c"))
keccak256(abi.encodePacked(["a"], ["bc"])) == keccak256(abi.encodePacked(["ab"], ["c"]))

// ✅ Use abi.encode() for hashing
keccak256(abi.encode("a", "bc"))  != keccak256(abi.encode("ab", "c"))
```

**Why**: `abi.encodePacked()` concatenates without delimiters/length info.

**When it matters**:
- Signature verification
- Mapping keys
- Cross-chain message hashes

**Mitigation**:
```solidity
// ✅ Option 1: Use abi.encode()
bytes32 hash = keccak256(abi.encode(a, b, c));

// ✅ Option 2: Fixed-length types only
bytes32 hash = keccak256(abi.encodePacked(uint256(a), address(b)));

// ✅ Option 3: Single dynamic type
bytes32 hash = keccak256(abi.encodePacked(dynamicString));
```

### 5. tx.origin vs msg.sender

**Critical rule**: **NEVER use `tx.origin` for authorization.**

**Why**:
- `tx.origin`: Original EOA that started transaction chain
- `msg.sender`: Immediate caller (EOA or contract)

**Attack**:
```solidity
// ❌ Vulnerable to phishing
contract Wallet {
    function withdraw() external {
        require(tx.origin == owner);  // VULNERABLE!
        payable(owner).transfer(address(this).balance);
    }
}

// Attacker's contract
contract Attacker {
    function attack(address wallet) external {
        Wallet(wallet).withdraw();  // tx.origin = victim, passes check!
    }
}

// Attack flow:
1. Victim visits attacker's website
2. Website calls Attacker.attack(victimWallet)
3. tx.origin = victim, msg.sender = Attacker contract
4. Wallet.withdraw() passes tx.origin check
5. Funds drained to attacker
```

**Delegatecall context**:
In proxy patterns, `msg.sender` = proxy, but `tx.origin` = original caller. Using `tx.origin` defeats proxy security.

**Fix**:
```solidity
// ✅ Always use msg.sender
function withdraw() external {
    require(msg.sender == owner);
    payable(owner).transfer(address(this).balance);
}
```

### 6. Delegatecall Storage Context

**Key point**: `delegatecall` executes target code in caller's storage context.

```solidity
contract Proxy {
    address public implementation;  // Slot 0

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

contract Implementation {
    address public implementation;  // Must match Proxy's slot 0

    function setImplementation(address _impl) external {
        implementation = _impl;  // Writes to Proxy's storage!
    }
}
```

**Risk**: Storage collision (see [Upgrade Attacks](#upgrade-attacks)).

### 7. ERC7201: Namespaced Storage (New Standard)

**Purpose**: Prevent storage collisions in modular contracts (proxies, libraries).

**Formula**: `erc7201(id: string) = keccak256(keccak256(id) - 1) & ~0xff`

**Example**:
```solidity
// @custom:storage-location erc7201:myproject.storage.main
bytes32 private constant MAIN_STORAGE_LOCATION =
    0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab00;

struct MainStorage {
    uint256 value;
    bool initialized;
}

function _getMainStorage() private pure returns (MainStorage storage $) {
    assembly {
        $.slot := MAIN_STORAGE_LOCATION
    }
}
```

**Solidity 0.8.20+**: Supports `@custom:storage-location` NatSpec tag.

### Detection Methods
- Static analysis: Slither, Aderyn
- Review: Check all `abi.encodePacked()` with dynamic types
- Test: Upgrade scripts validate storage layout
- Audit: Look for `tx.origin` usage

**Sources**:
- [ERC-7201: Namespaced Storage Layout](https://eips.ethereum.org/EIPS/eip-7201)
- [Understanding Hash Collisions: abi.encodePacked](https://www.nethermind.io/blog/understanding-hash-collisions-abi-encodepacked-in-solidity)
- [tx.origin Phishing Attack](https://solidity-by-example.org/hacks/phishing-with-tx-origin/)
- [Security Considerations - Solidity Docs](https://docs.soliditylang.org/en/latest/security-considerations.html)

---

## Summary: Attack Prevention Checklist

### Before Deployment
- [ ] Use Chainlink TWAP oracles (not AMM spot price)
- [ ] Check Chainlink staleness (`updatedAt` < heartbeat threshold)
- [ ] Implement `nonReentrant` on all state-changing functions
- [ ] Use `abi.encode()` for hashing (not `abi.encodePacked()`)
- [ ] Never use `tx.origin` for authorization
- [ ] Check return values of low-level calls
- [ ] Multiply before dividing (precision)
- [ ] Use OpenZeppelin's ERC4626 with `_decimalsOffset()`
- [ ] Apply access control modifiers (`onlyOwner`, `AccessControl`)
- [ ] Protect initialization functions (`initializer` modifier)
- [ ] Use ERC7201 namespaced storage for upgradeable contracts
- [ ] Never put `selfdestruct` in implementation contracts
- [ ] Implement timelock for governance (24-48h minimum)
- [ ] Require voting power delays (1-7 days)
- [ ] Set high quorum thresholds (10-20% of supply)
- [ ] Add replay protection for cross-chain messages (nonce + chainId)
- [ ] Test with fee-on-transfer and rebasing tokens
- [ ] Avoid ERC777 (use ERC20 with ERC2612/ERC1363)
- [ ] Enforce minimum deposit amounts (prevent dust attacks)
- [ ] Use private mempool (Flashbots) for MEV-sensitive txs

### Audit Priorities
1. **Critical**: Oracle manipulation, reentrancy, access control
2. **High**: Storage collisions, uninitialized proxies, upgrade logic
3. **Medium**: Precision errors, unchecked calls, token compatibility
4. **Low**: Gas optimizations, code quality

### Incident Response
1. **Pause mechanisms**: Circuit breakers for detected anomalies
2. **Emergency multisig**: Separate from normal operations
3. **Bug bounty**: Incentivize white-hat disclosure
4. **Insurance**: Cover catastrophic losses
5. **Monitoring**: On-chain alerts for large transactions, oracle deviations

---

## References

### Official Documentation
- [Solidity Security Considerations](https://docs.soliditylang.org/en/latest/security-considerations.html)
- [OpenZeppelin Contracts](https://docs.openzeppelin.com/contracts/)
- [ERC-4626 Tokenized Vault Standard](https://eips.ethereum.org/EIPS/eip-4626)
- [ERC-7201 Namespaced Storage Layout](https://eips.ethereum.org/EIPS/eip-7201)
- [ERC-7540 Asynchronous Vaults](https://eips.ethereum.org/EIPS/eip-7540)

### Security Resources
- [Rekt News](https://rekt.news/) - DeFi hack leaderboard
- [DeFiLlama Hacks](https://defillama.com/hacks) - Hack database
- [ChainSec DeFi Hacks](https://chainsec.io/defi-hacks/) - Comprehensive list
- [SWC Registry](https://swcregistry.io/) - Smart contract weakness classification
- [Consensys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)

### Academic Research
- [Strengthening DeFi Security: Flash Loan Vulnerabilities](https://arxiv.org/html/2411.01230v2)
- [TWAP Oracle Attacks: Easier Done than Said?](https://eprint.iacr.org/2022/445.pdf)
- [SoK: A Review of Cross-Chain Bridge Hacks in 2023](https://arxiv.org/html/2501.03423v1)
- [The Dark Side of Upgrades: Security Risks](https://arxiv.org/html/2508.02145v1)

### Tools
- **Static Analysis**: Slither, Mythril, Semgrep, Aderyn
- **Formal Verification**: Certora, Halmos, K Framework
- **Fuzzing**: Echidna, Foundry (invariant tests), Medusa
- **Runtime Monitoring**: Forta, OpenZeppelin Defender
- **Audit Firms**: Trail of Bits, OpenZeppelin, Consensys Diligence, Zellic, Code4rena

---

**End of Document**

Total attack vectors documented: **60+**
Real-world incidents referenced: **20+**
Total value at risk (2024-2026): **$6.6B+**
