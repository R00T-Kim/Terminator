# Business Logic Attack Scenario Templates

> Reference for analyst(bizlogic), web-tester, workflow-auditor agents.
> Each scenario includes: pattern name, trigger condition, test steps, expected vulnerable behavior, severity estimation.

## 1. Payment & Financial Logic

### 1.1 Negative Quantity/Amount Manipulation
- **Pattern**: Cart/order accepts negative values → payment reduction or refund fraud
- **Trigger**: Any endpoint accepting `quantity`, `amount`, `price` parameters
- **Test Steps**:
  1. Add item to cart with quantity=1, capture request
  2. Replay with quantity=-1 or amount=-0.01
  3. Check if total becomes negative or triggers refund
  4. Try quantity=0, quantity=99999999 (boundary)
- **Indicators**: No server-side validation, total price goes negative, refund generated
- **Severity**: Critical (direct financial impact)
- **Seen in**: E-commerce, exchanges (trading quantity), subscription billing

### 1.2 Balance Multiplication / Infinite Fund Creation
- **Pattern**: Deposit confirmation race → balance credited multiple times
- **Trigger**: Deposit/top-up/transfer endpoints with async confirmation
- **Test Steps**:
  1. Initiate deposit, capture confirmation callback
  2. Replay confirmation request N times rapidly
  3. Check if balance increases each time
  4. Test concurrent: deposit + withdrawal simultaneously
- **Indicators**: No idempotency key, balance increases without matching deposit
- **Severity**: Critical
- **Seen in**: Fintech, crypto exchanges, P2P payment

### 1.3 Currency/Asset Rounding Exploitation
- **Pattern**: Precision mismatch between display and backend → accumulate rounding errors
- **Trigger**: Multi-currency conversion, swap, or micro-transaction endpoints
- **Test Steps**:
  1. Execute many small conversions (e.g., $0.001 worth)
  2. Check if rounding consistently favors attacker
  3. Test decimal overflow (18+ decimal places for crypto)
  4. Compare displayed amount vs actual deducted amount
- **Indicators**: Inconsistent decimal handling, exploitable rounding direction
- **Severity**: High
- **Seen in**: Crypto exchanges, DeFi, forex platforms

### 1.4 Coupon/Promo Code Abuse
- **Pattern**: Coupon applied multiple times, stacked, or used after expiry
- **Trigger**: Discount/promo/referral code endpoints
- **Test Steps**:
  1. Apply coupon, complete purchase, reuse same coupon
  2. Apply multiple different coupons simultaneously
  3. Apply coupon, remove item, add expensive item, checkout
  4. Modify coupon value in request body
- **Indicators**: No single-use enforcement, stackable discounts
- **Severity**: Medium-High
- **Seen in**: E-commerce, SaaS, food delivery

## 2. Authentication & Account Logic

### 2.1 MFA Code Leakage in Response
- **Pattern**: MFA/OTP code exposed in redirect URL, response body, or headers
- **Trigger**: Login, password reset, or MFA verification endpoints
- **Test Steps**:
  1. Trigger MFA, inspect full HTTP response (headers + body + redirect URL)
  2. Check if OTP/token appears in: response JSON, Set-Cookie, Location header, HTML hidden fields
  3. Check if MFA code is predictable (sequential, timestamp-based)
  4. Check if MFA can be bypassed by removing the MFA parameter entirely
- **Indicators**: OTP in response before user submits it, predictable tokens
- **Severity**: Critical (account takeover)
- **Seen in**: Healthcare, banking, SaaS

### 2.2 Password Reset Token Reuse
- **Pattern**: Reset token not invalidated after use → replay for persistent access
- **Trigger**: Password reset flow
- **Test Steps**:
  1. Request password reset, capture token
  2. Use token to reset password
  3. Try using same token again
  4. Request new reset, check if old token still works
- **Indicators**: Token survives usage, no expiry enforcement
- **Severity**: High
- **Seen in**: Any web app with password reset

### 2.3 Role/Privilege Escalation via Parameter Manipulation
- **Pattern**: Role ID/type passed client-side → modify to gain admin
- **Trigger**: Registration, profile update, role assignment endpoints
- **Test Steps**:
  1. Register as regular user, capture request
  2. Add/modify `role`, `is_admin`, `user_type`, `permission_level` parameters
  3. Try accessing admin endpoints with regular session after role change
  4. Check if invitation-only roles can be self-assigned
- **Indicators**: Client-controlled role fields, no server-side role validation
- **Severity**: Critical
- **Seen in**: SaaS, multi-tenant apps, exchanges (trader→admin)

## 3. State Machine & Workflow Violations

### 3.1 Order/Transaction State Skip
- **Pattern**: Skip required states (pending→complete, skip payment verification)
- **Trigger**: Multi-step workflows: checkout, KYC, approval chains
- **Test Steps**:
  1. Map full state machine (pending→verified→approved→complete)
  2. Try jumping directly to final state via API
  3. Try reversing states (complete→pending→modify→complete)
  4. Try completing step N+1 before step N
- **Indicators**: No state transition validation, backend accepts any state
- **Severity**: High-Critical
- **Seen in**: E-commerce checkout, loan approval, KYC, exchanges

### 3.2 Race Condition in State Transitions
- **Pattern**: Concurrent requests exploit TOCTOU in state checks
- **Trigger**: Any "check then act" pattern: balance check→deduct, stock check→reserve
- **Test Steps**:
  1. Identify check-then-act pattern in API
  2. Send N concurrent requests (10-50) for same action
  3. Check if action executed more times than allowed
  4. Specific: withdrawal race (check balance → deduct → both succeed)
- **Indicators**: No distributed locking, optimistic concurrency without retry
- **Severity**: Critical
- **Seen in**: Banking, crypto exchanges, ticket booking, P2P trade

### 3.3 P2P Trade State Manipulation
- **Pattern**: Buyer marks "paid" → seller doesn't confirm → system auto-releases
- **Trigger**: P2P/escrow trade endpoints
- **Test Steps**:
  1. Create P2P trade as buyer
  2. Mark as "paid" without actual payment
  3. Wait for auto-release timer or dispute resolution
  4. Test: cancel after counterparty confirmed, modify amount mid-trade
- **Indicators**: No payment verification oracle, auto-release on timeout
- **Severity**: Critical
- **Seen in**: Crypto P2P (Binance P2P, CoinW P2P, etc.)

## 4. API & Data Logic

### 4.1 IDOR in Multi-Entity Operations
- **Pattern**: Modify entity ID to access/modify other users' resources
- **Trigger**: Any endpoint with user-controlled IDs (order_id, account_id, file_id)
- **Test Steps**:
  1. Perform action with own ID, capture request
  2. Increment/decrement ID
  3. Try UUID enumeration if applicable
  4. Test both read (GET) and write (PUT/DELETE) access
- **Indicators**: Sequential IDs, no ownership validation
- **Severity**: High-Critical
- **Seen in**: Universal

### 4.2 Mass Assignment / Hidden Parameter Injection
- **Pattern**: Backend binds all request params → inject unintended fields
- **Trigger**: PUT/PATCH endpoints, user profile update, settings
- **Test Steps**:
  1. Send normal update request
  2. Add extra fields: `balance`, `credits`, `role`, `verified`, `is_premium`
  3. Check if any extra field was persisted
  4. Check API docs/schema for undocumented fields
- **Indicators**: Framework auto-binding (Rails, Django, Spring), no whitelist
- **Severity**: Medium-Critical (depends on injectable field)
- **Seen in**: REST APIs, GraphQL

### 4.3 GraphQL Introspection & Depth Abuse
- **Pattern**: Introspection enabled → discover hidden mutations, nested query DoS
- **Trigger**: GraphQL endpoint
- **Test Steps**:
  1. `{__schema{types{name,fields{name}}}}` introspection query
  2. Look for admin mutations, internal fields
  3. Test deeply nested queries for resource exhaustion
  4. Test batch queries for rate limit bypass
- **Indicators**: Introspection enabled in production, no query depth limit
- **Severity**: Medium-High
- **Seen in**: Modern APIs, crypto platforms

## 5. Copy Trading / Social Trading (Exchange-Specific)

### 5.1 Lead Trader Position Attribution IDOR
- **Pattern**: Modify lead_trader_id to mirror unauthorized positions
- **Trigger**: Copy trading follow/unfollow, position mirror endpoints
- **Test Steps**:
  1. Follow a lead trader, capture API requests
  2. Modify lead_trader_id to another trader
  3. Check if positions are mirrored from unauthorized source
  4. Test: unfollow all → positions still active?
- **Indicators**: Client-controlled trader attribution, no follow validation
- **Severity**: Critical (forced fund movement)
- **Seen in**: CoinW, Binance Copy Trading, eToro

### 5.2 Grid Bot Parameter Overflow
- **Pattern**: Grid bot price bounds accept extreme values → unintended orders
- **Trigger**: Automated trading bot configuration endpoints
- **Test Steps**:
  1. Create grid bot with normal parameters
  2. Set lower_price=0, upper_price=MAX_INT
  3. Set grid_count=1 (single massive order)
  4. Set negative spread or zero step size
- **Indicators**: No sanity checks on trading parameters
- **Severity**: High
- **Seen in**: Exchange bot features (CoinW Grid, Binance Grid)

## Usage Guide for Agents

### analyst (mode=bizlogic)
- Start with Section 1-2 for financial and auth targets
- Cross-reference with `endpoint_map.md` to map scenarios to discovered endpoints
- Score each scenario's applicability (1-10) based on target type

### web-tester
- Execute test steps from relevant scenarios
- Focus on Section 3 (state machine) and Section 4 (API logic)
- Record all responses for evidence

### workflow-auditor
- Map target's state machines first
- Then apply Section 3 scenarios systematically
- Flag any transition that shouldn't be possible

### Severity Calibration
- Financial impact (fund loss/gain) = Critical
- Account takeover = Critical
- Data access across users = High
- Workflow bypass without direct financial impact = Medium-High
- Information disclosure = Medium
