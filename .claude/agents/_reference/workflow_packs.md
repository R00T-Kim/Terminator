# Workflow Packs Reference

Shared reference for `@workflow-auditor` and `@web-tester`. Each pack defines a structured test sequence for a common business workflow pattern. Packs are selected based on the target's workflow_map.md and state_machines.md.

> **Design rationale**: Pack definitions are separated from agent prompts per APE (Zhou et al., 2023) — aggressive pruning keeps agent prompts lightweight while preserving detailed test matrices in reference files.

---

## Pack Selection Guide

| Pack | Select When | Primary Attack Classes |
|------|-------------|----------------------|
| `workspace_pack` | Multi-tenant SaaS with team/workspace isolation | IDOR, cross-tenant access, role confusion |
| `billing_pack` | Payment processing, subscription tiers, refunds | Race condition, state manipulation, amount tampering |
| `admin_pack` | Admin panel, user management, impersonation | Privilege escalation, audit bypass, phantom access |
| `invite_pack` | Invitation/sharing with link-based or email-based acceptance | Replay, expiration bypass, unauthorized acceptance |
| `race_pack` | Any concurrent-access pattern on shared mutable resources | Double-spend, TOCTOU, idempotency violation |

---

## workspace_pack

**Precondition**: Target has workspace/team/organization concept with member roles.

### Test Sequence

```
1. SETUP
   - Create Workspace W1 with User A (owner)
   - Create Workspace W2 with User B (owner)
   - Add User C as member of W1

2. CROSS-TENANT ISOLATION
   - User A → GET /api/workspaces/{W2_id}/resources → MUST return 403/404
   - User A → GET /api/workspaces/{W2_id}/members → MUST return 403/404
   - User C → enumerate workspace IDs → SHOULD NOT reveal W2 existence

3. ROLE BOUNDARY
   - User C (member) → POST /api/workspaces/{W1_id}/invite → MUST fail (owner-only action?)
   - User C (member) → DELETE /api/workspaces/{W1_id} → MUST fail
   - User C (member) → PUT /api/workspaces/{W1_id}/settings → MUST fail

4. ROLE TRANSITION
   - Promote User C to admin → verify new permissions active
   - Demote User C back to member → verify old permissions revoked IMMEDIATELY
   - Delete User C from W1 → verify ALL access revoked (including cached sessions/tokens)

5. OWNERSHIP TRANSFER
   - Transfer W1 ownership from A to C
   - Verify A loses owner-only actions
   - Verify A cannot undo transfer unilaterally

6. EDGE CASES
   - User A in both W1 and W2 → actions in W1 context MUST NOT affect W2
   - Last admin removal → what happens? (should block or auto-transfer)
   - Workspace deletion → member sessions still valid?
```

### Expected Anomalies
- Missing tenant ID validation on resource endpoints (IDOR)
- Role change not invalidating existing sessions/tokens
- Ownership transfer not revoking previous owner's elevated permissions
- Cross-workspace data leakage via shared resource references

---

## billing_pack

**Precondition**: Target has payment processing, subscriptions, or credit system.

### Test Sequence

```
1. SUBSCRIPTION LIFECYCLE
   - Subscribe to free tier → upgrade to paid → downgrade to free → cancel
   - At each transition: verify feature access matches current tier IMMEDIATELY
   - After cancel: verify premium features are inaccessible

2. PAYMENT INTEGRITY
   - Initiate payment → intercept amount → modify to $0.01 → submit
   - Initiate payment → complete → replay same payment request
   - Initiate payment → cancel mid-flow → verify no charge AND no premium access

3. REFUND EXPLOITATION
   - Complete purchase → request refund → verify access revoked
   - Request refund for amount > original payment
   - Request refund twice for same transaction
   - Request refund after using the purchased resource

4. COUPON/CREDIT
   - Apply coupon → verify discount applied correctly
   - Apply same coupon twice (idempotency)
   - Apply expired coupon
   - Apply coupon from different account/workspace
   - Combine multiple coupons (if supposedly not allowed)

5. RACE CONDITIONS
   - Two simultaneous upgrade requests (double charge?)
   - Simultaneous purchase + cancel (charge without access? access without charge?)
   - Simultaneous coupon redemption (double discount?)
   - Balance transfer: send $100 twice simultaneously from $100 balance (double-spend)

6. TIER BOUNDARY
   - Free user → access paid API endpoint directly (without subscription)
   - Downgraded user → cached premium API key still works?
   - Trial expired → premium features still accessible via direct endpoint?
```

### Expected Anomalies
- Payment amount modifiable client-side
- Refund doesn't revoke associated access
- Coupon/credit reusable via race condition
- Tier downgrade doesn't invalidate premium API keys/sessions
- Balance can go negative via concurrent transfers

---

## admin_pack

**Precondition**: Target has admin panel, user management, or impersonation features.

### Test Sequence

```
1. ADMIN PRIVILEGE BOUNDARY
   - Regular user → access /admin/* endpoints directly → MUST return 403
   - Regular user → add admin role to self via API → MUST fail
   - New admin → verify cannot access super-admin functions

2. IMPERSONATION SAFETY
   - Admin impersonates User A → performs action → verify audit log records ADMIN, not User A
   - Admin impersonates User A → attempts to change User A's password → SHOULD be blocked
   - Admin impersonates User A → admin session expires → impersonation MUST end
   - Impersonation token → can it be used to impersonate OTHER users? (scope escalation)

3. USER MANAGEMENT
   - Admin creates user → sets initial permissions → verify correct
   - Admin deletes user → verify: sessions killed, data access revoked, scheduled jobs cancelled
   - Admin disables user → verify: cannot login, API keys fail, but data preserved

4. AUDIT LOG INTEGRITY
   - Admin modifies user → verify audit log entry created
   - Admin → attempt to delete/modify audit log entries → MUST fail
   - Bulk operations → each operation individually logged?
   - Failed admin actions → logged? (negative audit trail)

5. ADMIN SESSION
   - Admin session timeout → shorter than regular user?
   - Admin on multiple devices → concurrent session limit?
   - Admin role revoked → existing session immediately invalidated?

6. EDGE CASES
   - Last admin → can delete self? (should block)
   - Admin → create another admin → new admin deletes original admin
   - Admin → export all user data → rate limited? Logged?
```

### Expected Anomalies
- Admin endpoints accessible via direct URL without role check
- Impersonation doesn't properly scope actions
- Audit log entries modifiable or deletable
- Admin role revocation doesn't invalidate active sessions
- User deletion doesn't clean up all associated resources

---

## invite_pack

**Precondition**: Target has invitation system (email, link, or code-based).

### Test Sequence

```
1. INVITATION LIFECYCLE
   - Create invitation → send → accept → verify access granted
   - Create invitation → send → reject → verify NO access granted
   - Create invitation → wait for expiration → attempt accept → MUST fail

2. AUTHORIZATION
   - Invitation for user@a.com → user@b.com attempts to accept → MUST fail
   - Invitation → accepter gets higher role than intended?
   - Invitation → can non-admin create invitations? (if restricted)

3. REPLAY & REUSE
   - Accept invitation → attempt to accept again → MUST fail (already used)
   - Invitation link → share with unauthorized party → MUST be single-use OR scoped to email
   - Revoked invitation → attempt to accept → MUST fail

4. LINK SECURITY
   - Invitation token → predictable pattern? (sequential, time-based, short)
   - Invitation link → accessible without authentication?
   - Invitation link → enumerate other invitation tokens?

5. RACE CONDITIONS
   - Simultaneous accept + revoke → which wins?
   - Multiple invitations to same user → accept all → multiple roles?
   - Invitation accept + workspace delete simultaneously

6. EDGE CASES
   - Invite to email that already has an account → account merge? New account?
   - Re-invite after explicit rejection
   - Invitation to self (inviter = invitee)
   - Invitation with admin role → invitee becomes admin of inviter's workspace
```

### Expected Anomalies
- Invitation token predictable or enumerable
- Expired invitation still acceptable
- Invitation not scoped to specific email
- Simultaneous accept + revoke creates phantom access
- Re-invitation after rejection doesn't check rejection state

---

## race_pack

**Precondition**: Target has any concurrent-access pattern on shared mutable state.

### Test Sequence

```
1. IDENTIFY RACE TARGETS
   Scan endpoint_map.md for:
   - Balance/credit operations (transfer, withdraw, deposit)
   - Counter operations (like, vote, view count)
   - State change operations (status update, approval, toggle)
   - Resource creation with uniqueness constraints (username, email)
   - Coupon/code redemption with single-use constraint

2. CLASSIC DOUBLE-SPEND
   Balance: $100
   → Send two simultaneous: POST /api/transfer {"amount": 100, "to": "attacker"}
   → Expected: one succeeds, one fails (balance insufficient)
   → Vulnerable: both succeed (balance goes to -$100, attacker gets $200)
   Tool: Python asyncio with aiohttp, or Turbo Intruder (Burp)

3. TOCTOU (Time-of-Check-Time-of-Use)
   → Check: GET /api/balance → 100
   → Use: POST /api/withdraw → 100
   → Window: between check and use, another request changes state
   → Vulnerable if: check and use are separate database operations without locking

4. IDEMPOTENCY VIOLATION
   → Send same request with same idempotency key → MUST return same response
   → Send same request WITHOUT idempotency key → behavior depends on implementation
   → Key reuse across different operations → MUST fail

5. CONCURRENT STATE TRANSITIONS
   → Resource in state A
   → Thread 1: transition A → B
   → Thread 2: transition A → C (mutually exclusive with B)
   → Expected: one fails
   → Vulnerable: both succeed, resource in inconsistent state

6. RACE IN MULTI-STEP FLOWS
   → Step 1: Create order (state: PENDING)
   → Step 2: Pay order (state: PAID)
   → Race: Thread 1 completes step 2 while Thread 2 cancels at step 1
   → Vulnerable: payment processed but order cancelled (refund needed but not triggered)
```

### Testing Tools

```python
# Minimal race condition test template
import asyncio
import aiohttp

async def race_request(session, url, data, headers):
    async with session.post(url, json=data, headers=headers) as resp:
        return await resp.json()

async def test_race(url, data, headers, n=10):
    async with aiohttp.ClientSession() as session:
        tasks = [race_request(session, url, data, headers) for _ in range(n)]
        results = await asyncio.gather(*tasks)
        # Analyze: how many succeeded? Any inconsistent state?
        return results
```

### Expected Anomalies
- Balance goes negative (double-spend)
- Counter incremented more than once per action
- Single-use code redeemed multiple times
- Uniqueness constraint bypassed (duplicate usernames)
- State machine enters impossible state (both approved and rejected)

---

## Pack Combination Guidelines

Most targets need multiple packs. Common combinations:

| Target Type | Recommended Packs |
|-------------|-------------------|
| SaaS with teams | workspace_pack + invite_pack + billing_pack |
| E-commerce | billing_pack + race_pack |
| Admin panel only | admin_pack |
| API with credits | billing_pack + race_pack |
| Social platform | invite_pack + workspace_pack + race_pack |
| DeFi protocol | race_pack (adapted for on-chain) + billing_pack (adapted for token flows) |

Always run `race_pack` last — it requires understanding from other packs to identify the best race targets.
