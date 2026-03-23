# ENKI RedTeam Scenario Quick Checklist

Purpose: distill broad pentest checklists into a fast workflow for Red Team scenario style CTF problems.

## Use This For

- Web or API scenario challenges with accounts, roles, teams, invitations, credits, billing, admin features, or stateful flows
- Problems where the bug is likely in authorization, business logic, race handling, or workflow enforcement

## Do Not Waste Time On

- Platform or infrastructure attacks, DDoS, brute force, or noisy enumeration outside the challenge scope
- Huge generic scans before understanding the target's roles, states, and assets
- Chasing local fake flags or placeholder output

## First 10 Minutes

1. Identify the entrypoints.
   - Web pages, API endpoints, admin paths, invite links, reset flows, checkout flows, upload points
2. Identify the actors.
   - Unauthenticated, normal user, invited user, member, admin, service account
3. Identify the assets.
   - Session, token, workspace, project, invite token, coupon, credit, report, admin action, export
4. Identify the stateful flows.
   - Register, login, invite, accept, role change, create, approve, cancel, refund, transfer, delete

## Required Modeling Before Exploitation

Build these four artifacts mentally or in notes before serious testing:

- Trust boundaries: unauth -> auth, user -> admin, tenant A -> tenant B, public -> internal
- Role matrix: who should read, write, invite, transfer, approve, delete
- State machine: entry state, transitions, terminal states, rollback paths
- Invariants: explicit statements you can try to break

Good invariant examples:

- User A cannot read or modify User B's resource by changing only an identifier
- Expired or revoked invitations cannot be accepted
- Downgraded users lose premium actions immediately
- Admin role revocation invalidates active sessions immediately

## Highest ROI Bug Classes

Prioritize in this order unless the challenge clearly points elsewhere:

1. Business logic and workflow bypass
2. IDOR and BOLA
3. Privilege escalation and broken authorization
4. JWT or token validation flaws
5. Race conditions and idempotency bugs
6. CORS and CSRF chaining
7. SSRF and internal reachability
8. XSS, SSTI, SQLi, upload bugs when a sink is visible

## Symptom To Test Map

### Workspace, Team, Tenant

- Try cross-tenant resource access with guessed or reused IDs
- Promote and demote a user, then reuse old session or token
- Transfer ownership and check whether the former owner still keeps privileged actions

### Invite, Share, Approval

- Accept expired, revoked, or already-used invitations
- Accept an invite as the wrong account or without the intended email identity
- Race accept vs revoke, or accept the same token twice

### Billing, Coupon, Credit, Score

- Tamper amount, plan, coupon, quantity, or refund value
- Replay the same payment or redemption request
- Send concurrent spend or upgrade requests against the same balance or state

### Admin, Moderation, Audit

- Access admin endpoints directly as low privilege
- Add elevated fields in API bodies such as `role`, `is_admin`, `credits`
- Check whether impersonation, role revoke, delete, or disable actions leave stale access

### Auth, Token, Session

- Unauthenticated access to protected endpoints
- Token reuse across role changes
- JWT `alg`, `kid`, `jku`, or weak verification assumptions when the app exposes key material
- Session fixation or failure to rotate session after login

### CORS, OAuth, Redirect

- Wildcard or reflected origin handling on sensitive endpoints
- Credentialed CORS with attacker-controlled origin
- OAuth redirect, callback, or state validation gaps
- Chain CORS plus auth code or token exposure

## Workflow Packs To Apply

Use the closest pack and adapt fast:

- `workspace_pack`: teams, organizations, tenants, shared resources
- `invite_pack`: link invite, email invite, referral, approval flows
- `admin_pack`: admin console, impersonation, audit, user management
- `billing_pack`: subscription, coupon, credit, refund, score economy
- `race_pack`: simultaneous state changes on shared mutable state

## Minimal Evidence Standard

Save enough to prove the bug and write the write-up fast:

- Request and response pair
- Actor or role used
- Before and after state
- Timestamp when race or replay matters
- Exact invariant that was violated
- Why the behavior is not just intended design

## Write-Up Skeleton

1. Initial state
2. Expected invariant
3. Action taken
4. Observed broken state
5. Security impact
6. Reliable reproduction conditions

## Practical Rule For ENKI Style Scenarios

If the feature looks "normal" but depends on sequence, role, or ownership, assume the challenge is in the workflow, not in the payload.

## Reference Sources

- External breadth reference: https://github.com/Voorivex/pentest-guide
- Local workflow packs: `.claude/agents/_reference/workflow_packs.md`
- Local web technique notes: `knowledge/techniques/web_ctf_techniques.md`
- Local orchestration rules: `CLAUDE.md`
