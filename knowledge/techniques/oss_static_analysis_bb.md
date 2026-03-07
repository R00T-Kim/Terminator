# OSS Static Analysis Bug Bounty — Lessons (Klaw 2nd Wave, 2026-03-07)

## Context
Aiven/Klaw (Java/Spring Boot) — 22 controllers audited via 3 parallel analysts.
5 submissions from source-only analysis (no live instance).

## VRT Selection Is Everything
- Same hardcoded JWT secret finding:
  - "Application-Level DoS" = P2 baseline
  - "Server Security Misconfiguration > Using Default Credentials" = **P1 baseline**
- **Always check bugcrowd.com/vulnerability-rating-taxonomy before selecting VRT**
- Match VRT to **root cause**, not to **impact demonstration**
- Hardcoded secret → "Using Default Credentials" (not DoS)
- Missing permission annotation → "Broken Access Control > Privilege Escalation"
- Cross-tenant query → "Broken Access Control > IDOR > Read Sensitive Information"

## Judge Simulation Before Submission
- Run adversarial judge review on every P1/P2 report before submitting
- Common judge attacks:
  1. "A:H without benchmark data" → remove speculative DoS claims
  2. "AC:L when comment says change it" → defend with FIRST guidance (AC = attack complexity, not deployment probability)
  3. "Property name conflation" → distinguish same literal vs same config chain
  4. "No auth" overstatement → "bypasses Spring Security, internal JWT check forgeable with known default"
  5. "IDOR secondary VRT" → taxonomy shopping, remove it

## What to Keep vs Remove After Judge Review
**Keep (defensible):**
- AC:L for hardcoded credentials (FIRST guidance)
- PR:N when secret is in public repo
- 3-layer remediation
- Root cause code trace
- PoC script as evidence

**Remove (speculative):**
- "measurable latency spikes" without benchmark
- "all tenants" without cross-tenant proof
- "stale authorization decisions" without auth bypass PoC
- Secondary VRT categories (taxonomy shopping)

## CVSS Conservatism
- A:H → A:L when cache flush is the only proven impact (no measured outage)
- 6.5 with P1 VRT is stronger than 8.2 with speculative A:H
- Let VRT determine priority, not CVSS inflation

## OSS Program Evidence Standards
- Live instance NOT required for OSS programs
- Sufficient evidence: source-to-sink code trace + PoC script + integration test reference
- MockMVC integration tests = strong evidence for Java/Spring projects
- Negative controls (invalid token rejected) strengthen the report

## Property Name Precision
- Docker env var `KLAW_CLUSTERAPI_ACCESS_BASE64_SECRET` ≠ Java property `klaw.core.app2app.base64.secret`
- Same literal value but different config chains
- State this explicitly to preempt judge criticism

## Multi-Finding Pipeline (22 Controllers → 8 Unique Findings)
1. Split analysis by category: request flow / IDOR / unauth (3 parallel analysts)
2. Cross-reference reports to deduplicate
3. Check each finding against already-submitted reports (R4 overlap caught by critic)
4. Bundle same-root-cause findings (R6: self-approval + routing gap)
5. Separate different-root-cause findings (R5/R6/R7 all standalone)

## Spring Boot Auth Pattern Recognition
- `@PermissionAllowed` = custom AOP annotation (not Spring Security RBAC)
- Missing annotation = no permission check at all
- `permitAll` in SecurityConfig = Spring Security bypass (but app-level checks may still exist)
- `findByUsernameIgnoreCase` vs `findFirstByTenantIdAndUsername` = global vs tenant-scoped JPA query
- Tenant-scoped method EXISTS but UNUSED = strong evidence of implementation omission
