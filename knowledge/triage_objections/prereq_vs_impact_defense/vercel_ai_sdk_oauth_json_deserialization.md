---
target: Vercel AI SDK (vercel/ai) v6.0.78
finding: unsafe_json_deserialization_mcp_oauth_token_override
date_submitted: 2026-02-11
date_resolved: 2026-02-16
platform: HackerOne
report_id: 3547320
verdict: Closed / Informative
severity_claimed: High (8.8)
bounty: 0
---

# Triage Feedback: Vercel AI SDK — MCP/OAuth JSON deserialization

## Our Prediction
- Verdict: SUBMIT
- Severity: High CVSS 4.0 7.7
- Key claim: Spread operator at oauth.ts:775-778 lets attacker-controlled refresh_token overwrite original; .passthrough() schemas in OAuthProtectedResourceMetadataSchema, OAuthMetadataSchema, OpenIdProviderMetadataSchema permit property injection; 22 production sites use JSON.parse/response.json() despite project's own CLAUDE.md forbidding it.

## Actual Outcome
- Status: CLOSED (Informative)
- Triager (@h1_analyst_rio): "The issues you've identified require an attacker to control either the MCP server or OAuth endpoints that the application connects to. In legitimate deployment scenarios, these endpoints are typically trusted services under the application owner's control. The spread operator behavior in oauth.ts line 775-778, while technically allowing property overwriting, occurs within a controlled authentication flow where the OAuth server is expected to be trusted. Additionally, the property injection via .passthrough() schemas would only affect applications that explicitly check for arbitrary properties on metadata objects, which represents a misuse of the parsed data rather than a vulnerability in the parsing itself."
- Resolution Time: 5 days

## Mismatch Analysis
- Category: PREREQ_UNDER (threat model starts with compromised-trusted-component)
- Root Cause: Our threat model assumed a hostile MCP server / hostile OAuth discovery endpoint. Vendor's documented threat model treats both as trusted third parties the application owner chose. Without a chain demonstrating how an attacker becomes that trusted component (e.g., MCP server registry hijack, DNS takeover, SSRF-to-OAuth-discovery chain), the root finding has no attacker-controlled input boundary. We also presented 22 "policy violations" which are coding-standard issues, not exploitable bugs — triager treats such volume as defense-in-depth noise.
- Which destruction test would have caught this: Gate 1 Q4 (PREREQUISITE CHECK) — "is the attacker prerequisite ≥ impact?". Answer here: attacker needs to already control the server we're consuming → prerequisite equals or exceeds the resulting impact.

## Rule Update
- Mode affected: Gate 1 Q4 + threat-modeler artifact
- Specific change:
  - threat-modeler must explicitly label every external endpoint/component as TRUSTED or UNTRUSTED per vendor docs (not per attacker-wish). Any finding whose root cause sits behind a TRUSTED boundary starts at E4 / explore-only.
  - Policy-violation counts (CLAUDE.md / docs / linter rule violations) may not serve as primary finding evidence. They are allowed as Finding N (supporting) only when Finding 1 has E1/E2 evidence.
  - Add a "trusted-component-compromise assumption" red flag: if the attack narrative includes "attacker sets up a hostile MCP/OAuth/CA/registry/plugin" without a chain proving takeover is feasible, auto-STRENGTHEN at Gate 2.
- Confidence: HIGH
