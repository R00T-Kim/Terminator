---
target: Vercel agent-skills (vercel-deploy-claimable)
finding: unauth_deploy_endpoint_and_env_secret_in_tarball
date_submitted: 2026-02-11
date_resolved: 2026-02-13
platform: HackerOne
report_id: 3548853
verdict: Closed / Informative
severity_claimed: High (7.8) / CVSS 4.0 6.1
bounty: 0
---

# Triage Feedback: Vercel agent-skills — unauthenticated deploy + .env in tarball

## Our Prediction
- Verdict: SUBMIT
- Severity: High
- Key claim: claude-skills-deploy.vercel.com/api/deploy has no auth; deploy.sh:210 tarball only excludes node_modules/.git, silently includes .env; AI-agent users can't audit packaging.

## Actual Outcome
- Status: CLOSED (Informative)
- Triager (@h1_analyst_rio): "Key attack scenarios described require successful prompt injection against AI agents, which introduces significant preconditions and uncertainty around exploitability. Additionally, critical claims about credential exposure remain unverified without live testing to confirm whether uploaded files are actually served publicly. The conditional nature of these attacks, combined with unverified assumptions, means the described behavior lacks demonstrated security impact."
- Resolution Time: 2 days

## Mismatch Analysis
- Category: PREREQ_UNDER (prompt-injection prerequisite) + EVIDENCE_WEAK (unverified live claim)
- Root Cause: Two problems stacked:
  1. Attack chain started with "AI agent follows malicious instructions that make it deploy attacker content" — this is a prompt-injection prerequisite that we did not independently demonstrate. Triagers universally kill chains that begin with "after successful prompt injection".
  2. The .env-in-tarball finding was never tested live against the deployed preview URL. Our report said "if these files are served publicly" — conditional, not proven.
- Also, in the report body we self-qualified the endpoint as "may be intentionally designed as an open, claimable sandbox" — giving the triager the exact phrase to close on.
- Which destruction test would have caught this: Gate 2 Section A Q2 (PROVEN vs INFERRED) + A Q1 (LIVE vs MOCK).

## Rule Update
- Mode affected: Gate 2 Section A + new "prompt-injection-precondition" check
- Specific change:
  - Add Gate 1 Q6 (new): "PROMPT-INJECTION PREREQ CHECK". If the chain requires an LLM/agent to act maliciously, the prompt-injection step itself must be independently demonstrated with a concrete malicious-input→agent-response→vulnerable-action trace. Otherwise auto-KILL as speculative.
  - Gate 2 Section A Q2 must reject any "if … then …" impact phrasing. Impact claims must be in past tense referencing captured artifacts: "curl -O proved tarball contained .env; wget https://<preview-url>/.env returned 200 + secret_value X".
  - For AI-agent-tooling programs (Vercel agent-skills, Anthropic skills, MCP servers, langchain-ish), require live end-to-end chain: attacker input → agent → deployed artifact → exfil — all captured.
- Confidence: HIGH
