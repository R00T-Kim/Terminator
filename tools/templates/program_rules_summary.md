# Program Rules Summary — <TARGET_NAME>

## Platform
<REQUIRED: Platform name (FindTheGap, Bugcrowd, H1, Immunefi, etc.)>

## Auth Header Format
<REQUIRED: Exact auth header format used in API requests>
Example: `IdToken: <COGNITO_ID_TOKEN>` (NOT `Authorization: Bearer`)
- Discovered by: <scout intercept / Frida / mitmproxy / manual test>
- Verified: <date, by which agent>

## Mandatory Headers
<REQUIRED: All required headers for valid requests — copy exact values>
Example:
- `bugbounty: [FindtheGap]security_test_c16508a5-ebcb-4d0f-bf7a-811668fbaa44`
- `Content-Type: application/json`

## Known Issues (Exclude from Analysis)
<REQUIRED: List of known issues that are already reported or acknowledged by the program>
1. (Copy from program page — findings matching these = wasted tokens)
2.
3.

## Already Submitted Reports (Exclude from Analysis)
<REQUIRED: List of endpoints/vulns from already-submitted reports in this engagement>
1. (Update after each submission — prevents overlap)
2.

## Exclusion List (Out of Scope)
<REQUIRED: Vulnerability types explicitly excluded by the program>
1. (Copy exact exclusion text from program page)
2.
3.

## Submission Rules
<REQUIRED: Platform-specific submission rules>
- Bundling: <REQUIRED: e.g., "연계 가능한 취약점은 하나의 시나리오로 구성하여, 하나의 리포트로 제출">
- CVSS version: <REQUIRED: 3.1 or 4.0>
- Language: <REQUIRED: Korean, English, etc.>
- Report format: <REQUIRED: Platform-specific format requirements>
- Max bounty: <REQUIRED: e.g., "Critical 100M KRW, High 30M KRW">

## Verified Curl Template
<REQUIRED: A WORKING curl command that demonstrates correct auth — copy from actual successful test>
```bash
curl -s "https://api.example.com/endpoint" \
  -H "<auth_header>: <token>" \
  -H "<mandatory_header>: <value>"
```
**This curl MUST have been tested and returned 200. All agents MUST use this format.**
