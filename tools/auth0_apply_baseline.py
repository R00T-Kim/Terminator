#!/usr/bin/env python3
"""Apply a sanitized Auth0 baseline capture to the local rules summary.

This keeps secrets out of the checked-in rules file while replacing the live
auth/header placeholders with concrete header names and a sanitized curl
template derived from a successful captured request.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import date
from pathlib import Path


KEEP_HEADER_NAMES = (
    "accept",
    "content-type",
    "origin",
    "referer",
    "x-",
    "if-",
    "sec-fetch-",
    "csrf",
    "requested-with",
)


def load_capture(path: Path) -> dict:
    capture = json.loads(path.read_text())
    required = {"method", "url", "host", "path", "auth_headers", "mandatory_headers"}
    missing = sorted(required - set(capture))
    if missing:
        raise ValueError(f"baseline capture missing keys: {', '.join(missing)}")
    return capture


def keep_header(name: str) -> bool:
    lowered = name.lower()
    if lowered in {"user-agent", "accept-language", "accept-encoding", "priority"}:
        return False
    if lowered.startswith("sec-ch-"):
        return False
    return any(
        lowered == prefix or lowered.startswith(prefix)
        for prefix in KEEP_HEADER_NAMES
    )


def bullet_lines(items: list[str]) -> list[str]:
    return [f"- {item}" for item in items] if items else ["- none observed"]


def render_auth_section(capture: dict) -> str:
    auth_lines: list[str] = []
    if capture["auth_headers"]:
        auth_lines.append(
            "Observed from a successful researcher-environment request captured locally"
        )
        for header in capture["auth_headers"]:
            auth_lines.append(f"`{header['name']}: {header['value']}`")
    elif capture.get("cookie_names"):
        auth_lines.append(
            "Observed from a successful researcher-environment request using session cookies"
        )
        auth_lines.append(
            "Cookie names: `" + ", ".join(capture["cookie_names"]) + "`"
        )
    else:
        auth_lines.append("No explicit auth header was present in the captured request")

    auth_lines.extend(
        [
            f"Host: `{capture['host']}`",
            f"Path: `{capture['path']}`",
            'Discovered by: browser DevTools "Copy as cURL (bash)" in researcher environment',
            f"Verified: {date.today().isoformat()}",
        ]
    )
    return "\n".join(bullet_lines(auth_lines))


def render_headers_section(capture: dict) -> str:
    kept = [
        f"`{header['name']}: {header['value']}`"
        for header in capture["mandatory_headers"]
        if keep_header(header["name"])
    ]
    if capture.get("cookie_names"):
        kept.insert(
            0,
            "`Cookie: "
            + "; ".join(f"{name}=<value>" for name in capture["cookie_names"])
            + "`",
        )
    intro = [
        "Preserve the working request shape below when replaying manual tests",
        f"Derived from successful `{capture['method']}` baseline capture",
    ]
    return "\n".join(bullet_lines(intro + kept))


def render_curl_section(capture: dict, baseline_json: Path) -> str:
    lines = [
        f"# Sanitized from a successful request captured locally on {date.today().isoformat()}",
        f"# Source metadata: {baseline_json}",
        f'curl -i -X {capture["method"]} "{capture["url"]}" \\',
    ]

    auth_headers = capture.get("auth_headers", [])
    added_headers = False
    for header in auth_headers:
        lines.append(f'  -H "{header["name"]}: <captured_value>" \\')
        added_headers = True

    if capture.get("cookie_names"):
        cookie_value = "; ".join(f"{name}=<value>" for name in capture["cookie_names"])
        lines.append(f'  -H "Cookie: {cookie_value}" \\')
        added_headers = True

    for header in capture["mandatory_headers"]:
        if keep_header(header["name"]):
            lines.append(f'  -H "{header["name"]}: {header["value"]}" \\')
            added_headers = True

    if capture.get("body_present"):
        lines.append("  --data-raw '<redacted_body>'")
    elif added_headers:
        lines[-1] = lines[-1].rstrip(" \\")

    return (
        "Sanitized from a real successful request. Do not commit raw tokens or cookies.\n"
        "```bash\n"
        + "\n".join(lines)
        + "\n```\n"
        "**This curl template comes from a real successful request, but the sensitive values are redacted here. Keep the raw capture only in `targets/auth0/evidence/`.**"
    )


def replace_section(content: str, heading: str, new_body: str) -> str:
    pattern = rf"(?ms)^## {re.escape(heading)}\n.*?(?=^## |\Z)"
    replacement = f"## {heading}\n{new_body}\n\n"
    updated, count = re.subn(pattern, replacement, content)
    if count != 1:
        raise ValueError(f"could not replace section: {heading}")
    return updated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline-json",
        default="targets/auth0/evidence/baseline_capture.json",
        help="Sanitized baseline JSON from auth0_baseline_from_curl.py",
    )
    parser.add_argument(
        "--rules-file",
        default="targets/auth0/program_rules_summary.md",
        help="Rules summary file to update",
    )
    args = parser.parse_args()

    baseline_json = Path(args.baseline_json)
    rules_file = Path(args.rules_file)
    capture = load_capture(baseline_json)
    content = rules_file.read_text()

    content = replace_section(content, "Auth Header Format", render_auth_section(capture))
    content = replace_section(content, "Mandatory Headers", render_headers_section(capture))
    content = replace_section(
        content,
        "Verified Curl Template",
        render_curl_section(capture, baseline_json),
    )

    rules_file.write_text(content)
    print(f"UPDATED: {rules_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
