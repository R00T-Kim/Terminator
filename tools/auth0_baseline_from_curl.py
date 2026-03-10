#!/usr/bin/env python3
"""Extract Auth0 baseline metadata from a single 'Copy as cURL (bash)' command.

This helper does not replay traffic. It parses one captured request and writes a
sanitized baseline summary that can be used to fill program_rules_summary.md and
seed live testing notes.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
from pathlib import Path
from urllib.parse import parse_qsl, urlparse


SENSITIVE_HEADER_PATTERNS = (
    "authorization",
    "cookie",
    "x-auth",
    "token",
    "secret",
    "apikey",
)


def sanitize_header_value(name: str, value: str) -> str:
    lowered = name.lower()
    if any(pattern in lowered for pattern in SENSITIVE_HEADER_PATTERNS):
        if lowered == "cookie":
            cookie_names = []
            for cookie in value.split(";"):
                if "=" in cookie:
                    cookie_names.append(cookie.split("=", 1)[0].strip())
            return "COOKIE_NAMES: " + ", ".join(cookie_names[:20])
        return "<redacted>"
    if len(value) > 160:
        return value[:157] + "..."
    return value


def parse_curl(curl_text: str) -> dict:
    tokens = shlex.split(curl_text.strip())
    if not tokens or tokens[0] != "curl":
        raise ValueError("input does not look like a curl command")

    method = "GET"
    url = None
    headers: list[tuple[str, str]] = []
    body = None
    compressed = False

    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token in ("-X", "--request") and i + 1 < len(tokens):
            method = tokens[i + 1].upper()
            i += 2
            continue
        if token in ("-H", "--header") and i + 1 < len(tokens):
            raw = tokens[i + 1]
            if ":" in raw:
                name, value = raw.split(":", 1)
                headers.append((name.strip(), value.strip()))
            i += 2
            continue
        if token in ("--data", "--data-raw", "--data-binary", "--data-urlencode") and i + 1 < len(tokens):
            body = tokens[i + 1]
            if method == "GET":
                method = "POST"
            i += 2
            continue
        if token == "--compressed":
            compressed = True
            i += 1
            continue
        if not token.startswith("-") and url is None:
            url = token
            i += 1
            continue
        i += 1

    if not url:
        raise ValueError("no URL found in curl command")

    parsed = urlparse(url)
    query_keys = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]

    auth_headers = []
    mandatory_headers = []
    cookie_names = []
    for name, value in headers:
        lowered = name.lower()
        if lowered == "cookie":
            cookie_names = [
                item.split("=", 1)[0].strip()
                for item in value.split(";")
                if "=" in item
            ]
        if "authorization" in lowered or "token" in lowered or "auth" in lowered:
            auth_headers.append({"name": name, "value": sanitize_header_value(name, value)})
        else:
            mandatory_headers.append({"name": name, "value": sanitize_header_value(name, value)})

    body_preview = None
    if body:
        compact = re.sub(r"\s+", " ", body)
        body_preview = compact[:300] + ("..." if len(compact) > 300 else "")

    return {
        "method": method,
        "url": url,
        "scheme": parsed.scheme,
        "host": parsed.netloc,
        "path": parsed.path or "/",
        "query_keys": query_keys,
        "auth_headers": auth_headers,
        "mandatory_headers": mandatory_headers,
        "cookie_names": cookie_names,
        "content_type": next(
            (value for name, value in headers if name.lower() == "content-type"),
            None,
        ),
        "body_present": body is not None,
        "body_preview": body_preview,
        "compressed": compressed,
    }


def write_outputs(parsed: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "baseline_capture.json"
    md_path = output_dir / "baseline_capture_summary.md"

    json_path.write_text(json.dumps(parsed, indent=2, ensure_ascii=False) + "\n")

    lines = [
        "# Auth0 Baseline Capture Summary",
        "",
        f"- Method: `{parsed['method']}`",
        f"- URL: `{parsed['url']}`",
        f"- Host: `{parsed['host']}`",
        f"- Path: `{parsed['path']}`",
        f"- Query keys: `{', '.join(parsed['query_keys'])}`" if parsed["query_keys"] else "- Query keys: none",
        f"- Cookie names: `{', '.join(parsed['cookie_names'])}`" if parsed["cookie_names"] else "- Cookie names: none",
        f"- Content-Type: `{parsed['content_type']}`" if parsed["content_type"] else "- Content-Type: none",
        "",
        "## Auth Headers",
    ]

    if parsed["auth_headers"]:
        for header in parsed["auth_headers"]:
            lines.append(f"- `{header['name']}: {header['value']}`")
    else:
        lines.append("- none detected")

    lines.extend(["", "## Mandatory Headers"])
    if parsed["mandatory_headers"]:
        for header in parsed["mandatory_headers"]:
            lines.append(f"- `{header['name']}: {header['value']}`")
    else:
        lines.append("- none detected")

    lines.extend(["", "## Body Preview"])
    lines.append(parsed["body_preview"] or "no body")

    md_path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "curl_file",
        help="Path to a text file containing one 'Copy as cURL (bash)' command",
    )
    parser.add_argument(
        "--output-dir",
        default="targets/auth0/evidence",
        help="Directory where extracted baseline files will be written",
    )
    args = parser.parse_args()

    curl_file = Path(args.curl_file)
    curl_text = curl_file.read_text().strip()
    parsed = parse_curl(curl_text)
    write_outputs(parsed, Path(args.output_dir))
    print(f"WROTE: {Path(args.output_dir) / 'baseline_capture.json'}")
    print(f"WROTE: {Path(args.output_dir) / 'baseline_capture_summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
