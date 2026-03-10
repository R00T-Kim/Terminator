#!/usr/bin/env python3
"""Low-noise public recon collector for Auth0 by Okta.

Collects only publicly reachable metadata from Bugcrowd-listed in-scope targets,
official documentation, and public SDK repositories. No authenticated traffic,
credential retrieval, fuzzing, or high-rate requests are performed.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


USER_AGENT = "Mozilla/5.0 (compatible; Auth0PublicRecon/1.0)"

SURFACE_URLS = [
    "https://config.cic-bug-bounty.auth0app.com",
    "https://manage.cic-bug-bounty.auth0app.com",
    "https://marketplace.auth0.com",
    "https://dashboard.fga.dev",
    "https://api.us1.fga.dev",
    "https://customers.us1.fga.dev",
    "https://play.fga.dev",
    "https://auth0.com",
    "https://samltool.io",
    "https://webauthn.me",
    "https://openidconnect.net",
    "https://jwt.io",
    "https://auth0.net",
]

DOC_URLS = {
    "authentication_api": "https://auth0.com/docs/api/authentication",
    "management_api": "https://auth0.com/docs/api/management/v2",
    "dashboard_docs": "https://auth0.com/docs/dashboard",
    "lock_docs": "https://auth0.com/docs/libraries/lock/v11",
    "auth0_js_docs": "https://auth0.com/docs/libraries/auth0js/v9",
    "spa_js_docs": "https://auth0.com/docs/libraries/auth0-spa-js",
    "mfa_docs": "https://auth0.com/docs/multifactor-authentication",
    "fga_docs": "https://docs.fga.dev/",
    "fga_api_docs": "https://docs.fga.dev/api/service/",
}

SDK_REPOS = {
    "auth0_js": "https://github.com/auth0/auth0.js",
    "lock": "https://github.com/auth0/lock",
    "auth0_spa_js": "https://github.com/auth0/auth0-spa-js",
    "auth0_net": "https://github.com/auth0/Auth0.Net",
    "nextjs_auth0": "https://github.com/auth0/nextjs-auth0",
    "auth0_java": "https://github.com/auth0/auth0-java",
    "react_native_auth0": "https://github.com/auth0/react-native-auth0",
    "auth0_php": "https://github.com/auth0/auth0-php",
    "passport_wsfed_saml2": "https://github.com/auth0/passport-wsfed-saml2",
}

ROUTE_KEYWORDS = (
    "oauth",
    "oidc",
    "saml",
    "tenant",
    "member",
    "invite",
    "organization",
    "connection",
    "client",
    "application",
    "guardian",
    "mfa",
    "authorize",
    "token",
    "relation",
    "store",
    "tuple",
    "model",
    "user",
    "role",
)


def fetch(url: str) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8", errors="replace")
            return {
                "url": url,
                "status": response.status,
                "headers": dict(response.headers.items()),
                "body": body,
            }
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {
            "url": url,
            "status": exc.code,
            "headers": dict(exc.headers.items()),
            "body": body,
        }
    except URLError as exc:
        return {
            "url": url,
            "status": None,
            "headers": {},
            "body": "",
            "error": str(exc),
        }


def extract_title(body: str) -> str:
    match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()


def extract_meta_description(body: str) -> str:
    match = re.search(
        r'<meta\s+name="description"\s+content="(.*?)"',
        body,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()


def interesting_headers(headers: dict[str, str]) -> dict[str, str]:
    allow = {
        "content-type",
        "content-security-policy",
        "strict-transport-security",
        "server",
        "cache-control",
        "x-frame-options",
    }
    return {
        key: value[:200]
        for key, value in headers.items()
        if key.lower() in allow
    }


def extract_assets(body: str) -> list[str]:
    assets = sorted(
        {
            match
            for match in re.findall(r"https://[^\"'\s>]+", body)
            if match.endswith(".js") or match.endswith(".css")
        }
    )
    return assets[:50]


def extract_route_hints(body: str) -> list[str]:
    hints: list[str] = []
    for match in re.finditer(r"/[A-Za-z0-9_./?=&:-]{8,}", body):
        route = match.group(0)
        lowered = route.lower()
        if any(keyword in lowered for keyword in ROUTE_KEYWORDS) and route not in hints:
            hints.append(route)
    return hints[:120]


def classify_body(body: str, headers: dict[str, str]) -> str:
    content_type = headers.get("Content-Type", "").lower()
    if "application/json" in content_type:
        return "json"
    if "<html" in body.lower():
        return "html"
    if body.strip():
        return "text"
    return "empty"


def build_report() -> dict[str, Any]:
    report: dict[str, Any] = {
        "target": "auth0",
        "program_url": "https://bugcrowd.com/engagements/auth0-okta",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "network_public_recon_low_noise",
        "pipeline_phases_completed": ["phase_0_rules", "phase_1_public_surface_seed"],
        "surface_pages": [],
        "official_reference_pages": [],
        "sdk_repositories": [],
        "notes": [
            "Public-only collection. No authenticated requests, researcher credentials, or automated scanning performed.",
            "Use these results to seed endpoint_map.md, recon_notes.md, and manual tenant-boundary testing.",
        ],
    }

    for url in SURFACE_URLS:
        data = fetch(url)
        report["surface_pages"].append(
            {
                "url": url,
                "status": data["status"],
                "title": extract_title(data["body"]),
                "description": extract_meta_description(data["body"]),
                "headers": interesting_headers(data["headers"]),
                "body_kind": classify_body(data["body"], data["headers"]),
                "asset_urls": extract_assets(data["body"]),
                "route_hints": extract_route_hints(data["body"]),
            }
        )

    for name, url in DOC_URLS.items():
        data = fetch(url)
        report["official_reference_pages"].append(
            {
                "name": name,
                "url": url,
                "status": data["status"],
                "title": extract_title(data["body"]),
                "description": extract_meta_description(data["body"]),
                "headers": interesting_headers(data["headers"]),
            }
        )

    for name, url in SDK_REPOS.items():
        data = fetch(url)
        report["sdk_repositories"].append(
            {
                "name": name,
                "url": url,
                "status": data["status"],
                "title": extract_title(data["body"]),
                "description": extract_meta_description(data["body"]),
                "body_kind": classify_body(data["body"], data["headers"]),
            }
        )

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default="targets/auth0/recon_report.json",
        help="Output path for the generated JSON report",
    )
    args = parser.parse_args()

    report = build_report()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(f"WROTE: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
