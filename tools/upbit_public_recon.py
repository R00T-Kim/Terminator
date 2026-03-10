#!/usr/bin/env python3
"""Low-noise public recon collector for Upbit.

Collects only publicly accessible metadata from official scope pages and
documentation pages. This script is intended for PatchDay-safe preparation and
does not perform active fuzzing or authenticated testing.
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


USER_AGENT = "Mozilla/5.0 (compatible; UpbitPublicRecon/1.0)"

SURFACE_URLS = [
    "https://www.upbit.com",
    "https://upbit.com/exchange",
    "https://upbit.com/nft",
    "https://upbit.com/staking",
    "https://sg.upbit.com",
    "https://id.upbit.com",
    "https://th.upbit.com",
]

DOC_URLS = {
    "trading_pairs": "https://docs.upbit.com/kr/reference/list-trading-pairs",
    "deposits": "https://docs.upbit.com/kr/reference/list-deposits",
    "withdrawals": "https://docs.upbit.com/kr/reference/list-withdrawals",
    "orders_by_ids": "https://docs.upbit.com/kr/reference/list-orders-by-ids",
}

BUNDLE_TARGETS = {
    "core_web": "https://upbit-web-dist.upbit.com/upbit-web/sri-v2-KR_PC-1ce4f9d3-bundle-6d2cfae082069da4d64d.js",
    "nft_web": "https://cdn.upbit.com/upbit-nft/assets/index-C4s-3l20.js",
}

SECONDARY_HOSTS = [
    "https://id-kyc.upbit.com",
    "https://sg-kyc.upbit.com",
    "https://th-kyc.upbit.com",
]

ROUTE_PROBES = {
    "orders_by_ids_doc": "https://docs.upbit.com/kr/reference/list-orders-by-ids",
    "withdrawals_doc": "https://docs.upbit.com/kr/reference/list-withdrawals",
    "deposits_doc": "https://docs.upbit.com/kr/reference/list-deposits",
    "kr_withdrawals_route": "https://upbit.com/withdrawals",
    "kr_deposits_route": "https://upbit.com/deposits",
    "kr_kyc_user_level_route": "https://upbit.com/kycAuth/userLevel",
    "kr_order_buy_route": "https://upbit.com/detail/order/buy",
    "kr_order_sell_route": "https://upbit.com/detail/order/sell",
    "nft_collection_offers_route": "https://upbit.com/nx/v1/collection-offers/",
    "nft_my_offers_route": "https://upbit.com/nft/my/offers",
    "nft_my_trades_route": "https://upbit.com/nft/my/trades",
    "nft_my_wallets_route": "https://upbit.com/nft/my/wallets",
    "nft_product_route": "https://upbit.com/nft/marketplace/product/",
    "nft_collection_route": "https://upbit.com/nft/marketplace/collection/",
    "nft_sns_verification_route": "https://upbit.com/nft/sns-connect/verification",
}

ROUTE_KEYWORDS = (
    "order",
    "withdraw",
    "deposit",
    "staking",
    "nft",
    "wallet",
    "auth",
    "kyc",
    "trade",
    "offer",
    "gift",
    "collection",
    "bid",
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
        "cf-cache-status",
        "set-cookie",
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
    for match in re.finditer(r"/[A-Za-z0-9_./?-]{8,}", body):
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
        "target": "upbit",
        "program_url": "https://patchday.io/dunamu/upbit",
        "scope_url": "https://patchday.io/dunamu/upbit/scope",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "network_public_recon_low_noise",
        "pipeline_phases_completed": ["phase_0_rules", "phase_1_public_surface_seed"],
        "surface_pages": [],
        "official_reference_pages": [],
        "bundle_hints": {},
        "secondary_hosts": [],
        "route_probes": [],
        "notes": [
            "Public-only collection. No authenticated requests or fuzzing performed.",
            "Use results as a seed for endpoint_map.md, recon_notes.md, and manual Phase 1 testing.",
        ],
        "recon_notes_file": "recon_notes.md",
    }

    for url in SURFACE_URLS:
        data = fetch(url)
        report["surface_pages"].append(
            {
                "url": url,
                "status": data["status"],
                "title": extract_title(data["body"]),
                "headers": interesting_headers(data["headers"]),
                "asset_urls": extract_assets(data["body"]),
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
            }
        )

    for name, url in BUNDLE_TARGETS.items():
        data = fetch(url)
        report["bundle_hints"][name] = {
            "url": url,
            "status": data["status"],
            "route_hints": extract_route_hints(data["body"]),
        }

    for url in SECONDARY_HOSTS:
        data = fetch(url)
        report["secondary_hosts"].append(
            {
                "url": url,
                "status": data["status"],
                "title": extract_title(data["body"]),
                "headers": interesting_headers(data["headers"]),
                "body_kind": classify_body(data["body"], data["headers"]),
            }
        )

    for name, url in ROUTE_PROBES.items():
        data = fetch(url)
        report["route_probes"].append(
            {
                "name": name,
                "url": url,
                "status": data["status"],
                "title": extract_title(data["body"]),
                "headers": interesting_headers(data["headers"]),
                "body_kind": classify_body(data["body"], data["headers"]),
            }
        )

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default="targets/upbit/recon_report.json",
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
