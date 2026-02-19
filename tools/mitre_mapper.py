#!/usr/bin/env python3
"""MITRE CVE→CWE→CAPEC→ATT&CK Mapper for Terminator pipeline."""

import argparse
import json
import sys
import time
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

SCRIPT_DIR = Path(__file__).parent
DATA_DIR = SCRIPT_DIR / "data"
CWE_CAPEC_MAP_FILE = DATA_DIR / "cwe_capec_map.json"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT_DELAY = 6  # seconds between requests (5 req/30s without API key)
REQUEST_TIMEOUT = 15

# Well-known CVE→CWE offline fallback (for --offline mode or NVD outage)
KNOWN_CVE_CWE: dict[str, list[str]] = {
    "CVE-2021-44228": ["CWE-917", "CWE-502", "CWE-20", "CWE-400"],  # Log4Shell
    "CVE-2021-45046": ["CWE-917"],                                   # Log4j follow-up
    "CVE-2021-45105": ["CWE-400"],                                   # Log4j DoS
    "CVE-2021-44832": ["CWE-20"],                                    # Log4j arbitrary code exec
    "CVE-2023-44487": ["CWE-400"],                                   # HTTP/2 Rapid Reset
    "CVE-2021-26855": ["CWE-918"],                                   # Exchange ProxyLogon SSRF
    "CVE-2021-26857": ["CWE-502"],                                   # Exchange deserialization
    "CVE-2021-34473": ["CWE-918"],                                   # Exchange ProxyShell
    "CVE-2022-22965": ["CWE-94"],                                    # Spring4Shell RCE
    "CVE-2022-1388":  ["CWE-306"],                                   # F5 BIG-IP auth bypass
    "CVE-2022-26134": ["CWE-917"],                                   # Confluence OGNL injection
    "CVE-2021-21985": ["CWE-20"],                                    # VMware vCenter RCE
    "CVE-2020-1472":  ["CWE-306"],                                   # Zerologon
    "CVE-2019-19781": ["CWE-22"],                                    # Citrix path traversal
    "CVE-2021-27101": ["CWE-89"],                                    # Accellion SQLi
    "CVE-2021-3156":  ["CWE-787"],                                   # sudo heap overflow
    "CVE-2022-0847":  ["CWE-787"],                                   # Dirty Pipe
    "CVE-2021-4034":  ["CWE-787"],                                   # PwnKit
    "CVE-2023-23397": ["CWE-287"],                                   # Outlook NTLM auth bypass
    "CVE-2023-20198": ["CWE-287"],                                   # Cisco IOS XE auth bypass
    "CVE-2023-4966":  ["CWE-119"],                                   # Citrix Bleed
    "CVE-2023-34362": ["CWE-89"],                                    # MOVEit SQLi
    "CVE-2024-3400":  ["CWE-77"],                                    # PAN-OS command injection
}


def load_cwe_capec_map() -> dict:
    """Load the local CWE→CAPEC→ATT&CK mapping file."""
    if not CWE_CAPEC_MAP_FILE.exists():
        print(f"[ERROR] Mapping file not found: {CWE_CAPEC_MAP_FILE}", file=sys.stderr)
        sys.exit(1)
    with open(CWE_CAPEC_MAP_FILE, "r") as f:
        return json.load(f)


def fetch_cve_from_nvd(cve_id: str) -> dict:
    """
    Fetch CVE details from NVD API 2.0.
    Returns parsed JSON response or empty dict on failure.
    """
    url = f"{NVD_API_BASE}?cveId={cve_id}"
    headers = {
        "Accept": "application/json",
        "User-Agent": "Terminator-MITRE-Mapper/1.0",
    }
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=REQUEST_TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data
    except HTTPError as e:
        print(f"[WARN] NVD API HTTP error for {cve_id}: {e.code} {e.reason}", file=sys.stderr)
        return {}
    except URLError as e:
        print(f"[WARN] NVD API unreachable (offline mode): {e.reason}", file=sys.stderr)
        return {}
    except Exception as e:
        print(f"[WARN] Unexpected error fetching {cve_id}: {e}", file=sys.stderr)
        return {}


def parse_cve_details(nvd_response: dict, cve_id: str) -> dict:
    """
    Extract description, CVSS score, and other metadata from NVD response.
    Returns a dict with 'description', 'cvss_score', 'cvss_version'.
    """
    result = {
        "description": "No description available",
        "cvss_score": None,
        "cvss_version": None,
        "published": None,
    }
    vulnerabilities = nvd_response.get("vulnerabilities", [])
    if not vulnerabilities:
        return result

    cve_data = vulnerabilities[0].get("cve", {})

    # Description
    descriptions = cve_data.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            result["description"] = desc.get("value", "No description available")
            break

    # Published date
    result["published"] = cve_data.get("published", None)

    # CVSS score (prefer v3.1, fallback to v3.0, then v2)
    metrics = cve_data.get("metrics", {})
    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            result["cvss_score"] = cvss_data.get("baseScore")
            result["cvss_version"] = cvss_data.get("version", version_key)
            break

    return result


def extract_cwes(nvd_response: dict) -> list:
    """
    Extract CWE IDs from NVD CVE response.
    Returns list of CWE IDs like ['CWE-79', 'CWE-89'].
    """
    cwes = []
    vulnerabilities = nvd_response.get("vulnerabilities", [])
    if not vulnerabilities:
        return cwes

    cve_data = vulnerabilities[0].get("cve", {})
    weaknesses = cve_data.get("weaknesses", [])

    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-") and value != "CWE-noinfo" and value != "CWE-Other":
                if value not in cwes:
                    cwes.append(value)

    return cwes


def map_cwe_to_capec(cwe_id: str, mapping: dict) -> list:
    """
    Map a CWE ID to CAPEC entries using the local mapping.
    Returns list of {'capec_id': ..., 'name': ...} dicts.
    """
    cwe_to_capec = mapping.get("cwe_to_capec", {})
    return cwe_to_capec.get(cwe_id, [])


def map_cwe_to_atlas(cwe_id: str, mapping: dict) -> list:
    """
    Map a CWE ID to MITRE ATLAS techniques using the local mapping.
    Returns list of {'technique_id': ..., 'name': ...} dicts.
    """
    cwe_to_atlas = mapping.get("cwe_to_atlas", {})
    return cwe_to_atlas.get(cwe_id, [])


def get_atlas_detail(technique_id: str, mapping: dict) -> dict:
    """Get ATLAS technique metadata (tactic, url) from mapping."""
    atlas_techniques = mapping.get("atlas_techniques", {})
    return atlas_techniques.get(technique_id, {})


def map_capec_to_attack(capec_id: str, mapping: dict) -> list:
    """
    Map a CAPEC ID to ATT&CK techniques using the local mapping.
    Returns list of {'technique_id': ..., 'name': ...} dicts.
    """
    capec_to_attack = mapping.get("capec_to_attack", {})
    return capec_to_attack.get(capec_id, [])


def build_chain(cve_id: str, mapping: dict, nvd_response: dict, include_atlas: bool = False) -> dict:
    """
    Build the full CVE→CWE→CAPEC→ATT&CK chain for a single CVE.
    Returns a structured dict with the complete taxonomy chain.
    """
    cve_details = parse_cve_details(nvd_response, cve_id)
    cwes = extract_cwes(nvd_response)
    offline = not bool(nvd_response)

    # Offline fallback: use well-known CVE→CWE table
    if not cwes and offline:
        cwes = KNOWN_CVE_CWE.get(cve_id.upper(), [])

    chain = {
        "cve_id": cve_id,
        "description": cve_details["description"],
        "cvss_score": cve_details["cvss_score"],
        "cvss_version": cve_details["cvss_version"],
        "published": cve_details["published"],
        "offline": offline,
        "cwes": [],
    }

    # If no CWEs found at all, return empty chain
    if not cwes:
        chain["cwes"] = []
        return chain

    for cwe_id in cwes:
        capec_entries = map_cwe_to_capec(cwe_id, mapping)
        cwe_node = {
            "cwe_id": cwe_id,
            "capecs": [],
        }

        # Deduplicate ATT&CK techniques across CAPECs
        seen_techniques = set()
        for capec in capec_entries:
            attack_techniques = map_capec_to_attack(capec["capec_id"], mapping)
            # Deduplicate within this CAPEC
            unique_techniques = []
            for tech in attack_techniques:
                if tech["technique_id"] not in seen_techniques:
                    seen_techniques.add(tech["technique_id"])
                    unique_techniques.append(tech)

            cwe_node["capecs"].append({
                "capec_id": capec["capec_id"],
                "name": capec["name"],
                "attack_techniques": unique_techniques,
            })

        # ATLAS mapping (AI/ML threat taxonomy)
        if include_atlas:
            atlas_entries = map_cwe_to_atlas(cwe_id, mapping)
            atlas_enriched = []
            for entry in atlas_entries:
                detail = get_atlas_detail(entry["technique_id"], mapping)
                atlas_enriched.append({
                    "technique_id": entry["technique_id"],
                    "name": entry["name"],
                    "tactic": detail.get("tactic", "Unknown"),
                    "url": detail.get("url", ""),
                })
            cwe_node["atlas_techniques"] = atlas_enriched

        chain["cwes"].append(cwe_node)

    return chain


def format_text(chain: dict) -> str:
    """Format a chain dict as human-readable text output."""
    lines = []
    cve_id = chain["cve_id"]
    desc = chain["description"]
    # Truncate long descriptions
    if len(desc) > 100:
        desc = desc[:97] + "..."

    score_str = ""
    if chain.get("cvss_score"):
        score_str = f" [CVSS {chain['cvss_version']}: {chain['cvss_score']}]"

    offline_str = " (OFFLINE - NVD data unavailable)" if chain.get("offline") else ""
    lines.append(f"{cve_id}: {desc}{score_str}{offline_str}")

    if not chain["cwes"]:
        lines.append("  [!] No CWE mappings found in NVD or local database")
        return "\n".join(lines)

    for cwe_node in chain["cwes"]:
        lines.append(f"  CWE: {cwe_node['cwe_id']}")

        if not cwe_node["capecs"]:
            lines.append(f"    [!] No CAPEC mapping for {cwe_node['cwe_id']}")
            continue

        for capec in cwe_node["capecs"]:
            lines.append(f"    CAPEC: {capec['capec_id']} ({capec['name']})")

            if not capec["attack_techniques"]:
                lines.append(f"      [!] No ATT&CK mapping for {capec['capec_id']}")
                continue

            for tech in capec["attack_techniques"]:
                lines.append(f"      ATT&CK: {tech['technique_id']} ({tech['name']})")

        # ATLAS techniques (if present)
        atlas_techs = cwe_node.get("atlas_techniques", [])
        if atlas_techs:
            for atech in atlas_techs:
                tactic = atech.get("tactic", "")
                tactic_str = f" [{tactic}]" if tactic else ""
                lines.append(f"    ATLAS: {atech['technique_id']} ({atech['name']}){tactic_str}")

    return "\n".join(lines)


def process_cve(cve_id: str, mapping: dict, verbose: bool, index: int, total: int) -> dict:
    """
    Fetch and process a single CVE. Handles rate limiting.
    Returns the chain dict.
    """
    cve_id = cve_id.upper().strip()

    if verbose and total > 1:
        print(f"[{index}/{total}] Fetching {cve_id} from NVD...", file=sys.stderr)
    elif verbose:
        print(f"Fetching {cve_id} from NVD...", file=sys.stderr)

    nvd_response = fetch_cve_from_nvd(cve_id)

    # Rate limiting: wait between requests
    if index < total:
        time.sleep(RATE_LIMIT_DELAY)

    return build_chain(cve_id, mapping, nvd_response)


def main():
    parser = argparse.ArgumentParser(
        description="MITRE CVE→CWE→CAPEC→ATT&CK Mapper for Terminator pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 mitre_mapper.py CVE-2021-44228
  python3 mitre_mapper.py CVE-2021-44228 --json
  python3 mitre_mapper.py CVE-2021-44228 CVE-2023-44487 --json
  python3 mitre_mapper.py CVE-2021-44228 --verbose
        """,
    )
    parser.add_argument(
        "cve_ids",
        nargs="+",
        metavar="CVE_ID",
        help="One or more CVE IDs (e.g. CVE-2021-44228)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output structured JSON instead of human-readable text",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show progress and debug information",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip NVD API calls (use only local mapping data)",
    )
    parser.add_argument(
        "--atlas",
        action="store_true",
        help="Include MITRE ATLAS (AI/ML threat) mappings in output",
    )

    args = parser.parse_args()

    if args.verbose:
        print(f"Loading mapping from {CWE_CAPEC_MAP_FILE}...", file=sys.stderr)

    mapping = load_cwe_capec_map()
    total = len(args.cve_ids)
    results = []

    for i, cve_id in enumerate(args.cve_ids, start=1):
        if args.offline:
            nvd_response = {}
        else:
            cve_id_upper = cve_id.upper().strip()
            if args.verbose and total > 1:
                print(f"[{i}/{total}] Fetching {cve_id_upper} from NVD...", file=sys.stderr)
            elif args.verbose:
                print(f"Fetching {cve_id_upper} from NVD...", file=sys.stderr)
            nvd_response = fetch_cve_from_nvd(cve_id_upper)
            # Rate limiting between requests
            if i < total:
                time.sleep(RATE_LIMIT_DELAY)

        chain = build_chain(cve_id.upper().strip(), mapping, nvd_response, include_atlas=args.atlas)
        results.append(chain)

    if args.json_output:
        output = {
            "tool": "mitre_mapper",
            "version": "1.0.0",
            "mapping_meta": mapping.get("meta", {}),
            "results": results,
        }
        print(json.dumps(output, indent=2))
    else:
        for i, chain in enumerate(results):
            if i > 0:
                print()
            print(format_text(chain))


if __name__ == "__main__":
    main()
