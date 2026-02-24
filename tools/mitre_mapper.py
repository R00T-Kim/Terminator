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
    # Web vulnerabilities (v1.1 additions)
    "CVE-2021-41773": ["CWE-22", "CWE-78"],                          # Apache path traversal/RCE
    "CVE-2021-42013": ["CWE-22"],                                    # Apache path traversal follow-up
    "CVE-2022-22963": ["CWE-94"],                                    # Spring Cloud Function SPEL injection
    "CVE-2023-46604": ["CWE-502"],                                   # Apache ActiveMQ deserialization RCE
    "CVE-2021-22986": ["CWE-306"],                                   # F5 BIG-IP/BIG-IQ SSRF+auth bypass
    "CVE-2023-50164": ["CWE-434"],                                   # Apache Struts file upload RCE
    "CVE-2022-36804": ["CWE-78"],                                    # Bitbucket Server command injection
    "CVE-2024-23897": ["CWE-22"],                                    # Jenkins path traversal LFI
    "CVE-2023-27163": ["CWE-918"],                                   # request-baskets SSRF
    "CVE-2022-0540":  ["CWE-862"],                                   # Jira auth bypass
    "CVE-2022-26923": ["CWE-863"],                                   # AD CS cert template privesc
    "CVE-2021-40438": ["CWE-918"],                                   # Apache mod_proxy SSRF
    "CVE-2023-22515": ["CWE-639"],                                   # Confluence broken access control
    "CVE-2024-21626": ["CWE-22"],                                    # runc container escape
    "CVE-2022-3786":  ["CWE-787"],                                   # OpenSSL X.509 buffer overflow
    "CVE-2023-0386":  ["CWE-269"],                                   # Linux OverlayFS privesc
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


# CWE metadata for get_context_for_finding() — sinks, techniques, related patterns
_CWE_CONTEXT: dict[str, dict] = {
    "CWE-79":   {"name": "Cross-Site Scripting (XSS)",
                 "related": ["Stored XSS", "Reflected XSS", "DOM XSS"],
                 "sinks": ["innerHTML", "document.write", "eval", "location.href", "setAttribute"]},
    "CWE-89":   {"name": "SQL Injection",
                 "related": ["Blind SQLi", "Union-based SQLi", "Error-based SQLi"],
                 "sinks": ["execute()", "query()", "cursor.execute", "raw SQL string concat"]},
    "CWE-918":  {"name": "Server-Side Request Forgery (SSRF)",
                 "related": ["Blind SSRF", "SSRF via redirect", "Cloud metadata SSRF"],
                 "sinks": ["fetch()", "urllib.request", "requests.get", "curl", "file:// scheme"]},
    "CWE-22":   {"name": "Path Traversal",
                 "related": ["Directory traversal", "Zip slip", "LFI"],
                 "sinks": ["open()", "readFile()", "sendFile()", "include()", "require()"]},
    "CWE-502":  {"name": "Deserialization of Untrusted Data",
                 "related": ["Java deserialization", "pickle RCE", "YAML load RCE"],
                 "sinks": ["pickle.loads", "yaml.load", "ObjectInputStream", "unserialize()", "JSON gadget chain"]},
    "CWE-862":  {"name": "Missing Authorization",
                 "related": ["Broken access control", "Privilege escalation"],
                 "sinks": ["API endpoint without authz check", "missing @RequiresPermission", "no role validation"]},
    "CWE-863":  {"name": "Incorrect Authorization",
                 "related": ["Horizontal privesc", "Vertical privesc", "IDOR"],
                 "sinks": ["role check on wrong object", "cached auth state", "JWT without server validation"]},
    "CWE-352":  {"name": "Cross-Site Request Forgery (CSRF)",
                 "related": ["State-changing GET request", "Missing SameSite cookie", "Token bypass"],
                 "sinks": ["form action without CSRF token", "fetch() without origin check", "missing Referer validation"]},
    "CWE-611":  {"name": "XML External Entity Injection (XXE)",
                 "related": ["File read XXE", "SSRF via XXE", "Blind XXE"],
                 "sinks": ["XMLParser with external entities", "etree.parse()", "DOMParser", "SAXParser"]},
    "CWE-94":   {"name": "Code Injection",
                 "related": ["SSTI", "eval injection", "Remote code inclusion"],
                 "sinks": ["eval()", "exec()", "Function() constructor", "compile()", "template engine with raw input"]},
    "CWE-78":   {"name": "OS Command Injection",
                 "related": ["Shell injection", "Blind OS cmdi", "Command chaining"],
                 "sinks": ["os.system()", "subprocess with shell=True", "Runtime.exec()", "backtick execution"]},
    "CWE-434":  {"name": "Unrestricted File Upload",
                 "related": ["WebShell upload", "MIME type bypass", "Extension bypass"],
                 "sinks": ["move_uploaded_file()", "multer dest without validation", "content-type not checked"]},
    "CWE-601":  {"name": "Open Redirect",
                 "related": ["Header injection redirect", "URL redirect abuse", "Phishing via redirect"],
                 "sinks": ["Location header with user input", "res.redirect(req.query.url)", "window.location = param"]},
    "CWE-639":  {"name": "IDOR / Insecure Direct Object Reference",
                 "related": ["Horizontal privesc", "Mass assignment", "Broken object-level auth"],
                 "sinks": ["findById(req.params.id) without ownership check", "WHERE id=? no user binding", "path param in DB query"]},
    "CWE-347":  {"name": "Improper JWT Verification",
                 "related": ["alg:none attack", "Key confusion HS256/RS256", "Missing signature check"],
                 "sinks": ["jwt.decode(verify=False)", "jose without verify flag", "alg header trusted from token itself"]},
    "CWE-798":  {"name": "Hardcoded Credentials",
                 "related": ["Hardcoded API key", "Default password", "Embedded secret in binary"],
                 "sinks": ["string literal in auth check", "const SECRET = '...'", "config file with plaintext creds"]},
    "CWE-327":  {"name": "Use of Broken or Risky Cryptographic Algorithm",
                 "related": ["MD5/SHA1 for passwords", "ECB mode encryption", "DES/RC4 usage"],
                 "sinks": ["hashlib.md5()", "Cipher.getInstance('AES/ECB')", "DES.new()", "Math.random() for security tokens"]},
    "CWE-1321": {"name": "Prototype Pollution",
                 "related": ["__proto__ pollution", "constructor.prototype override", "Object.assign gadget"],
                 "sinks": ["Object.assign with user data", "_.merge() with untrusted input", "bracket notation with __proto__ key"]},
    "CWE-942":  {"name": "Permissive CORS Policy",
                 "related": ["Wildcard CORS", "Reflected Origin header", "Credentialed CORS abuse"],
                 "sinks": ["Access-Control-Allow-Origin: *", "origin reflected without allowlist", "credentials:true with wildcard"]},
    "CWE-1336": {"name": "Server-Side Template Injection (SSTI)",
                 "related": ["Jinja2 SSTI", "Twig SSTI", "AngularJS CSTI"],
                 "sinks": ["render_template_string(user_input)", "Jinja2 Environment().from_string()", "ng-bind-html with raw input"]},
    "CWE-77":   {"name": "Command Injection (Improper Neutralization)",
                 "related": ["Shell metachar injection", "Argument injection"],
                 "sinks": ["os.popen()", "Runtime.exec()", "shell=True subprocess", "backtick execution"]},
    "CWE-20":   {"name": "Improper Input Validation",
                 "related": ["Type confusion", "Integer overflow trigger", "Null byte injection"],
                 "sinks": ["any unsanitized user input reaching logic or memory ops"]},
    "CWE-287":  {"name": "Improper Authentication",
                 "related": ["Auth bypass", "NTLM relay", "Session fixation"],
                 "sinks": ["token comparison without timing-safe equals", "auth header not verified server-side", "session not invalidated on logout"]},
    "CWE-306":  {"name": "Missing Authentication for Critical Function",
                 "related": ["Unauthenticated API endpoint", "Auth bypass on admin route"],
                 "sinks": ["route handler without auth middleware", "function callable without session check"]},
}


def get_context_for_finding(cwe_id: str, mapping: dict | None = None) -> str:
    """
    Return a formatted MITRE context string suitable for injecting into an agent prompt.

    Usage (standalone):
        from tools.mitre_mapper import get_context_for_finding, load_cwe_capec_map
        mapping = load_cwe_capec_map()
        print(get_context_for_finding("CWE-79", mapping))

    Usage (without mapping — metadata only):
        print(get_context_for_finding("CWE-79"))

    Example output:
        MITRE Context: CWE-79 (XSS) → CAPEC-86 (XSS via HTTP Headers) → T1059.007 (JavaScript)
        Related techniques: Stored XSS, Reflected XSS, DOM XSS
        Common sinks: innerHTML, document.write, eval
        ATT&CK techniques: T1059.007, T1189
    """
    cwe_id = cwe_id.upper().strip()
    meta = _CWE_CONTEXT.get(cwe_id, {})
    cwe_name = meta.get("name", "Unknown weakness")
    related = meta.get("related", [])
    sinks = meta.get("sinks", [])

    lines: list[str] = []

    if mapping is not None:
        cwe_to_capec = mapping.get("cwe_to_capec", {})
        capec_to_attack = mapping.get("capec_to_attack", {})
        capecs = cwe_to_capec.get(cwe_id, [])

        all_techniques: list[str] = []
        first_chain = ""
        for capec in capecs[:2]:
            capec_id = capec["capec_id"]
            capec_name = capec["name"]
            techs = capec_to_attack.get(capec_id, [])
            if techs and not first_chain:
                t = techs[0]
                first_chain = (
                    f"MITRE Context: {cwe_id} ({cwe_name})"
                    f" → {capec_id} ({capec_name})"
                    f" → {t['technique_id']} ({t['name']})"
                )
            for t in techs:
                if t["technique_id"] not in all_techniques:
                    all_techniques.append(t["technique_id"])

        lines.append(first_chain if first_chain else f"MITRE Context: {cwe_id} ({cwe_name}) → [no CAPEC mapping]")
        if all_techniques:
            lines.append(f"ATT&CK techniques: {', '.join(all_techniques)}")
    else:
        lines.append(f"MITRE Context: {cwe_id} ({cwe_name})")

    if related:
        lines.append(f"Related techniques: {', '.join(related)}")
    if sinks:
        lines.append(f"Common sinks: {', '.join(sinks)}")

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
