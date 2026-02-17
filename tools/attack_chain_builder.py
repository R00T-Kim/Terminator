#!/usr/bin/env python3
"""
Attack Chain Builder for Terminator Bug Bounty Pipeline.
Converts MITRE enrichment (CVE→CWE→CAPEC→ATT&CK) into actionable exploit plans.
Reads mitre_enrichment.json + recon_report.json → outputs attack_plan.md
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent

# ATT&CK Technique → Exploit Category mapping
TECHNIQUE_TO_EXPLOIT_CATEGORY = {
    "T1190": {
        "category": "Remote Code Execution / Auth Bypass",
        "tools": ["nuclei", "searchsploit", "curl", "SSRFmap"],
        "payloads": ["PayloadsAllTheThings/File Inclusion", "PayloadsAllTheThings/SSRF"],
        "priority": "CRITICAL",
        "approach": "Search for public PoC → adapt to target → verify pre-auth → capture evidence",
    },
    "T1059": {
        "category": "Command Injection",
        "tools": ["commix", "curl", "burpsuite"],
        "payloads": ["PayloadsAllTheThings/Command Injection"],
        "priority": "CRITICAL",
        "approach": "Test injection points with safe payloads (id, whoami) → use commix for automation",
    },
    "T1059.001": {
        "category": "PowerShell Injection",
        "tools": ["curl", "python3"],
        "payloads": ["PayloadsAllTheThings/Command Injection"],
        "priority": "CRITICAL",
        "approach": "Test PowerShell-specific injection vectors → encode payloads → verify execution",
    },
    "T1059.007": {
        "category": "XSS / JavaScript Injection",
        "tools": ["dalfox", "burpsuite", "curl"],
        "payloads": ["PayloadsAllTheThings/XSS Injection"],
        "priority": "HIGH",
        "approach": "dalfox automated scan → manual context-aware bypass → stored vs reflected",
    },
    "T1190+T1059": {
        "category": "Pre-Auth RCE Chain",
        "tools": ["searchsploit", "nuclei", "commix"],
        "payloads": ["PayloadsAllTheThings/Command Injection", "PayloadsAllTheThings/File Inclusion"],
        "priority": "CRITICAL+",
        "approach": "HIGHEST VALUE: Combine public-facing exploit with command execution — document full chain",
    },
    "T1203": {
        "category": "Client-Side Exploitation",
        "tools": ["gdb", "pwntools", "ROPgadget"],
        "payloads": [],
        "priority": "HIGH",
        "approach": "Memory corruption → ROP chain or ret2libc → shell/flag",
    },
    "T1068": {
        "category": "Privilege Escalation",
        "tools": ["searchsploit", "pwntools", "gdb"],
        "payloads": [],
        "priority": "HIGH",
        "approach": "LPE exploit → verify kernel/SUID target → test in Docker sandbox",
    },
    "T1078": {
        "category": "Valid Accounts / Credential Abuse",
        "tools": ["hydra", "curl", "sqlmap"],
        "payloads": ["PayloadsAllTheThings/Default Credentials"],
        "priority": "HIGH",
        "approach": "Test default creds → credential stuffing → session fixation → token prediction",
    },
    "T1078.001": {
        "category": "Default Accounts",
        "tools": ["curl", "nuclei"],
        "payloads": ["PayloadsAllTheThings/Default Credentials"],
        "priority": "HIGH",
        "approach": "Try common default creds → check vendor documentation → verify with nuclei default-login templates",
    },
    "T1556": {
        "category": "Authentication Bypass",
        "tools": ["sqlmap", "curl", "burpsuite"],
        "payloads": ["PayloadsAllTheThings/SQL Injection", "PayloadsAllTheThings/Authentication Bypass"],
        "priority": "HIGH",
        "approach": "SQLi auth bypass → JWT manipulation → session fixation → race condition",
    },
    "T1548": {
        "category": "Privilege Escalation via Abuse of Control",
        "tools": ["curl", "python3"],
        "payloads": [],
        "priority": "HIGH",
        "approach": "IDOR → role manipulation → hidden admin endpoints → mass assignment",
    },
    "T1539": {
        "category": "Session Hijacking",
        "tools": ["curl", "burpsuite"],
        "payloads": ["PayloadsAllTheThings/CSRF"],
        "priority": "MEDIUM",
        "approach": "CSRF PoC → steal session cookie → verify auth bypass with stolen session",
    },
    "T1185": {
        "category": "Browser Session Hijacking",
        "tools": ["dalfox", "burpsuite"],
        "payloads": ["PayloadsAllTheThings/XSS Injection"],
        "priority": "MEDIUM",
        "approach": "XSS → cookie exfil → session replay → demonstrate account takeover",
    },
    "T1110": {
        "category": "Brute Force",
        "tools": ["hydra", "ffuf", "python3"],
        "payloads": [],
        "priority": "MEDIUM",
        "approach": "Rate limit check → lockout policy check → safe brute force with 10 attempts max",
    },
    "T1005": {
        "category": "Data Exfiltration from Local System",
        "tools": ["curl", "SSRFmap"],
        "payloads": ["PayloadsAllTheThings/File Inclusion", "PayloadsAllTheThings/SSRF"],
        "priority": "HIGH",
        "approach": "Path traversal → LFI → SSRF internal file read → sensitive data extraction",
    },
    "T1083": {
        "category": "File and Directory Discovery",
        "tools": ["gobuster", "ffuf", "dirsearch"],
        "payloads": [],
        "priority": "LOW",
        "approach": "Directory brute-force → identify sensitive files → check for backup/config exposure",
    },
    "T1565": {
        "category": "Data Manipulation",
        "tools": ["curl", "burpsuite", "sqlmap"],
        "payloads": ["PayloadsAllTheThings/SQL Injection"],
        "priority": "HIGH",
        "approach": "SQLi → data modification → business logic manipulation → integrity violation proof",
    },
    "T1552": {
        "category": "Unsecured Credentials",
        "tools": ["trufflehog", "strings", "grep"],
        "payloads": [],
        "priority": "HIGH",
        "approach": "trufflehog --only-verified → binary strings extraction → config file analysis",
    },
    "T1499": {
        "category": "Denial of Service",
        "tools": ["curl", "python3"],
        "payloads": [],
        "priority": "LOW",
        "approach": "DoS usually out-of-scope. Verify program includes DoS before testing.",
    },
    "T1566.001": {
        "category": "Phishing / Social Engineering",
        "tools": [],
        "payloads": [],
        "priority": "LOW",
        "approach": "Phishing usually out-of-scope for bug bounty. Skip unless program explicitly includes.",
    },
    "T1027": {
        "category": "Obfuscated Files / Filter Bypass",
        "tools": ["curl", "burpsuite"],
        "payloads": ["PayloadsAllTheThings/File Upload"],
        "priority": "MEDIUM",
        "approach": "Test encoding bypasses (double URL encode, null byte, extension manipulation)",
    },
    "T1036": {
        "category": "Masquerading / Spoofing",
        "tools": ["curl"],
        "payloads": [],
        "priority": "MEDIUM",
        "approach": "Test header spoofing (X-Forwarded-For, Host, Origin) → verify bypass impact",
    },
    "T1090": {
        "category": "SSRF / Proxy",
        "tools": ["SSRFmap", "curl", "python3"],
        "payloads": ["PayloadsAllTheThings/SSRF"],
        "priority": "HIGH",
        "approach": "SSRFmap → internal service enumeration → cloud metadata → internal API access",
    },
    "T1563": {
        "category": "Remote Service Session Hijacking",
        "tools": ["curl", "python3"],
        "payloads": [],
        "priority": "HIGH",
        "approach": "Session token analysis → predictability → fixation → hijacking PoC",
    },
    "T1189": {
        "category": "Drive-by Compromise",
        "tools": ["dalfox", "burpsuite"],
        "payloads": ["PayloadsAllTheThings/XSS Injection"],
        "priority": "MEDIUM",
        "approach": "Stored XSS → malicious payload delivery → demonstrate cross-user impact",
    },
}

PRIORITY_ORDER = {"CRITICAL+": 0, "CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "UNKNOWN": 5}


def load_mitre_enrichment(mitre_file: Path) -> list:
    """Load CVE chains from mitre_enrichment.json."""
    if not mitre_file.exists():
        return []
    try:
        data = json.loads(mitre_file.read_text())
        return data.get("results", [])
    except Exception as e:
        print(f"[WARN] Failed to load {mitre_file}: {e}", file=sys.stderr)
        return []


def load_recon_report(recon_file: Path) -> dict:
    """Load recon data from recon_report.json."""
    if not recon_file.exists():
        return {}
    try:
        return json.loads(recon_file.read_text())
    except Exception:
        return {}


def extract_attack_techniques(mitre_results: list) -> list:
    """
    Extract all unique ATT&CK techniques from MITRE enrichment results.
    Returns list of dicts with technique_id, name, source_cve, priority.
    """
    technique_map = {}  # technique_id → {name, cves, cvss_max}

    for result in mitre_results:
        cve_id = result.get("cve_id", "")
        cvss = result.get("cvss_score") or 0.0

        for cwe in result.get("cwes", []):
            for capec in cwe.get("capecs", []):
                for tech in capec.get("attack_techniques", []):
                    tid = tech["technique_id"]
                    if tid not in technique_map:
                        technique_map[tid] = {
                            "technique_id": tid,
                            "name": tech["name"],
                            "source_cves": [],
                            "cvss_max": 0.0,
                            "capecs": [],
                        }
                    if cve_id not in technique_map[tid]["source_cves"]:
                        technique_map[tid]["source_cves"].append(cve_id)
                    technique_map[tid]["cvss_max"] = max(technique_map[tid]["cvss_max"], cvss)
                    capec_id = capec.get("capec_id", "")
                    if capec_id not in technique_map[tid]["capecs"]:
                        technique_map[tid]["capecs"].append(capec_id)

    # Check for chained techniques (T1190 + T1059 = CRITICAL+)
    tech_ids = set(technique_map.keys())
    chains = []
    if "T1190" in tech_ids and any(t.startswith("T1059") for t in tech_ids):
        chains.append("T1190+T1059")

    techniques = list(technique_map.values())

    # Add chain entries
    for chain_id in chains:
        chain_info = TECHNIQUE_TO_EXPLOIT_CATEGORY.get(chain_id, {})
        techniques.insert(0, {
            "technique_id": chain_id,
            "name": "Pre-Auth RCE Chain (chained techniques)",
            "source_cves": [],
            "cvss_max": 10.0,
            "capecs": [],
            "is_chain": True,
        })

    return techniques


def build_exploit_plan(techniques: list, recon: dict) -> list:
    """Build prioritized exploit plan from ATT&CK techniques + recon data."""
    plan = []
    target = recon.get("target", "unknown")
    open_ports = recon.get("open_ports", [])
    technologies = recon.get("technologies", [])

    for tech in techniques:
        tid = tech["technique_id"]
        exploit_info = TECHNIQUE_TO_EXPLOIT_CATEGORY.get(tid, {
            "category": "Unknown",
            "tools": [],
            "payloads": [],
            "priority": "UNKNOWN",
            "approach": "Manual investigation required",
        })

        priority = exploit_info.get("priority", "UNKNOWN")
        if tech.get("cvss_max", 0) >= 9.0 and priority not in ("CRITICAL+", "CRITICAL"):
            priority = "CRITICAL"  # Elevate based on CVSS

        entry = {
            "technique_id": tid,
            "technique_name": tech.get("name", ""),
            "category": exploit_info["category"],
            "priority": priority,
            "priority_order": PRIORITY_ORDER.get(priority, 5),
            "source_cves": tech.get("source_cves", []),
            "cvss_max": tech.get("cvss_max", 0.0),
            "capecs": tech.get("capecs", []),
            "tools": exploit_info["tools"],
            "payload_refs": exploit_info["payloads"],
            "approach": exploit_info["approach"],
            "is_chain": tech.get("is_chain", False),
            "target_services": [],
        }

        # Match to specific services from recon
        for port_info in open_ports:
            svc = port_info.get("service", "")
            ver = port_info.get("version", "")
            if any(kw in svc.lower() for kw in ["http", "https", "web", "api"]):
                if tid in ("T1190", "T1059", "T1059.007", "T1190+T1059"):
                    entry["target_services"].append(f"{port_info['port']}/{svc} {ver}".strip())

        plan.append(entry)

    # Sort by priority
    plan.sort(key=lambda x: (x["priority_order"], -x["cvss_max"]))
    return plan


def format_attack_plan_md(plan: list, recon: dict, mitre_results: list) -> str:
    """Format the attack plan as Markdown for analyst handoff."""
    target = recon.get("target", "unknown")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cves = recon.get("cves_found", [r.get("cve_id") for r in mitre_results])

    lines = [
        f"# Attack Chain Plan: {target}",
        f"Generated: {ts}",
        "",
        "## Executive Summary",
        f"- Target: `{target}`",
        f"- CVEs identified: {', '.join(cves) if cves else 'None from nuclei (manual scan required)'}",
        f"- ATT&CK techniques mapped: {len(plan)}",
        f"- CRITICAL/CRITICAL+ items: {sum(1 for p in plan if p['priority'] in ('CRITICAL', 'CRITICAL+'))}",
        "",
        "## Prioritized Exploit Plan",
        "",
    ]

    for i, entry in enumerate(plan, 1):
        priority = entry["priority"]
        prefix = "🔴" if priority in ("CRITICAL+", "CRITICAL") else "🟠" if priority == "HIGH" else "🟡" if priority == "MEDIUM" else "⚪"

        lines.append(f"### Priority {i}: [{priority}] {entry['category']}")
        lines.append(f"**ATT&CK**: `{entry['technique_id']}` — {entry['technique_name']}")

        if entry.get("is_chain"):
            lines.append("**TYPE**: CHAINED TECHNIQUE — highest value target")

        if entry["source_cves"]:
            cvss_str = f" (CVSS max: {entry['cvss_max']})" if entry["cvss_max"] else ""
            lines.append(f"**Source CVEs**: {', '.join(entry['source_cves'])}{cvss_str}")

        if entry["capecs"]:
            lines.append(f"**CAPEC**: {', '.join(entry['capecs'])}")

        if entry["target_services"]:
            lines.append(f"**Target Services**: {', '.join(entry['target_services'])}")

        lines.append(f"**Approach**: {entry['approach']}")

        if entry["tools"]:
            lines.append(f"**Tools**: `{'`, `'.join(entry['tools'])}`")

        if entry["payload_refs"]:
            lines.append(f"**Payload Refs**: {', '.join(f'`~/{r}`' for r in entry['payload_refs'])}")

        lines.append("")

    # Search commands section
    lines.extend([
        "## Search Commands (run these first)",
        "",
        "```bash",
        "# ExploitDB search for each CVE",
    ])
    for cve in cves[:5]:
        lines.append(f"~/exploitdb/searchsploit {cve}")
    lines.extend([
        "",
        "# PoC-in-GitHub search",
    ])
    for cve in cves[:3]:
        year = cve.split("-")[1] if "-" in cve else "2024"
        lines.append(f"cat ~/PoC-in-GitHub/{year}/{cve}.json 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); [print(u) for u in d.get('references',[])]\"")
    lines.extend([
        "",
        "# trickest-cve search",
    ])
    for cve in cves[:3]:
        year = cve.split("-")[1] if "-" in cve else "2024"
        lines.append(f"cat ~/trickest-cve/{year}/{cve}.md 2>/dev/null | head -30")
    lines.extend([
        "",
        "# Nuclei CVE-specific templates",
    ])
    for cve in cves[:3]:
        year = cve.split("-")[1] if "-" in cve else "2024"
        lines.append(f"ls ~/nuclei-templates/http/cves/{year}/ 2>/dev/null | grep -i {cve.lower()}")
    lines.append("```")

    lines.extend([
        "",
        "## Handoff to Exploiter",
        "",
        "Confidence score each finding with:",
        "```bash",
        "python3 tools/confidence_scorer.py --input vulnerability_candidates.json --mitre mitre_enrichment.json",
        "```",
        "",
        "Only pass findings with confidence score >= 5 to exploiter.",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Attack Chain Builder — MITRE enrichment → actionable exploit plan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 attack_chain_builder.py
  python3 attack_chain_builder.py --mitre mitre_enrichment.json --recon recon_report.json
  python3 attack_chain_builder.py --mitre mitre_enrichment.json --json
  python3 attack_chain_builder.py --mitre mitre_enrichment.json --output attack_plan.md
        """,
    )
    parser.add_argument("--mitre", "-m", default="mitre_enrichment.json",
                        help="Path to mitre_enrichment.json (default: mitre_enrichment.json)")
    parser.add_argument("--recon", "-r", default="recon_report.json",
                        help="Path to recon_report.json (default: recon_report.json)")
    parser.add_argument("--output", "-o", default="attack_plan.md",
                        help="Output file (default: attack_plan.md)")
    parser.add_argument("--json", "-j", action="store_true", dest="json_output",
                        help="Output JSON instead of Markdown")
    parser.add_argument("--min-priority", choices=["CRITICAL+", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        default="LOW", help="Minimum priority to include (default: LOW)")
    args = parser.parse_args()

    mitre_file = Path(args.mitre)
    recon_file = Path(args.recon)
    output_file = Path(args.output)

    print(f"[INFO] Loading MITRE enrichment from {mitre_file}...", file=sys.stderr)
    mitre_results = load_mitre_enrichment(mitre_file)
    print(f"[INFO] Loaded {len(mitre_results)} CVE chains", file=sys.stderr)

    print(f"[INFO] Loading recon report from {recon_file}...", file=sys.stderr)
    recon = load_recon_report(recon_file)

    techniques = extract_attack_techniques(mitre_results)
    print(f"[INFO] Extracted {len(techniques)} ATT&CK techniques", file=sys.stderr)

    plan = build_exploit_plan(techniques, recon)

    # Filter by min priority
    min_order = PRIORITY_ORDER.get(args.min_priority, 5)
    plan = [p for p in plan if p["priority_order"] <= min_order]

    if args.json_output:
        output = {
            "tool": "attack_chain_builder",
            "target": recon.get("target", "unknown"),
            "generated": datetime.now().isoformat(),
            "total_techniques": len(plan),
            "plan": plan,
        }
        print(json.dumps(output, indent=2))
    else:
        content = format_attack_plan_md(plan, recon, mitre_results)
        output_file.write_text(content)
        print(f"[OK] Attack plan saved to {output_file}", file=sys.stderr)
        print(content)


if __name__ == "__main__":
    main()
