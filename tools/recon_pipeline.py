#!/usr/bin/env python3
"""
Recon Pipeline Orchestrator for Terminator.
6-phase automated reconnaissance: Domain→Ports→HTTP→Enum→Vuln→MITRE
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
CONFIG_FILE = SCRIPT_DIR / "recon_config.json"
MITRE_MAPPER = SCRIPT_DIR / "mitre_mapper.py"

# ANSI colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def log(phase: str, msg: str, level: str = "info"):
    ts = datetime.now().strftime("%H:%M:%S")
    color = {
        "info": CYAN,
        "ok": GREEN,
        "warn": YELLOW,
        "error": RED,
    }.get(level, RESET)
    print(f"{color}[{ts}][{phase}] {msg}{RESET}", flush=True)


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        log("CONFIG", f"Config file not found: {CONFIG_FILE}", "error")
        sys.exit(1)
    with open(CONFIG_FILE) as f:
        return json.load(f)


def run_cmd(cmd: list, timeout: int = 120, capture: bool = True) -> tuple[int, str, str]:
    """Run a shell command, return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Binary not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def tool_available(name: str) -> bool:
    """Check if a tool binary is available in PATH or expanded path."""
    expanded = os.path.expanduser(name)
    if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
        return True
    rc, _, _ = run_cmd(["which", name], timeout=5)
    return rc == 0


# ── Phase 0: Duplicate Pre-Screen ──────────────────────────────────────────

def phase0_duplicate_prescreen(target: str, output_dir: Path, verbose: bool) -> dict:
    log("P0", f"Duplicate pre-screen for {target}")
    results = {
        "phase": "phase0",
        "target": target,
        "github_advisories": [],
        "recent_security_commits": [],
        "duplicate_risk": "UNKNOWN",
        "notes": [],
    }

    # Check GitHub security advisories if gh CLI available
    if tool_available("gh"):
        # Try to detect org/repo from target
        owner_repo = None
        if "github.com/" in target:
            parts = target.replace("https://", "").replace("http://", "").split("/")
            if len(parts) >= 3:
                owner_repo = f"{parts[1]}/{parts[2]}"

        if owner_repo:
            rc, out, _ = run_cmd(
                ["gh", "api", f"/repos/{owner_repo}/security-advisories",
                 "--jq", ".[].summary"],
                timeout=30,
            )
            if rc == 0 and out.strip():
                advisories = [l.strip() for l in out.strip().splitlines() if l.strip()]
                results["github_advisories"] = advisories[:10]
                results["notes"].append(f"Found {len(advisories)} GitHub security advisories")
                if len(advisories) > 5:
                    results["duplicate_risk"] = "HIGH"

    notes_file = output_dir / "duplicate_prescreen.md"
    with open(notes_file, "w") as f:
        f.write(f"# Duplicate Pre-Screen: {target}\n\n")
        f.write(f"**Duplicate Risk**: {results['duplicate_risk']}\n\n")
        f.write("## GitHub Advisories\n")
        for adv in results["github_advisories"]:
            f.write(f"- {adv}\n")
        f.write("\n## Notes\n")
        for note in results["notes"]:
            f.write(f"- {note}\n")

    log("P0", f"Duplicate risk: {results['duplicate_risk']}", "ok")
    return results


# ── Phase 1: Domain & Subdomain Discovery ──────────────────────────────────

def phase1_domain_discovery(target: str, output_dir: Path, verbose: bool) -> dict:
    log("P1", f"Domain & subdomain discovery for {target}")
    results = {
        "phase": "phase1",
        "subdomains": [],
        "live_hosts": [],
        "urls": [],
    }

    # subfinder
    subs_file = output_dir / "subdomains.txt"
    if tool_available("subfinder"):
        rc, out, err = run_cmd(
            ["subfinder", "-d", target, "-silent", "-o", str(subs_file)],
            timeout=120,
        )
        if subs_file.exists():
            results["subdomains"] = [l.strip() for l in subs_file.read_text().splitlines() if l.strip()]
            log("P1", f"subfinder: {len(results['subdomains'])} subdomains", "ok")
    else:
        log("P1", "subfinder not available, skipping", "warn")

    # httpx probe on discovered subdomains
    if results["subdomains"] and tool_available("httpx"):
        live_file = output_dir / "live_hosts.txt"
        rc, out, err = run_cmd(
            ["httpx", "-silent", "-title", "-status-code", "-o", str(live_file)],
            timeout=120,
        )
        if live_file.exists():
            results["live_hosts"] = [l.strip() for l in live_file.read_text().splitlines() if l.strip()]
            log("P1", f"httpx: {len(results['live_hosts'])} live hosts", "ok")

    # URL collection (gau + waybackurls)
    urls_file = output_dir / "urls.txt"
    urls = set()
    for tool_bin, tool_name in [("gau", "gau"), ("waybackurls", "waybackurls")]:
        if tool_available(tool_bin):
            rc, out, err = run_cmd(
                ["bash", "-c", f"echo '{target}' | {tool_bin}"],
                timeout=60,
            )
            if rc == 0 and out.strip():
                new_urls = set(out.strip().splitlines())
                urls |= new_urls
                log("P1", f"{tool_name}: {len(new_urls)} URLs", "ok")
        else:
            log("P1", f"{tool_name} not available", "warn")

    if urls:
        urls_file.write_text("\n".join(sorted(urls)))
        results["urls"] = list(urls)[:100]  # cap for report

    # DNS records
    rc, out, _ = run_cmd(["dig", "+short", target, "A"], timeout=10)
    results["dns_a"] = [l.strip() for l in out.splitlines() if l.strip()]

    log("P1", f"Done: {len(results['subdomains'])} subs, {len(results['live_hosts'])} live, {len(urls)} URLs", "ok")
    return results


# ── Phase 2: Port Scanning ──────────────────────────────────────────────────

def phase2_port_scan(target: str, output_dir: Path, full_scan: bool, verbose: bool) -> dict:
    log("P2", f"Port scanning {target} (full={full_scan})")
    results = {"phase": "phase2", "open_ports": [], "nmap_output": ""}

    if not tool_available("nmap"):
        log("P2", "nmap not available", "warn")
        return results

    nmap_fast_file = output_dir / "nmap_fast.txt"
    # Fast scan (top 1000)
    rc, out, err = run_cmd(
        ["nmap", "-sV", "-T4", "--top-ports", "1000", "--min-rate", "1000",
         "-oN", str(nmap_fast_file), target],
        timeout=300,
    )
    if nmap_fast_file.exists():
        content = nmap_fast_file.read_text()
        results["nmap_output"] = content
        # Parse open ports
        for line in content.splitlines():
            m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
            if m:
                results["open_ports"].append({
                    "port": int(m.group(1)),
                    "proto": m.group(2),
                    "service": m.group(3),
                    "version": m.group(4).strip(),
                })

    log("P2", f"Found {len(results['open_ports'])} open ports", "ok")

    # Full scan (optional, parallel)
    if full_scan:
        log("P2", "Running full port scan (-p-)...")
        nmap_full_file = output_dir / "nmap_full.txt"
        run_cmd(
            ["nmap", "-sS", "-p-", "-T4", "--min-rate", "2000",
             "-oN", str(nmap_full_file), target],
            timeout=600,
        )

    return results


# ── Phase 3: HTTP Probing ───────────────────────────────────────────────────

def phase3_http_probe(target: str, open_ports: list, output_dir: Path, verbose: bool) -> dict:
    log("P3", "HTTP probing & tech fingerprinting")
    results = {
        "phase": "phase3",
        "web_targets": [],
        "technologies": [],
        "waf_detected": False,
        "headers": {},
    }

    # Determine web targets from open ports
    web_ports = [p for p in open_ports if p["service"] in ("http", "https", "http-alt", "ssl/http")]
    if not web_ports:
        # Default to 80/443
        web_ports = [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}]

    targets_urls = []
    for p in web_ports:
        scheme = "https" if p["service"] in ("https", "ssl/http") or p["port"] == 443 else "http"
        url = f"{scheme}://{target}:{p['port']}" if p["port"] not in (80, 443) else f"{scheme}://{target}"
        targets_urls.append(url)

    results["web_targets"] = targets_urls

    # httpx tech detection
    if tool_available("httpx") and targets_urls:
        probe_file = output_dir / "httpx_probe.txt"
        rc, out, err = run_cmd(
            ["httpx", "-silent", "-title", "-tech-detect", "-status-code",
             "-content-length", "-web-server", "-o", str(probe_file)]
            + targets_urls,
            timeout=60,
        )
        if probe_file.exists():
            content = probe_file.read_text()
            # Extract technologies
            techs = set()
            for line in content.splitlines():
                m = re.findall(r"\[([^\]]+)\]", line)
                for item in m:
                    if item and not item.isdigit():
                        techs.add(item)
            results["technologies"] = list(techs)
            log("P3", f"httpx: {len(techs)} technologies detected", "ok")

    # WAF detection via curl headers
    for url in targets_urls[:1]:
        rc, out, _ = run_cmd(["curl", "-sI", "--max-time", "10", url], timeout=15)
        if rc == 0:
            waf_headers = ["x-sucuri", "x-waf", "cf-ray", "x-firewall", "server: cloudflare"]
            for h in waf_headers:
                if h.lower() in out.lower():
                    results["waf_detected"] = True
                    results["waf_vendor"] = h
                    log("P3", f"WAF detected: {h}", "warn")
                    break

    log("P3", f"Done: {len(targets_urls)} web targets, WAF={results['waf_detected']}", "ok")
    return results


# ── Phase 4: Resource Enumeration ──────────────────────────────────────────

def phase4_enumeration(web_targets: list, output_dir: Path, verbose: bool) -> dict:
    log("P4", "Resource enumeration (dirs, endpoints)")
    results = {"phase": "phase4", "endpoints": [], "interesting_paths": []}

    if not web_targets:
        log("P4", "No web targets, skipping", "warn")
        return results

    base_url = web_targets[0]

    # gobuster
    if tool_available("gobuster"):
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/dirb/wordlists/common.txt"
        if os.path.exists(wordlist):
            gobuster_file = output_dir / "gobuster.txt"
            rc, out, err = run_cmd(
                ["gobuster", "dir", "-u", base_url, "-w", wordlist,
                 "-t", "20", "-q", "-o", str(gobuster_file)],
                timeout=180,
            )
            if gobuster_file.exists():
                lines = [l.strip() for l in gobuster_file.read_text().splitlines() if l.strip()]
                results["endpoints"].extend(lines[:50])
                log("P4", f"gobuster: {len(lines)} paths found", "ok")
        else:
            log("P4", "dirb wordlist not found", "warn")
    else:
        log("P4", "gobuster not available", "warn")

    # katana crawl
    if tool_available("katana"):
        katana_file = output_dir / "katana_urls.txt"
        rc, out, err = run_cmd(
            ["katana", "-u", base_url, "-d", "3", "-silent", "-o", str(katana_file)],
            timeout=120,
        )
        if katana_file.exists():
            urls = [l.strip() for l in katana_file.read_text().splitlines() if l.strip()]
            results["endpoints"].extend(urls[:50])
            log("P4", f"katana: {len(urls)} URLs crawled", "ok")
    else:
        log("P4", "katana not available", "warn")

    # Deduplicate endpoints
    results["endpoints"] = list(dict.fromkeys(results["endpoints"]))

    # Flag interesting paths
    interesting_patterns = [
        r"/admin", r"/api/", r"/wp-", r"/phpmy", r"/.git", r"/backup",
        r"/config", r"/debug", r"/test", r"/dev", r"/swagger",
    ]
    for ep in results["endpoints"]:
        for pat in interesting_patterns:
            if re.search(pat, ep, re.IGNORECASE):
                results["interesting_paths"].append(ep)
                break

    log("P4", f"Done: {len(results['endpoints'])} endpoints, {len(results['interesting_paths'])} interesting", "ok")
    return results


# ── Phase 5: Vuln Scanning ──────────────────────────────────────────────────

def phase5_vuln_scan(web_targets: list, output_dir: Path, oss_path: str, verbose: bool) -> dict:
    log("P5", "Vulnerability scanning")
    results = {"phase": "phase5", "cves_found": [], "misconfigs": [], "secrets": []}

    cve_file = output_dir / "nuclei_cve.txt"
    misconfig_file = output_dir / "nuclei_misconfig.txt"
    cve_ids_file = output_dir / "cve_ids_found.txt"

    # nuclei CVE scan
    if tool_available("nuclei") and web_targets:
        base_url = web_targets[0]
        rc, out, err = run_cmd(
            ["nuclei", "-u", base_url, "-tags", "cve", "-severity", "critical,high",
             "-silent", "-o", str(cve_file)],
            timeout=300,
        )
        if cve_file.exists():
            content = cve_file.read_text()
            # Extract CVE IDs
            cve_ids = list(set(re.findall(r"CVE-\d{4}-\d+", content, re.IGNORECASE)))
            cve_ids = [c.upper() for c in cve_ids]
            results["cves_found"] = cve_ids
            log("P5", f"nuclei CVE: {len(cve_ids)} CVEs found", "ok")

        # nuclei misconfiguration scan
        rc2, out2, err2 = run_cmd(
            ["nuclei", "-u", base_url, "-tags", "misconfig,exposure",
             "-severity", "critical,high", "-silent", "-o", str(misconfig_file)],
            timeout=300,
        )
        if misconfig_file.exists():
            lines = [l for l in misconfig_file.read_text().splitlines() if l.strip()]
            results["misconfigs"] = lines[:20]
            log("P5", f"nuclei misconfig: {len(lines)} findings", "ok")
    else:
        log("P5", "nuclei not available or no web targets", "warn")

    # trufflehog (OSS mode)
    if oss_path and tool_available("trufflehog"):
        rc, out, err = run_cmd(
            ["trufflehog", "filesystem", oss_path, "--only-verified"],
            timeout=120,
        )
        if out.strip():
            results["secrets"] = out.strip().splitlines()[:10]
            log("P5", f"trufflehog: {len(results['secrets'])} secrets found", "warn")
    elif oss_path:
        log("P5", "trufflehog not available", "warn")

    # Write CVE IDs file for Phase 6
    if results["cves_found"]:
        cve_ids_file.write_text("\n".join(results["cves_found"]))
        log("P5", f"Wrote {len(results['cves_found'])} CVE IDs to {cve_ids_file.name}", "ok")
    else:
        cve_ids_file.write_text("")

    log("P5", f"Done: {len(results['cves_found'])} CVEs, {len(results['misconfigs'])} misconfigs, {len(results['secrets'])} secrets", "ok")
    return results


# ── Phase 6: MITRE Enrichment ───────────────────────────────────────────────

def phase6_mitre_enrichment(cve_ids: list, output_dir: Path, offline: bool, verbose: bool) -> dict:
    log("P6", f"MITRE enrichment for {len(cve_ids)} CVEs")
    results = {"phase": "phase6", "enriched": [], "attack_techniques": []}
    mitre_file = output_dir / "mitre_enrichment.json"

    if not cve_ids:
        log("P6", "No CVEs to enrich, skipping", "warn")
        mitre_file.write_text(json.dumps({"results": [], "note": "No CVEs found"}, indent=2))
        return results

    if not MITRE_MAPPER.exists():
        log("P6", f"mitre_mapper.py not found at {MITRE_MAPPER}", "error")
        return results

    cmd = [sys.executable, str(MITRE_MAPPER)] + cve_ids + ["--json"]
    if offline:
        cmd.append("--offline")

    rc, out, err = run_cmd(cmd, timeout=120)
    if err and verbose:
        for line in err.strip().splitlines():
            log("P6", f"  {line}", "warn")

    if rc == 0 and out.strip():
        try:
            data = json.loads(out)
            mitre_file.write_text(json.dumps(data, indent=2))
            results["enriched"] = data.get("results", [])

            # Collect all unique ATT&CK techniques
            techniques = set()
            for r in results["enriched"]:
                for cwe in r.get("cwes", []):
                    for capec in cwe.get("capecs", []):
                        for tech in capec.get("attack_techniques", []):
                            techniques.add(f"{tech['technique_id']} ({tech['name']})")
            results["attack_techniques"] = sorted(techniques)
            log("P6", f"Enriched {len(results['enriched'])} CVEs → {len(techniques)} ATT&CK techniques", "ok")
        except json.JSONDecodeError as e:
            log("P6", f"Failed to parse mitre_mapper output: {e}", "error")
    else:
        log("P6", f"mitre_mapper failed (rc={rc}): {err[:100]}", "error")
        # Offline fallback
        if not offline:
            log("P6", "Retrying in offline mode...", "warn")
            return phase6_mitre_enrichment(cve_ids, output_dir, offline=True, verbose=verbose)

    return results


# ── Report Generation ────────────────────────────────────────────────────────

def generate_report(target: str, mode: str, phase_results: list, output_dir: Path):
    """Merge all phase results into recon_report.json and recon_notes.md."""
    report = {
        "target": target,
        "mode": mode,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline_phases_completed": [],
        "dns_a": [],
        "subdomains": [],
        "live_hosts": [],
        "open_ports": [],
        "technologies": [],
        "waf_detected": False,
        "endpoints": [],
        "interesting_paths": [],
        "cves_found": [],
        "misconfigs": [],
        "secrets_found": 0,
        "mitre_enrichment_file": "mitre_enrichment.json",
        "attack_techniques": [],
        "potential_vectors": [],
    }

    for pr in phase_results:
        phase = pr.get("phase", "")
        report["pipeline_phases_completed"].append(phase)

        if phase == "phase1":
            report["subdomains"] = pr.get("subdomains", [])
            report["live_hosts"] = pr.get("live_hosts", [])
            report["dns_a"] = pr.get("dns_a", [])
        elif phase == "phase2":
            report["open_ports"] = pr.get("open_ports", [])
        elif phase == "phase3":
            report["technologies"] = pr.get("technologies", [])
            report["waf_detected"] = pr.get("waf_detected", False)
        elif phase == "phase4":
            report["endpoints"] = pr.get("endpoints", [])[:30]
            report["interesting_paths"] = pr.get("interesting_paths", [])
        elif phase == "phase5":
            report["cves_found"] = pr.get("cves_found", [])
            report["misconfigs"] = pr.get("misconfigs", [])[:10]
            report["secrets_found"] = len(pr.get("secrets", []))
        elif phase == "phase6":
            report["attack_techniques"] = pr.get("attack_techniques", [])

    # Derive potential vectors
    vectors = []
    if report["cves_found"]:
        vectors.append(f"Known CVEs: {', '.join(report['cves_found'][:3])}")
    if report["interesting_paths"]:
        vectors.append(f"Interesting paths: {', '.join(report['interesting_paths'][:3])}")
    if report["waf_detected"]:
        vectors.append("WAF detected — rate-limit attacks")
    if report["secrets_found"] > 0:
        vectors.append(f"{report['secrets_found']} secrets detected")
    report["potential_vectors"] = vectors

    # Save JSON report
    report_file = output_dir / "recon_report.json"
    report_file.write_text(json.dumps(report, indent=2))

    # Save Markdown notes
    notes_file = output_dir / "recon_notes.md"
    with open(notes_file, "w") as f:
        f.write(f"# Recon Notes: {target}\n\n")
        f.write(f"**Mode**: {mode}  \n")
        f.write(f"**Timestamp**: {report['timestamp']}  \n")
        f.write(f"**Phases**: {', '.join(report['pipeline_phases_completed'])}\n\n")
        f.write("## Key Findings\n")
        for v in vectors:
            f.write(f"- {v}\n")
        f.write("\n## Open Ports\n")
        for p in report["open_ports"]:
            f.write(f"- {p['port']}/{p['proto']} {p['service']} {p['version']}\n")
        f.write("\n## Technologies\n")
        for t in report["technologies"]:
            f.write(f"- {t}\n")
        f.write("\n## CVEs Found\n")
        for c in report["cves_found"]:
            f.write(f"- {c}\n")
        f.write("\n## ATT&CK Techniques\n")
        for t in report["attack_techniques"]:
            f.write(f"- {t}\n")
        f.write("\n## Interesting Paths\n")
        for p in report["interesting_paths"]:
            f.write(f"- {p}\n")
        f.write("\n## Recommended Next Steps\n")
        f.write("1. Exploit highest CVSS CVEs first\n")
        f.write("2. Investigate interesting paths for auth bypass / info disclosure\n")
        f.write("3. Check misconfigurations for exploitable exposures\n")

    log("REPORT", f"Saved: {report_file}", "ok")
    log("REPORT", f"Saved: {notes_file}", "ok")
    return report


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Terminator Recon Pipeline — 6-phase automated reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  network  Standard network target (default)
  oss      Open-source repo scan (skips network phases)
  quick    Fast scan: ports + HTTP + nuclei CVE only

Examples:
  python3 recon_pipeline.py example.com
  python3 recon_pipeline.py example.com --mode quick --output /tmp/recon
  python3 recon_pipeline.py https://github.com/org/repo --mode oss
  python3 recon_pipeline.py 192.168.1.1 --full-scan --offline-mitre
        """,
    )
    parser.add_argument("target", help="Target domain, IP, or GitHub repo URL")
    parser.add_argument(
        "--mode", choices=["network", "oss", "quick"], default="network",
        help="Scan mode (default: network)"
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="Output directory (default: recon_output/<target>/<timestamp>)"
    )
    parser.add_argument(
        "--full-scan", action="store_true",
        help="Run full port scan (-p-) in Phase 2"
    )
    parser.add_argument(
        "--offline-mitre", action="store_true",
        help="Use offline mode for MITRE enrichment (skip NVD API)"
    )
    parser.add_argument(
        "--phases", nargs="+",
        help="Run specific phases only (e.g. --phases phase2 phase5 phase6)"
    )
    parser.add_argument(
        "--oss-path", default=None,
        help="Local path to OSS repo for secret scanning in Phase 5"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose output"
    )
    args = parser.parse_args()

    # Normalize target
    target = args.target.strip().rstrip("/")
    domain = re.sub(r"^https?://", "", target).split("/")[0]

    # Set up output directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = PROJECT_DIR / "recon_output" / domain / ts
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{BOLD}{CYAN}=== Terminator Recon Pipeline ==={RESET}")
    print(f"Target: {target}")
    print(f"Mode: {args.mode}")
    print(f"Output: {output_dir}\n")

    config = load_config()
    phase_results = []
    run_phases = set(args.phases) if args.phases else None

    def should_run(phase_name: str) -> bool:
        if run_phases:
            return phase_name in run_phases
        if args.mode == "quick":
            return phase_name in {"phase0", "phase2", "phase3", "phase5", "phase6"}
        if args.mode == "oss":
            return phase_name not in {"phase2", "phase3"}
        return True

    start = time.time()

    # Phase 0
    if should_run("phase0"):
        r = phase0_duplicate_prescreen(domain, output_dir, args.verbose)
        phase_results.append(r)
        if r.get("duplicate_risk") == "HIGH" and args.mode != "oss":
            log("P0", "HIGH duplicate risk — consider stopping. Continuing anyway.", "warn")

    # Phase 1
    p1_result = {"phase": "phase1", "subdomains": [], "live_hosts": [], "urls": [], "dns_a": []}
    if should_run("phase1"):
        p1_result = phase1_domain_discovery(domain, output_dir, args.verbose)
        phase_results.append(p1_result)

    # Phase 2 + Phase 3 in parallel (if network mode)
    p2_result = {"phase": "phase2", "open_ports": [], "nmap_output": ""}
    p3_result = {"phase": "phase3", "web_targets": [], "technologies": [], "waf_detected": False}

    run_p2 = should_run("phase2")
    run_p3 = should_run("phase3")

    if run_p2 and run_p3:
        log("ORCH", "Running Phase 2 → Phase 3 sequentially (Phase 3 needs port data)")
        p2_result = phase2_port_scan(domain, output_dir, args.full_scan, args.verbose)
        p3_result = phase3_http_probe(domain, p2_result.get("open_ports", []), output_dir, args.verbose)
        phase_results.extend([p2_result, p3_result])
    else:
        if run_p2:
            p2_result = phase2_port_scan(domain, output_dir, args.full_scan, args.verbose)
            phase_results.append(p2_result)
        if run_p3:
            p3_result = phase3_http_probe(domain, p2_result.get("open_ports", []), output_dir, args.verbose)
            phase_results.append(p3_result)

    # Phase 4
    p4_result = {"phase": "phase4", "endpoints": [], "interesting_paths": []}
    if should_run("phase4"):
        p4_result = phase4_enumeration(p3_result.get("web_targets", []), output_dir, args.verbose)
        phase_results.append(p4_result)

    # Phase 5
    p5_result = {"phase": "phase5", "cves_found": [], "misconfigs": [], "secrets": []}
    if should_run("phase5"):
        p5_result = phase5_vuln_scan(
            p3_result.get("web_targets", []),
            output_dir,
            args.oss_path,
            args.verbose,
        )
        phase_results.append(p5_result)

    # Phase 6
    if should_run("phase6"):
        p6_result = phase6_mitre_enrichment(
            p5_result.get("cves_found", []),
            output_dir,
            args.offline_mitre,
            args.verbose,
        )
        phase_results.append(p6_result)

    # Generate final report
    report = generate_report(target, args.mode, phase_results, output_dir)

    elapsed = time.time() - start
    print(f"\n{BOLD}{GREEN}=== Recon Complete ({elapsed:.1f}s) ==={RESET}")
    print(f"Open ports: {len(report['open_ports'])}")
    print(f"Subdomains: {len(report['subdomains'])}")
    print(f"CVEs found: {len(report['cves_found'])}")
    print(f"ATT&CK techniques: {len(report['attack_techniques'])}")
    print(f"Output: {output_dir}")


if __name__ == "__main__":
    main()
