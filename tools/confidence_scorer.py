#!/usr/bin/env python3
"""
Confidence Scorer for Terminator Bug Bounty Pipeline.
Automates analyst's 10-point Confidence Questionnaire scoring.
Reads vulnerability_candidates.md or takes structured JSON input.
"""

import argparse
import json
import sys
from pathlib import Path

QUESTIONS = [
    ("user_controlled_input", "User-controlled input reaches the vulnerable code path?"),
    ("no_sanitization", "No input validation/sanitization between input and sink?"),
    ("public_poc_exists", "Public PoC or similar CVE exists?"),
    ("pre_auth", "Vulnerability is pre-authentication (no login required)?"),
    ("high_impact", "Impact is HIGH+ (RCE, auth bypass, data exfil)?"),
    ("variant_confirmed", "Confirmed via variant analysis (same pattern as known CVE)?"),
    ("violates_own_rules", "The project's own security rules prohibit this pattern?"),
    ("default_config", "Reachable in default configuration (no special setup)?"),
    ("latest_version", "Affects latest released version (not just dev branch)?"),
    ("full_flow_traced", "Complete source→sink data flow traced?"),
]

THRESHOLDS = {
    "exploit_first": (8, 10),
    "investigate": (5, 7),
    "deprioritize": (1, 4),
    "drop": (0, 0),
}

TIER_MAP = {
    (8, 10): ("EXPLOIT FIRST", "Send to exploiter immediately"),
    (5, 7): ("INVESTIGATE", "Deeper analysis needed before exploiter"),
    (1, 4): ("DEPRIORITIZE", "Low value — only pursue if time allows"),
    (0, 0): ("DROP", "No exploitation path — do not report"),
}

MITRE_TECHNIQUE_PRIORITY = {
    "T1190": "CRITICAL",
    "T1059": "CRITICAL",
    "T1059.001": "CRITICAL",
    "T1059.003": "CRITICAL",
    "T1059.007": "HIGH",
    "T1203": "HIGH",
    "T1068": "HIGH",
    "T1078": "HIGH",
    "T1548": "HIGH",
    "T1556": "HIGH",
    "T1189": "MEDIUM",
    "T1539": "MEDIUM",
    "T1185": "MEDIUM",
    "T1565": "MEDIUM",
    "T1083": "LOW",
    "T1499": "LOW",
    "T1027": "LOW",
    "T1595": "LOW",
    "T1590": "LOW",
    "T1592": "LOW",
}


def score_finding(answers: dict) -> dict:
    """Score a finding based on the 10-question checklist."""
    score = 0
    details = []
    for key, question in QUESTIONS:
        answered = answers.get(key, False)
        points = 1 if answered else 0
        score += points
        details.append({
            "question": question,
            "answer": answered,
            "points": points,
        })

    # Determine tier
    tier_label = "DROP"
    tier_action = "No exploitation path — do not report"
    for (low, high), (label, action) in TIER_MAP.items():
        if low <= score <= high:
            tier_label = label
            tier_action = action
            break

    return {
        "score": score,
        "max_score": len(QUESTIONS),
        "tier": tier_label,
        "action": tier_action,
        "send_to_exploiter": score >= 5,
        "details": details,
    }


def enrich_with_mitre(finding: dict, mitre_file: Path) -> dict:
    """Enrich a finding with MITRE ATT&CK technique priority from mitre_enrichment.json."""
    if not mitre_file.exists():
        return finding

    try:
        data = json.loads(mitre_file.read_text())
    except Exception:
        return finding

    cve_id = (finding.get("cve_id") or "").upper()
    if not cve_id:
        return finding

    for result in data.get("results", []):
        if result.get("cve_id", "").upper() == cve_id:
            techniques = set()
            for cwe in result.get("cwes", []):
                for capec in cwe.get("capecs", []):
                    for tech in capec.get("attack_techniques", []):
                        techniques.add(tech["technique_id"])

            if techniques:
                # Determine highest priority from MITRE techniques
                priorities = [MITRE_TECHNIQUE_PRIORITY.get(t, "UNKNOWN") for t in techniques]
                priority_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
                highest = min(priorities, key=lambda p: priority_order.index(p) if p in priority_order else 99)
                finding["mitre_techniques"] = sorted(techniques)
                finding["mitre_priority"] = highest
                # If MITRE says CRITICAL and score is 5+, boost recommendation
                if highest == "CRITICAL" and finding.get("score", 0) >= 5:
                    finding["mitre_boost"] = True
            break

    return finding


def interactive_score(finding_name: str, cve_id: str = None) -> dict:
    """Interactive mode: prompt user for each question."""
    print(f"\n{'='*60}")
    print(f"Scoring: {finding_name}")
    if cve_id:
        print(f"CVE: {cve_id}")
    print(f"{'='*60}")
    print("Answer each question (y/n/?):\n")

    answers = {}
    for key, question in QUESTIONS:
        while True:
            resp = input(f"  {question}\n  > ").strip().lower()
            if resp in ("y", "yes", "1"):
                answers[key] = True
                break
            elif resp in ("n", "no", "0"):
                answers[key] = False
                break
            elif resp == "?":
                print("  (Enter y for Yes, n for No)")
            else:
                print("  Invalid input. Enter y or n.")

    return answers


def format_result(name: str, result: dict, cve_id: str = None) -> str:
    """Format scoring result as human-readable text."""
    lines = []
    lines.append(f"\n{'='*60}")
    lines.append(f"Finding: {name}")
    if cve_id:
        lines.append(f"CVE: {cve_id}")
    lines.append(f"Score: {result['score']}/{result['max_score']}")
    lines.append(f"Tier: {result['tier']}")
    lines.append(f"Action: {result['action']}")
    lines.append(f"Send to Exploiter: {'YES' if result['send_to_exploiter'] else 'NO'}")

    if result.get("mitre_techniques"):
        lines.append(f"ATT&CK Techniques: {', '.join(result['mitre_techniques'])}")
        lines.append(f"MITRE Priority: {result.get('mitre_priority', 'N/A')}")
        if result.get("mitre_boost"):
            lines.append("  *** MITRE BOOST: CRITICAL technique + score>=5 → Prioritize ***")

    lines.append(f"\nBreakdown:")
    for d in result["details"]:
        mark = "+" if d["answer"] else "-"
        lines.append(f"  [{mark}] {d['question']}")

    lines.append(f"{'='*60}")
    return "\n".join(lines)


def batch_score_from_json(input_file: Path, mitre_file: Path) -> list:
    """Score multiple findings from a JSON file."""
    data = json.loads(input_file.read_text())
    findings = data if isinstance(data, list) else data.get("findings", [])
    results = []

    for finding in findings:
        name = finding.get("name", "Unknown")
        cve_id = finding.get("cve_id", None)
        answers = finding.get("answers", {})

        scored = score_finding(answers)
        scored["name"] = name
        scored["cve_id"] = cve_id

        # Enrich with MITRE data
        scored = enrich_with_mitre(scored, mitre_file)
        results.append(scored)

    # Sort by score descending
    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Terminator Confidence Scorer — automate analyst 10-point questionnaire",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive scoring for a single finding
  python3 confidence_scorer.py --name "Log4j RCE" --cve CVE-2021-44228

  # Batch scoring from JSON file
  python3 confidence_scorer.py --input findings.json --json

  # With MITRE enrichment from scout Phase 6
  python3 confidence_scorer.py --input findings.json --mitre mitre_enrichment.json --json

Input JSON format:
  [
    {
      "name": "SQL Injection in /api/users",
      "cve_id": "CVE-2023-1234",
      "answers": {
        "user_controlled_input": true,
        "no_sanitization": true,
        "public_poc_exists": true,
        "pre_auth": false,
        "high_impact": true,
        "variant_confirmed": false,
        "violates_own_rules": true,
        "default_config": true,
        "latest_version": true,
        "full_flow_traced": true
      }
    }
  ]
        """,
    )
    parser.add_argument("--name", help="Finding name (interactive mode)")
    parser.add_argument("--cve", help="CVE ID (optional, for MITRE enrichment)")
    parser.add_argument("--input", "-i", help="JSON file with findings to batch-score")
    parser.add_argument("--mitre", "-m", default="mitre_enrichment.json",
                        help="Path to mitre_enrichment.json (default: mitre_enrichment.json)")
    parser.add_argument("--json", "-j", action="store_true", dest="json_output",
                        help="Output JSON instead of human-readable text")
    parser.add_argument("--threshold", "-t", type=int, default=5,
                        help="Minimum score to send to exploiter (default: 5)")
    parser.add_argument("--list-questions", action="store_true",
                        help="List all 10 questions and exit")
    args = parser.parse_args()

    if args.list_questions:
        print("10-Point Confidence Questionnaire:")
        for i, (key, q) in enumerate(QUESTIONS, 1):
            print(f"  {i:2d}. [{key}] {q}")
        return

    mitre_file = Path(args.mitre)

    if args.input:
        # Batch mode
        input_file = Path(args.input)
        if not input_file.exists():
            print(f"[ERROR] Input file not found: {input_file}", file=sys.stderr)
            sys.exit(1)

        results = batch_score_from_json(input_file, mitre_file)

        if args.json_output:
            output = {
                "tool": "confidence_scorer",
                "threshold": args.threshold,
                "total_findings": len(results),
                "send_to_exploiter": sum(1 for r in results if r["score"] >= args.threshold),
                "drop_count": sum(1 for r in results if r["score"] < args.threshold),
                "findings": results,
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"\nConfidence Scoring Results ({len(results)} findings)")
            print(f"Threshold: {args.threshold}/10 to send to exploiter\n")
            for r in results:
                print(format_result(r["name"], r, r.get("cve_id")))
            # Summary
            exploitable = [r for r in results if r["score"] >= args.threshold]
            dropped = [r for r in results if r["score"] < args.threshold]
            print(f"\nSUMMARY: {len(exploitable)} → exploiter, {len(dropped)} → dropped")
            if exploitable:
                print("Send to exploiter (highest first):")
                for r in exploitable:
                    boost = " [MITRE BOOST]" if r.get("mitre_boost") else ""
                    print(f"  {r['score']}/10 {r['tier']}: {r['name']}{boost}")
    else:
        # Interactive mode (single finding)
        name = args.name or input("Finding name: ").strip()
        cve_id = args.cve or None

        answers = interactive_score(name, cve_id)
        result = score_finding(answers)
        result["name"] = name
        result["cve_id"] = cve_id

        if cve_id:
            result = enrich_with_mitre(result, mitre_file)

        if args.json_output:
            print(json.dumps(result, indent=2))
        else:
            print(format_result(name, result, cve_id))


if __name__ == "__main__":
    main()
