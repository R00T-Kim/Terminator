#!/usr/bin/env python3
"""
Terminator Report Generator - SARIF + PDF output
Usage:
  python3 tools/report_generator.py --report-dir reports/<timestamp> [--sarif] [--pdf] [--all]
  python3 tools/report_generator.py --summary-json reports/<ts>/summary.json [--sarif] [--pdf]
"""

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ── SARIF Generator ────────────────────────────────────────────────────────────

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}

SEVERITY_TO_RANK = {
    "critical": 100.0,
    "high": 75.0,
    "medium": 50.0,
    "low": 25.0,
    "info": 0.0,
}


def parse_findings_from_log(log_path: Path) -> list[dict]:
    """Extract [SEVERITY] tagged findings from session.log."""
    findings = []
    if not log_path.exists():
        return findings

    pattern = re.compile(
        r'\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.+)', re.IGNORECASE
    )
    seen = set()
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            m = pattern.search(line)
            if m:
                severity = m.group(1).lower()
                message = m.group(2).strip()
                key = (severity, message)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "severity": severity,
                        "message": message,
                        "line": lineno,
                        "uri": log_path.name,
                    })
    return findings


def parse_findings_from_final_report(report_path: Path) -> list[dict]:
    """Extract CVSS/severity findings from final_report.md or analysis_report.md."""
    findings = []
    if not report_path.exists():
        return findings

    # Match markdown headings like: ## [HIGH] SQL Injection in /api/search
    heading_pattern = re.compile(
        r'^#{1,3}\s+\[?(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]?\s*[-:]?\s*(.+)',
        re.IGNORECASE | re.MULTILINE
    )
    with open(report_path, encoding="utf-8", errors="replace") as fh:
        content = fh.read()

    for m in heading_pattern.finditer(content):
        findings.append({
            "severity": m.group(1).lower(),
            "message": m.group(2).strip(),
            "line": content[:m.start()].count('\n') + 1,
            "uri": report_path.name,
        })
    return findings


def build_sarif(report_dir: Path, tool_name: str = "Terminator") -> dict:
    """Build a SARIF 2.1.0 document from report_dir artifacts."""
    all_findings = []

    # Collect from session.log
    log_path = report_dir / "session.log"
    all_findings.extend(parse_findings_from_log(log_path))

    # Collect from markdown reports
    for md_name in ("final_report.md", "analysis_report.md", "exploit_report.md", "recon.md"):
        md_path = report_dir / md_name
        all_findings.extend(parse_findings_from_final_report(md_path))

    # Deduplicate by (severity, message)
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f["severity"], f["message"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    all_findings = deduped

    # Build rules from unique severities
    rules = {}
    for f in all_findings:
        sev = f["severity"]
        rule_id = f"TERM-{sev.upper()}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f"Terminator{sev.capitalize()}Finding",
                "shortDescription": {"text": f"{sev.upper()} severity finding detected by Terminator"},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_LEVEL.get(sev, "warning"),
                    "rank": SEVERITY_TO_RANK.get(sev, 50.0),
                },
                "properties": {"tags": ["security", sev]},
            }

    # Build results
    results = []
    for f in all_findings:
        sev = f["severity"]
        rule_id = f"TERM-{sev.upper()}"
        result = {
            "ruleId": rule_id,
            "level": SEVERITY_TO_LEVEL.get(sev, "warning"),
            "message": {"text": f["message"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f["uri"],
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": f["line"]},
                    }
                }
            ],
            "rank": SEVERITY_TO_RANK.get(sev, 50.0),
        }
        results.append(result)

    # Read summary.json for metadata
    summary = {}
    summary_path = report_dir / "summary.json"
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text())
        except Exception:
            pass

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "3.0.0",
                        "informationUri": "https://github.com/rootk1m/Terminator",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": summary.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "toolExecutionNotifications": [],
                    }
                ],
                "artifacts": [
                    {"location": {"uri": f["uri"], "uriBaseId": "%SRCROOT%"}}
                    for f in {f["uri"]: f for f in all_findings}.values()
                ],
                "properties": {
                    "mode": summary.get("mode", "unknown"),
                    "target": summary.get("target", ""),
                    "duration_seconds": summary.get("duration_seconds", 0),
                    "flags_found": summary.get("flags_found", []),
                },
            }
        ],
    }
    return sarif_doc


def write_sarif(report_dir: Path) -> Path:
    sarif = build_sarif(report_dir)
    out_path = report_dir / "findings.sarif"
    out_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False))
    print(f"[+] SARIF written: {out_path}")
    return out_path


# ── PDF Generator ──────────────────────────────────────────────────────────────

def write_pdf(report_dir: Path) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        print("[!] reportlab not installed. Run: pip3 install reportlab", file=sys.stderr)
        sys.exit(1)

    out_path = report_dir / "report.pdf"

    # Load summary
    summary = {}
    summary_path = report_dir / "summary.json"
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text())
        except Exception:
            pass

    # Load writeup or final_report
    body_text = ""
    for candidate in ("writeup.md", "final_report.md", "firmware_summary.md", "analysis_report.md"):
        md_path = report_dir / candidate
        if md_path.exists():
            body_text = md_path.read_text(encoding="utf-8", errors="replace")
            break

    # Strip markdown to plain text (basic)
    def md_to_plain(text: str) -> str:
        text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)
        text = re.sub(r'\*\*(.*?)\*\*', r'\1', text)
        text = re.sub(r'\*(.*?)\*', r'\1', text)
        text = re.sub(r'`{1,3}(.*?)`{1,3}', r'\1', text, flags=re.DOTALL)
        text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)
        text = re.sub(r'^[-*+]\s+', '• ', text, flags=re.MULTILINE)
        return text

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    style_title = ParagraphStyle(
        "TermTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=6,
    )
    style_h2 = ParagraphStyle(
        "TermH2",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#16213e"),
        spaceBefore=14,
        spaceAfter=4,
    )
    style_body = ParagraphStyle(
        "TermBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        spaceAfter=4,
    )
    style_meta = ParagraphStyle(
        "TermMeta",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#555555"),
    )
    style_flag = ParagraphStyle(
        "TermFlag",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#006400"),
        fontName="Courier",
        spaceAfter=4,
    )

    SEVERITY_COLORS = {
        "critical": colors.HexColor("#8B0000"),
        "high": colors.HexColor("#CC3300"),
        "medium": colors.HexColor("#E67300"),
        "low": colors.HexColor("#0066CC"),
        "info": colors.HexColor("#555555"),
    }

    story = []

    # Title
    mode = summary.get("mode", "unknown").upper()
    target = summary.get("target", report_dir.name)
    story.append(Paragraph(f"Terminator Security Report", style_title))
    story.append(Paragraph(f"Mode: {mode} | Target: {target}", style_meta))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 0.3 * cm))

    # Metadata table
    ts = summary.get("timestamp", datetime.now(timezone.utc).isoformat())
    duration = summary.get("duration_seconds", 0)
    status = summary.get("status", "unknown")
    exit_code = summary.get("exit_code", 0)

    meta_data = [
        ["Timestamp", ts],
        ["Duration", f"{duration}s ({duration // 60}m {duration % 60}s)"],
        ["Status", status.upper()],
        ["Exit Code", str(exit_code)],
    ]
    meta_table = Table(meta_data, colWidths=[4 * cm, 13 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#16213e")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f5f5f5"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.4 * cm))

    # Flags found
    flags = summary.get("flags_found", [])
    if flags:
        story.append(Paragraph("Flags Found", style_h2))
        for flag in flags:
            story.append(Paragraph(f"  {flag}", style_flag))
        story.append(Spacer(1, 0.2 * cm))

    # Findings summary table
    findings = summary.get("findings", {})
    if any(findings.values()):
        story.append(Paragraph("Findings Summary", style_h2))
        sev_rows = [["Severity", "Count"]]
        for sev in ("critical", "high", "medium", "low", "info"):
            cnt = findings.get(sev, 0)
            if cnt > 0:
                sev_rows.append([sev.upper(), str(cnt)])

        if len(sev_rows) > 1:
            sev_table = Table(sev_rows, colWidths=[4 * cm, 3 * cm])
            ts_cmds = [
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
            for i, row in enumerate(sev_rows[1:], 1):
                sev = row[0].lower()
                clr = SEVERITY_COLORS.get(sev, colors.black)
                ts_cmds.append(("TEXTCOLOR", (0, i), (0, i), clr))
                ts_cmds.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
            sev_table.setStyle(TableStyle(ts_cmds))
            story.append(sev_table)
            story.append(Spacer(1, 0.3 * cm))

    # Detailed findings from SARIF
    sarif_path = report_dir / "findings.sarif"
    if sarif_path.exists():
        try:
            sarif = json.loads(sarif_path.read_text())
            results = sarif.get("runs", [{}])[0].get("results", [])
            if results:
                story.append(Paragraph("Detailed Findings", style_h2))
                for r in results[:50]:  # cap at 50
                    sev_level = r.get("level", "note")
                    sev_map = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
                    sev_label = sev_map.get(sev_level, "INFO")
                    msg = r.get("message", {}).get("text", "")
                    rule = r.get("ruleId", "")
                    clr = SEVERITY_COLORS.get(sev_label.lower(), colors.black)
                    # rank maps back to severity
                    rank = r.get("rank", 0)
                    if rank >= 100:
                        sev_label = "CRITICAL"
                        clr = SEVERITY_COLORS["critical"]
                    elif rank >= 75:
                        sev_label = "HIGH"
                        clr = SEVERITY_COLORS["high"]
                    elif rank >= 50:
                        sev_label = "MEDIUM"
                        clr = SEVERITY_COLORS["medium"]
                    elif rank >= 25:
                        sev_label = "LOW"
                        clr = SEVERITY_COLORS["low"]
                    else:
                        sev_label = "INFO"
                        clr = SEVERITY_COLORS["info"]

                    row_data = [[
                        Paragraph(f'<font color="#{clr.hexval()[2:]}"><b>[{sev_label}]</b></font>', style_body),
                        Paragraph(msg[:200], style_body),
                    ]]
                    row_table = Table(row_data, colWidths=[2.5 * cm, 14.5 * cm])
                    row_table.setStyle(TableStyle([
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                        ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#eeeeee")),
                    ]))
                    story.append(row_table)
        except Exception:
            pass

    story.append(Spacer(1, 0.4 * cm))

    # Body content from markdown
    if body_text:
        story.append(Paragraph("Report Details", style_h2))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
        story.append(Spacer(1, 0.2 * cm))
        plain = md_to_plain(body_text)
        for para in plain.split('\n\n'):
            para = para.strip()
            if para:
                # Escape XML special chars
                para = para.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                try:
                    story.append(Paragraph(para[:1000], style_body))
                except Exception:
                    pass

    # Footer note
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Paragraph(
        f"Generated by Terminator v3.0 | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        style_meta
    ))

    doc.build(story)
    print(f"[+] PDF written: {out_path}")
    return out_path


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Terminator Report Generator — SARIF 2.1.0 + PDF output"
    )
    parser.add_argument("--report-dir", help="Path to report directory (e.g. reports/20260217_120000)")
    parser.add_argument("--sarif", action="store_true", help="Generate SARIF output")
    parser.add_argument("--pdf", action="store_true", help="Generate PDF output")
    parser.add_argument("--all", action="store_true", help="Generate all formats (SARIF + PDF)")
    args = parser.parse_args()

    if not args.report_dir:
        parser.print_help()
        sys.exit(1)

    report_dir = Path(args.report_dir).resolve()
    if not report_dir.exists():
        print(f"[!] Report directory not found: {report_dir}", file=sys.stderr)
        sys.exit(1)

    do_sarif = args.sarif or args.all
    do_pdf = args.pdf or args.all

    if not do_sarif and not do_pdf:
        # default: both
        do_sarif = True
        do_pdf = True

    outputs = []
    if do_sarif:
        outputs.append(write_sarif(report_dir))
    if do_pdf:
        outputs.append(write_pdf(report_dir))

    print(f"\n[+] Report generation complete.")
    for p in outputs:
        print(f"    {p}")


if __name__ == "__main__":
    main()
