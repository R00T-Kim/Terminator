#!/usr/bin/env python3
"""Generate a low-noise Auth0 cross-tenant test matrix from researcher mappings."""

from __future__ import annotations

import argparse
import re
from itertools import permutations
from pathlib import Path


MAPPING_RE = re.compile(
    r"^\s*-\s*(?P<user>[^:]+):\s*(?P<label>.+?)\s*->\s*(?P<tenant>.+?)\s*$"
)

OPERATIONS = (
    "invite.create",
    "invite.accept",
    "member.role_update",
    "member.revoke",
    "application.read",
    "application.update",
    "connection.read",
    "connection.update",
    "log.read",
    "fga.store.read",
    "fga.store.write",
    "fga.customer.read",
)


def parse_mappings(path: Path) -> list[dict[str, str]]:
    mappings: list[dict[str, str]] = []
    for line in path.read_text().splitlines():
        match = MAPPING_RE.match(line)
        if not match:
            continue
        mappings.append(
            {
                "user": match.group("user").strip(),
                "label": match.group("label").strip(),
                "tenant": match.group("tenant").strip(),
            }
        )
    if len(mappings) < 2:
        raise ValueError("expected at least two user->tenant mappings")
    return mappings


def render_markdown(mappings: list[dict[str, str]]) -> str:
    lines = [
        "# Auth0 Cross-Tenant Test Matrix",
        "",
        "Generated from `researcher_tenant_map.md`. Use this as a manual checklist only.",
        "",
        "## Participants",
        "",
        "| User | Login Label | Default Tenant |",
        "|------|-------------|----------------|",
    ]
    for mapping in mappings:
        lines.append(
            f"| {mapping['user']} | {mapping['label']} | {mapping['tenant']} |"
        )

    lines.extend(
        [
            "",
            "## Baseline Self-Flows",
            "",
            "| Actor | Tenant | Operation Family | Status | Evidence |",
            "|-------|--------|------------------|--------|----------|",
        ]
    )
    for mapping in mappings:
        for family in ("member", "application", "connection", "logs", "fga"):
            lines.append(
                f"| {mapping['user']} | {mapping['tenant']} | {family} | TODO | |"
            )

    lines.extend(
        [
            "",
            "## Cross-Tenant Tamper Cases",
            "",
            "| Actor | Actor Tenant | Foreign Tenant | Operation | Status | Evidence |",
            "|-------|--------------|----------------|-----------|--------|----------|",
        ]
    )
    for actor, target in permutations(mappings, 2):
        for operation in OPERATIONS:
            lines.append(
                f"| {actor['user']} | {actor['tenant']} | {target['tenant']} | {operation} | TODO | |"
            )

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- Keep testing manual-only. No Burp scan modes and no high-rate replay.",
            "- For each row, store the exact request path, object ID shape, and whether the response was `SAFE`, `TESTED`, or `VULN`.",
            "- Prioritize `invite.accept`, `member.role_update`, `application.read/update`, and `fga.store/customer` rows first.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tenant-map",
        default="targets/auth0/evidence/researcher_tenant_map.md",
        help="Markdown file containing user->tenant mappings",
    )
    parser.add_argument(
        "--output",
        default="targets/auth0/evidence/cross_tenant_test_matrix.md",
        help="Markdown output path",
    )
    args = parser.parse_args()

    mappings = parse_mappings(Path(args.tenant_map))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(mappings))
    print(f"WROTE: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
