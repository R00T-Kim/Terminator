from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools import bb_preflight, bb_research_sync


RESEARCH_REGISTRY_SAMPLE = [
    {"title": "Program page", "authority": "official", "applicability": "campaign", "domain": "target.example", "url": "https://target.example", "source_type": "page", "surface_signals": {"auth": True}, "bug_classes": ["auth-session"]},
    {"title": "Docs", "authority": "official", "applicability": "campaign", "domain": "target.example", "url": "https://target.example/docs", "source_type": "docs", "surface_signals": {"docs": True, "workflow": True}, "bug_classes": ["workflow"]},
    {"title": "Release notes", "authority": "official", "applicability": "campaign", "domain": "target.example", "url": "https://target.example/release-notes", "source_type": "release-notes", "surface_signals": {"changelog": True}, "bug_classes": ["variant"]},
    {"title": "Engineering blog", "authority": "official", "applicability": "campaign", "domain": "target.example", "url": "https://target.example/engineering", "source_type": "blog", "surface_signals": {"workflow": True}, "bug_classes": ["workflow"]},
    {"title": "Project Naptime", "authority": "paper", "applicability": "design", "domain": "projectzero.google", "url": "https://projectzero.google/2024/06/project-naptime.html", "source_type": "paper", "surface_signals": {}, "bug_classes": ["agentic", "validation"]},
    {"title": "MAPTA", "authority": "paper", "applicability": "design", "domain": "arxiv.org", "url": "https://arxiv.org/abs/2508.20816", "source_type": "paper", "surface_signals": {}, "bug_classes": ["agentic", "validation"]},
    {"title": "HackerOne HPSR", "authority": "platform", "applicability": "tactic", "domain": "hackerone.com", "url": "https://www.hackerone.com/blog/2025-hpsr-researcher-signals", "source_type": "blog", "surface_signals": {}, "bug_classes": ["workflow"]},
    {"title": "Intigriti reports", "authority": "platform", "applicability": "tactic", "domain": "intigriti.com", "url": "https://www.intigriti.com/researchers/blog/hacking-tools/writing-effective-bug-bounty-reports", "source_type": "blog", "surface_signals": {}, "bug_classes": ["validation"]},
    {"title": "Heelan industrialisation", "authority": "practitioner", "applicability": "design", "domain": "sean.heelan.io", "url": "https://sean.heelan.io/2026/01/18/on-the-coming-industrialisation-of-exploit-generation-with-llms/", "source_type": "blog", "surface_signals": {}, "bug_classes": ["validation"]},
    {"title": "Semgrep variant analysis", "authority": "practitioner", "applicability": "tactic", "domain": "semgrep.dev", "url": "https://semgrep.dev/blog/2025/finding-more-zero-days-through-variant-analysis/", "source_type": "blog", "surface_signals": {}, "bug_classes": ["variant"]},
]


def _write_research_artifacts(target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / bb_preflight.RESEARCH_REGISTRY).write_text(
        json.dumps(RESEARCH_REGISTRY_SAMPLE, indent=2),
        encoding="utf-8",
    )
    (target_dir / bb_preflight.RESEARCH_BRIEF).write_text(
        "# Research Brief\n\nThis brief ties official program docs, release notes, platform intelligence, and practitioner prior art into a concrete hunt packet for the target.\n",
        encoding="utf-8",
    )
    (target_dir / bb_preflight.RESEARCH_GAP_MATRIX).write_text(
        "# Research Gap Matrix\n\n| Class | Public signal | Target signal | Gap | Candidate angle |\n|------|---------------|---------------|-----|-----------------|\n| Variant hunting | release note present | repo/release evidence present | covered | Mine recent fixes |\n",
        encoding="utf-8",
    )
    (target_dir / bb_preflight.RESEARCH_HYPOTHESES).write_text(
        "# Research Hypotheses\n\n"
        "## Variant hypotheses\n- Review fresh fixes for incomplete patch coverage.\n\n"
        "## Workflow/Auth/GraphQL hypotheses\n- Model auth and billing flows for skip-step and replay abuse.\n\n"
        "## PoC/validation hypotheses\n- Promote invariant violations into live differential proofs using the verified curl template.\n\n"
        "## Why now\n- Recent release notes and engineering posts suggest fresh surface worth testing.\n\n"
        "## What would kill this hypothesis\n- The feature is disabled or excluded by program rules.\n",
        encoding="utf-8",
    )


def test_init_creates_research_templates(tmp_path: Path) -> None:
    target_dir = tmp_path / "mission"
    result = bb_preflight.init(str(target_dir))

    assert result == 0
    assert (target_dir / bb_preflight.RULES_FILE).exists()
    assert (target_dir / bb_preflight.ENDPOINT_MAP).exists()
    assert (target_dir / bb_preflight.RESEARCH_BRIEF).exists()
    assert (target_dir / bb_preflight.RESEARCH_GAP_MATRIX).exists()
    assert (target_dir / bb_preflight.RESEARCH_HYPOTHESES).exists()
    assert (target_dir / bb_preflight.RESEARCH_REGISTRY).exists()


def test_research_check_passes_with_required_mix(tmp_path: Path) -> None:
    target_dir = tmp_path / "mission"
    _write_research_artifacts(target_dir)

    assert bb_preflight.research_check(str(target_dir)) == 0


def test_hypothesis_check_fails_when_queue_missing(tmp_path: Path) -> None:
    target_dir = tmp_path / "mission"
    target_dir.mkdir(parents=True)
    (target_dir / bb_preflight.RESEARCH_HYPOTHESES).write_text(
        "# Research Hypotheses\n\n## Variant hypotheses\n- one\n",
        encoding="utf-8",
    )

    assert bb_preflight.hypothesis_check(str(target_dir)) == 1


def test_citation_check_requires_target_specific_context(tmp_path: Path) -> None:
    target_dir = tmp_path / "mission"
    _write_research_artifacts(target_dir)
    submission_dir = target_dir / "submission" / "demo"
    submission_dir.mkdir(parents=True)
    report = submission_dir / "report.md"
    report.write_text(
        "# Example\n\nNo useful sections or citations here.\n",
        encoding="utf-8",
    )

    assert bb_preflight.citation_check(str(submission_dir), str(report)) == 1

    report.write_text(
        "# Example\n\n"
        "## Program Scope Alignment\n"
        "The report stays in scope per https://target.example/security and the published submission rules.\n\n"
        "## Target-Specific Context\n"
        "Release notes at https://target.example/release-notes show the affected auth workflow and target-specific behavior.\n\n"
        "## Prior Art & Differentiation\n"
        "This differs from prior art documented at https://www.hackerone.com/blog/2025-hpsr-researcher-signals because the issue is target-specific and tied to a fresh release.\n",
        encoding="utf-8",
    )

    assert bb_preflight.citation_check(str(submission_dir), str(report)) == 0


def test_target_sync_writes_artifacts_from_stubbed_sources(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    index_path = tmp_path / "knowledge" / "bounty_research_index.json"
    index_path.parent.mkdir(parents=True)
    index_payload = {
        "entries": [
            {"title": "Design Ref", "url": "https://design.example", "authority": "paper", "applicability": "design", "freshness_days": 10, "bug_classes": ["validation"], "surface_signals": {}, "domain": "design.example"},
            {"title": "Tactic Ref", "url": "https://tactic.example", "authority": "platform", "applicability": "tactic", "freshness_days": 5, "bug_classes": ["workflow"], "surface_signals": {}, "domain": "tactic.example"},
        ]
    }
    index_path.write_text(json.dumps(index_payload), encoding="utf-8")
    monkeypatch.setattr(bb_research_sync, "GLOBAL_INDEX_PATH", index_path)

    def fake_fetch_remote_source(url: str, target_dir: Path, authority: str, applicability: str, **_: object):
        slug = bb_research_sync._slugify(url)
        snapshot = target_dir / "research_sources" / f"{slug}.md"
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_text(f"# Snapshot\n\n{url}\n", encoding="utf-8")
        return {
            "title": slug,
            "url": url,
            "source_type": "docs",
            "authority": authority,
            "applicability": applicability,
            "published_at": "2026-04-23",
            "collected_at": "2026-04-23T00:00:00Z",
            "freshness_days": 0,
            "domain": "target.example",
            "tags": ["graphql"] if "graphql" in url else ["auth-bypass"],
            "bug_classes": ["graphql"] if "graphql" in url else ["auth-session"],
            "surface_signals": {"graphql": "graphql" in url, "auth": True, "workflow": True},
            "target_relevance": 1.0,
            "snapshot_path": str(snapshot.relative_to(target_dir)),
            "indexed_into_knowledge": False,
            "notes": "stubbed",
        }

    monkeypatch.setattr(bb_research_sync, "fetch_remote_source", fake_fetch_remote_source)

    target_dir = tmp_path / "targets" / "demo"
    registry = bb_research_sync.target_sync(
        target_dir=target_dir,
        target_url="https://target.example",
        source_urls=["https://target.example/docs", "https://target.example/graphql"],
        repo_path=None,
        index_knowledge=False,
        limit=2,
    )

    assert registry
    assert (target_dir / "research_source_registry.json").exists()
    assert (target_dir / "research_brief.md").exists()
    assert (target_dir / "research_gap_matrix.md").exists()
    assert (target_dir / "research_hypotheses.md").exists()
    assert "## Workflow/Auth/GraphQL hypotheses" in (target_dir / "research_hypotheses.md").read_text(encoding="utf-8")
