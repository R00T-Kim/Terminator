#!/usr/bin/env python3
"""Research-first sync for bug bounty campaigns.

This tool keeps Terminator's bounty pipeline grounded in current public
research before target-specific hunting begins.

Subcommands:
    global-sync
        Fetch curated bug bounty / AEG research seeds into knowledge.db and
        build a reusable research index.

    target-sync <target_dir> --url <target_url>
        Build target-specific research artifacts from a target URL, optional
        source URLs, and optional local repo history.

Outputs (target-sync):
    targets/<target>/research_source_registry.json
    targets/<target>/research_brief.md
    targets/<target>/research_gap_matrix.md
    targets/<target>/research_hypotheses.md
    targets/<target>/research_sources/*.md

The implementation is intentionally conservative: it favors deterministic
keyword extraction, lightweight markdown snapshots, and explicit provenance
over model-generated summaries.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.knowledge_fetcher import (  # type: ignore
    DB_PATH,
    _auto_tag,
    _clean_content,
    _extract_domain,
    _extract_title,
    fetch_url as index_url,
)

SEED_REGISTRY_PATH = PROJECT_ROOT / "tools" / "data" / "bounty_research_seed_urls.json"
GLOBAL_INDEX_PATH = PROJECT_ROOT / "knowledge" / "bounty_research_index.json"
GLOBAL_DIGEST_PATH = PROJECT_ROOT / "knowledge" / "bounty_research_digest.md"
DEFAULT_GNOSIS_ROOT = Path.home() / "gnosis"

TEXT_LIKE_SUFFIXES = {
    ".json", ".xml", ".txt", ".md", ".yaml", ".yml", ".csv", ".rst", ".pdf",
}

BUG_CLASS_KEYWORDS: dict[str, tuple[str, ...]] = {
    "variant": ("cve", "patch", "advisory", "release note", "release-notes", "regression", "variant", "fix"),
    "auth-session": ("auth", "authentication", "authorization", "session", "token", "jwt", "oauth", "oidc", "sso", "mfa", "login", "logout"),
    "access-control": ("access control", "idor", "bola", "bfla", "permission", "rbac", "tenant", "admin", "privilege"),
    "workflow": ("workflow", "state", "business logic", "billing", "payment", "refund", "subscription", "invite", "approval", "checkout", "race"),
    "graphql": ("graphql", "resolver", "introspection", "mutation", "query", "apollo", "graphiql", "persisted query"),
    "validation": ("proof-of-concept", "proof of concept", "proof-of-vulnerability", "proof of vulnerability", "poc", "pov", "validation", "sandbox", "reproduce"),
    "agentic": ("agentic", "agent", "multi-agent", "orchestrator", "validator", "reflection", "tool use"),
}

TARGET_SURFACE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "docs": ("docs", "documentation", "developer", "api reference", "swagger", "openapi"),
    "security": ("security", "security.txt", "advisory", "responsible disclosure", "bug bounty"),
    "changelog": ("changelog", "release note", "release notes", "what's new", "migration"),
    "graphql": BUG_CLASS_KEYWORDS["graphql"],
    "auth": BUG_CLASS_KEYWORDS["auth-session"],
    "workflow": BUG_CLASS_KEYWORDS["workflow"],
}

TARGET_CANDIDATE_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
    "/security",
    "/docs",
    "/developer",
    "/developers",
    "/api",
    "/api/docs",
    "/openapi.json",
    "/swagger.json",
    "/graphql",
    "/graphiql",
    "/playground",
    "/sitemap.xml",
    "/robots.txt",
    "/changelog",
    "/release-notes",
    "/releases",
    "/blog",
    "/engineering",
    "/status",
]

GNOSIS_SOURCE_CANDIDATES = [
    {
        "id": "gnosis-aeg-sota",
        "title": "Gnosis AEG SOTA synthesis",
        "path": "wiki/concepts/aeg-sota-research-synthesis-2026-04.md",
        "authority": "internal-synthesis",
        "applicability": "design",
        "bug_classes": ["agentic", "validation", "variant"],
    },
    {
        "id": "gnosis-llm-pipeline",
        "title": "Gnosis LLM exploit automation pipeline",
        "path": "wiki/concepts/llm-exploit-automation-pipeline.md",
        "authority": "internal-synthesis",
        "applicability": "design",
        "bug_classes": ["agentic", "validation", "workflow"],
    },
    {
        "id": "gnosis-heelan-industrialisation",
        "title": "Gnosis Heelan industrialisation digest",
        "path": "wiki/articles/heelan/2026-01-18-industrialisation-of-exploit-generation-with-llms.md",
        "authority": "internal-synthesis",
        "applicability": "design",
        "bug_classes": ["agentic", "validation"],
    },
    {
        "id": "gnosis-xint-code",
        "title": "Gnosis Xint Code notes",
        "path": "wiki/tools/xint-code.md",
        "authority": "internal-synthesis",
        "applicability": "tactic",
        "bug_classes": ["workflow", "access-control"],
    },
    {
        "id": "gnosis-firmagent",
        "title": "Gnosis FirmAgent notes",
        "path": "wiki/firmware/firmagent.md",
        "authority": "internal-synthesis",
        "applicability": "design",
        "bug_classes": ["agentic", "validation"],
    },
]

LOCAL_RESEARCH_FILES = [
    {
        "id": "terminator-llm-bb-sota",
        "title": "Terminator LLM bug bounty SOTA",
        "path": PROJECT_ROOT / "research" / "llm_bug_bounty_sota_2024_2026.md",
        "authority": "internal-synthesis",
        "applicability": "design",
        "bug_classes": ["variant", "validation", "workflow", "graphql"],
    },
    {
        "id": "terminator-triage-insights",
        "title": "Terminator bug bounty triage insights",
        "path": PROJECT_ROOT / "research" / "bug_bounty_triage_insights_2024_2026.md",
        "authority": "internal-synthesis",
        "applicability": "tactic",
        "bug_classes": ["workflow", "graphql", "access-control", "validation"],
    },
    {
        "id": "terminator-orchestration",
        "title": "Terminator multi-agent orchestration patterns",
        "path": PROJECT_ROOT / "research" / "multi_agent_orchestration_patterns_2024_2026.md",
        "authority": "internal-synthesis",
        "applicability": "design",
        "bug_classes": ["agentic", "validation"],
    },
]


class ResearchSyncError(RuntimeError):
    """Raised when research sync inputs are structurally invalid."""


def _slugify(value: str, max_len: int = 80) -> str:
    value = re.sub(r"https?://", "", value)
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return value[:max_len] or "source"


def _parse_iso_date(raw: str | None) -> date | None:
    if not raw:
        return None
    raw = raw.strip()
    for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    return None


def _freshness_days(published_at: str | None) -> int | None:
    parsed = _parse_iso_date(published_at)
    if not parsed:
        return None
    return (date.today() - parsed).days


def _extract_frontmatter_value(text: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}:\s*(.+)$", text, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return None


def detect_bug_classes(text: str) -> list[str]:
    lower = text.lower()
    found: list[str] = []
    for klass, keywords in BUG_CLASS_KEYWORDS.items():
        if any(keyword in lower for keyword in keywords):
            found.append(klass)
    return found


def summarize_surface_signals(text: str) -> dict[str, bool]:
    lower = text.lower()
    return {
        signal: any(keyword in lower for keyword in keywords)
        for signal, keywords in TARGET_SURFACE_KEYWORDS.items()
    }


def derive_target_candidate_urls(base_url: str) -> list[str]:
    parsed = urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        raise ResearchSyncError(f"Invalid target URL: {base_url}")

    root = f"{parsed.scheme}://{parsed.netloc}"
    candidates = [root, base_url]
    candidates.extend(urljoin(root, path) for path in TARGET_CANDIDATE_PATHS)

    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            deduped.append(candidate)
    return deduped


def _fetch_bytes(url: str, timeout: int = 25, accept: str = "text/plain, text/markdown;q=0.9, */*;q=0.1") -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Terminator-BB-ResearchSync/1.0",
            "Accept": accept,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_url_text(url: str, timeout: int = 25) -> str:
    parsed = urlparse(url)
    suffix = Path(parsed.path).suffix.lower()
    try_direct = suffix in TEXT_LIKE_SUFFIXES or parsed.path.endswith(("/robots.txt", "/sitemap.xml", "/security.txt", "/openapi.json", "/swagger.json"))

    errors: list[str] = []
    if try_direct:
        try:
            return _fetch_bytes(url, timeout=timeout).decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            errors.append(str(exc))

    jina_url = f"https://r.jina.ai/{url}"
    try:
        raw = _fetch_bytes(jina_url, timeout=timeout, accept="text/markdown").decode("utf-8", errors="replace")
        return _clean_content(raw)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        errors.append(str(exc))

    raise ResearchSyncError(f"Failed to fetch {url}: {' | '.join(errors)}")


def _content_title(url: str, content: str) -> str:
    title = _extract_title(content)
    if title:
        return title.strip()
    parsed = urlparse(url)
    if parsed.path and parsed.path not in {"", "/"}:
        return parsed.path.strip("/").split("/")[-1]
    return parsed.netloc


def _source_type_from_url(url: str) -> str:
    lower = url.lower()
    if lower.endswith(("/sitemap.xml", "/robots.txt", "/security.txt")) or ".well-known/security.txt" in lower:
        return "meta"
    if any(token in lower for token in ("changelog", "release-notes", "/releases", "whats-new", "what-s-new")):
        return "release-notes"
    if any(token in lower for token in ("docs", "developer", "developers", "openapi", "swagger")):
        return "docs"
    if "graphql" in lower or "graphiql" in lower or "playground" in lower:
        return "graphql"
    if any(token in lower for token in ("blog", "engineering")):
        return "blog"
    return "page"


def _target_keywords(target_dir: Path, target_url: str) -> set[str]:
    parsed = urlparse(target_url)
    host_parts = [part for part in re.split(r"[^a-z0-9]+", parsed.netloc.lower()) if len(part) >= 3]
    dir_parts = [part for part in re.split(r"[^a-z0-9]+", target_dir.name.lower()) if len(part) >= 3]
    return set(host_parts + dir_parts)


def _compute_target_relevance(text: str, keywords: set[str]) -> float:
    if not keywords:
        return 0.5
    lower = text.lower()
    hits = sum(1 for keyword in keywords if keyword in lower)
    return round(min(1.0, 0.25 + (hits / max(len(keywords), 1))), 2)


def _write_snapshot(path: Path, title: str, source_url: str, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    excerpt = content.strip()[:10_000]
    path.write_text(
        f"# {title}\n\n"
        f"- Source URL: {source_url}\n"
        f"- Collected: {datetime.now(timezone.utc).isoformat()}\n\n"
        f"## Snapshot\n\n{excerpt}\n",
        encoding="utf-8",
    )


def _maybe_index_url(url: str, enable_index: bool) -> bool:
    if not enable_index:
        return False
    try:
        return bool(index_url(url, db_path=DB_PATH, verbose=False))
    except Exception:
        return False


def fetch_remote_source(
    url: str,
    target_dir: Path,
    authority: str,
    applicability: str,
    published_at: str | None = None,
    enable_index: bool = True,
    notes: str | None = None,
) -> dict[str, Any] | None:
    try:
        content = fetch_url_text(url)
    except ResearchSyncError:
        return None

    if len(content.strip()) < 50:
        return None

    title = _content_title(url, content)
    bug_classes = detect_bug_classes(f"{title}\n{content}")
    signals = summarize_surface_signals(f"{title}\n{content}")
    snapshot_dir = target_dir / "research_sources"
    snapshot_name = _slugify(title or url) + ".md"
    snapshot_path = snapshot_dir / snapshot_name
    _write_snapshot(snapshot_path, title, url, content)

    return {
        "title": title,
        "url": url,
        "source_type": _source_type_from_url(url),
        "authority": authority,
        "applicability": applicability,
        "published_at": published_at,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "freshness_days": _freshness_days(published_at),
        "domain": _extract_domain(url),
        "tags": [tag for tag in _auto_tag(content).split(", ") if tag],
        "bug_classes": bug_classes,
        "surface_signals": signals,
        "target_relevance": 0.0,  # filled later
        "snapshot_path": str(snapshot_path.relative_to(target_dir)),
        "indexed_into_knowledge": _maybe_index_url(url, enable_index),
        "notes": notes or "",
    }


def _repo_signal_entry(repo_path: Path, target_dir: Path) -> dict[str, Any] | None:
    git_dir = repo_path / ".git"
    if not git_dir.exists():
        return None

    try:
        history = subprocess.run(
            [
                "git", "log", "--oneline", "--since=12 months ago", "-n", "50",
                "--grep=security\\|CVE\\|fix\\|patch\\|auth\\|graphql\\|permission\\|bypass\\|session\\|release",
            ],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None

    lines = [line.strip() for line in history.stdout.splitlines() if line.strip()]
    if not lines:
        summary = "No security-significant git history found in last 12 months"
    else:
        summary = "\n".join(lines[:20])

    snapshot_path = target_dir / "research_sources" / "repo-history.md"
    _write_snapshot(snapshot_path, "Repository history signals", str(repo_path), summary)
    bug_classes = detect_bug_classes(summary)
    signals = summarize_surface_signals(summary)

    return {
        "title": f"Repository history analysis ({repo_path.name})",
        "url": str(repo_path),
        "source_type": "repo-analysis",
        "authority": "official",
        "applicability": "campaign",
        "published_at": None,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "freshness_days": None,
        "domain": repo_path.name,
        "tags": [tag for tag in _auto_tag(summary).split(", ") if tag],
        "bug_classes": bug_classes,
        "surface_signals": signals,
        "target_relevance": 1.0,
        "snapshot_path": str(snapshot_path.relative_to(target_dir)),
        "indexed_into_knowledge": False,
        "notes": f"Recent security-significant git history count: {len(lines)}",
    }


def load_seed_registry(path: Path = SEED_REGISTRY_PATH) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ResearchSyncError(f"Seed registry must be a list: {path}")
    return data


def build_local_research_entries(gnosis_root: Path = DEFAULT_GNOSIS_ROOT) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []

    for item in LOCAL_RESEARCH_FILES:
        path = Path(item["path"])
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        title = _extract_title(content) or item["title"]
        entries.append(
            {
                "id": item["id"],
                "title": title,
                "url": str(path),
                "source_type": "local-research",
                "authority": item["authority"],
                "applicability": item["applicability"],
                "published_at": _extract_frontmatter_value(content, "updated") or _extract_frontmatter_value(content, "created"),
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "freshness_days": _freshness_days(_extract_frontmatter_value(content, "updated") or _extract_frontmatter_value(content, "created")),
                "domain": path.parent.name,
                "tags": [tag for tag in _auto_tag(content).split(", ") if tag],
                "bug_classes": item["bug_classes"],
                "surface_signals": summarize_surface_signals(content),
                "target_relevance": 0.5,
                "snapshot_path": str(path.relative_to(PROJECT_ROOT)),
                "indexed_into_knowledge": False,
                "notes": "Local Terminator research digest",
            }
        )

    for item in GNOSIS_SOURCE_CANDIDATES:
        path = gnosis_root / item["path"]
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        title = _extract_title(content) or item["title"]
        entries.append(
            {
                "id": item["id"],
                "title": title,
                "url": str(path),
                "source_type": "gnosis-digest",
                "authority": item["authority"],
                "applicability": item["applicability"],
                "published_at": _extract_frontmatter_value(content, "updated") or _extract_frontmatter_value(content, "created"),
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "freshness_days": _freshness_days(_extract_frontmatter_value(content, "updated") or _extract_frontmatter_value(content, "created")),
                "domain": path.parent.name,
                "tags": [tag for tag in _auto_tag(content).split(", ") if tag],
                "bug_classes": item["bug_classes"],
                "surface_signals": summarize_surface_signals(content),
                "target_relevance": 0.5,
                "snapshot_path": str(path),
                "indexed_into_knowledge": False,
                "notes": "Gnosis long-form synthesis",
            }
        )

    return entries


def write_global_index(
    seeds: list[dict[str, Any]],
    local_entries: list[dict[str, Any]],
    fetched_remote: list[dict[str, Any]],
    index_path: Path = GLOBAL_INDEX_PATH,
    digest_path: Path = GLOBAL_DIGEST_PATH,
) -> dict[str, Any]:
    index_path.parent.mkdir(parents=True, exist_ok=True)
    entries = fetched_remote + local_entries
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed_count": len(seeds),
        "entries": entries,
        "authority_counts": dict(Counter(entry["authority"] for entry in entries)),
        "applicability_counts": dict(Counter(entry["applicability"] for entry in entries)),
    }
    index_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# Bounty Research Digest",
        "",
        f"Generated: {payload['generated_at']}",
        "",
        "## Source mix",
    ]
    for key, value in payload["authority_counts"].items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Applicability mix"])
    for key, value in payload["applicability_counts"].items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Highest-priority references"])
    for entry in entries[:12]:
        lines.append(f"- [{entry['authority']}/{entry['applicability']}] {entry['title']} — {entry['url']}")
    digest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return payload


def _select_reference_entries(index_entries: list[dict[str, Any]], applicability: str, limit: int = 6) -> list[dict[str, Any]]:
    filtered = [entry for entry in index_entries if entry.get("applicability") == applicability]
    filtered.sort(key=lambda item: (item.get("authority") != "official", item.get("freshness_days") or 99999, item.get("title", "")))
    return filtered[:limit]


def _summarize_target_surface(registry: list[dict[str, Any]]) -> dict[str, Any]:
    signal_counter: Counter[str] = Counter()
    bug_classes: Counter[str] = Counter()
    official_count = 0
    for entry in registry:
        bug_classes.update(entry.get("bug_classes", []))
        for signal, enabled in entry.get("surface_signals", {}).items():
            if enabled:
                signal_counter[signal] += 1
        if entry.get("authority") == "official" and entry.get("applicability") == "campaign":
            official_count += 1
    return {
        "signal_counter": signal_counter,
        "bug_classes": bug_classes,
        "official_campaign_sources": official_count,
    }


def build_gap_rows(registry: list[dict[str, Any]]) -> list[dict[str, str]]:
    summary = _summarize_target_surface(registry)
    bug_classes = summary["bug_classes"]
    signal_counter = summary["signal_counter"]
    rows: list[dict[str, str]] = []

    def _status(*keys: str) -> tuple[str, str]:
        hits = sum(bug_classes.get(key, 0) for key in keys)
        if hits:
            return ("covered", f"{hits} supporting source(s)")
        return ("gap", "No strong supporting source yet")

    status, evidence = _status("variant")
    rows.append({
        "class": "Variant hunting",
        "public_signal": evidence,
        "target_signal": "Repo/advisory/release-note evidence" if status == "covered" else "Need recent fix/advisory evidence",
        "gap": status,
        "candidate_angle": "Mine recent fixes, advisories, and regressions for incomplete patch variants",
    })

    auth_hits = bug_classes.get("auth-session", 0) + bug_classes.get("access-control", 0)
    rows.append({
        "class": "Auth / access control",
        "public_signal": f"{auth_hits} supporting source(s)" if auth_hits else "No strong public auth signal",
        "target_signal": "Docs/session/admin/auth flows present" if signal_counter.get("auth") else "Auth surface not yet mapped",
        "gap": "gap" if signal_counter.get("auth") and auth_hits == 0 else "covered",
        "candidate_angle": "Test session invalidation, role persistence, and object-level auth mismatches",
    })

    workflow_hits = bug_classes.get("workflow", 0)
    rows.append({
        "class": "Workflow / business logic",
        "public_signal": f"{workflow_hits} supporting source(s)" if workflow_hits else "No strong public workflow signal",
        "target_signal": "Billing/invite/admin/docs clues present" if signal_counter.get("workflow") else "Workflow surface not yet mapped",
        "gap": "gap" if signal_counter.get("workflow") and workflow_hits == 0 else "covered",
        "candidate_angle": "Model state transitions from docs, then test skip-step/replay/race abuse",
    })

    graphql_hits = bug_classes.get("graphql", 0)
    rows.append({
        "class": "GraphQL",
        "public_signal": f"{graphql_hits} supporting source(s)" if graphql_hits else "No strong GraphQL prior art",
        "target_signal": "GraphQL endpoint/docs detected" if signal_counter.get("graphql") else "No GraphQL surface detected yet",
        "gap": "gap" if signal_counter.get("graphql") and graphql_hits == 0 else "covered",
        "candidate_angle": "Prioritize resolver auth, batched queries, aliases, and mutation replay",
    })

    validation_hits = bug_classes.get("validation", 0)
    rows.append({
        "class": "PoC / validation",
        "public_signal": f"{validation_hits} supporting source(s)" if validation_hits else "Need more PoC-generation references",
        "target_signal": "Official curl/examples/docs present" if summary["official_campaign_sources"] else "No official campaign reproduction anchors",
        "gap": "gap" if summary["official_campaign_sources"] == 0 else "covered",
        "candidate_angle": "Plan E3/E4 → E1/E2 escalation path before exploitation starts",
    })
    return rows


def build_hypotheses(registry: list[dict[str, Any]]) -> dict[str, list[str]]:
    summary = _summarize_target_surface(registry)
    bug_classes = summary["bug_classes"]
    signal_counter = summary["signal_counter"]
    campaign_entries = [entry for entry in registry if entry.get("applicability") == "campaign"]
    release_entries = [entry for entry in campaign_entries if entry.get("source_type") == "release-notes"]
    repo_entries = [entry for entry in campaign_entries if entry.get("source_type") == "repo-analysis"]

    variant: list[str] = []
    if bug_classes.get("variant") or release_entries or repo_entries:
        variant.append("Review recent advisories / release notes / security-tagged commits for incomplete fixes, sibling call paths, and alternate entry points.")
    else:
        variant.append("If a public repo or changelog appears later, treat the freshest fix as a seed for exact and similar variant analysis.")

    workflow_auth_graphql: list[str] = []
    if signal_counter.get("graphql"):
        workflow_auth_graphql.append("GraphQL surface detected: test resolver-level authorization, alias-based rate-limit bypass, batched queries, and mutation replay.")
    if signal_counter.get("auth"):
        workflow_auth_graphql.append("Auth/session clues detected: test login/session invalidation, token reuse across roles, forced browsing, and stale privilege persistence.")
    if signal_counter.get("workflow"):
        workflow_auth_graphql.append("Workflow clues detected: map billing/invite/admin state machines, then test skip-step, replay, race, and rollback abuse.")
    if not workflow_auth_graphql:
        workflow_auth_graphql.append("Start with access-control and workflow mapping from docs/API examples, then expand into auth, admin, and object-level tests.")

    validation: list[str] = []
    if summary["official_campaign_sources"]:
        validation.append("Official docs/rules exist: derive target-specific curl/request templates early so every candidate has a clear E3→E1 validation path.")
    else:
        validation.append("No official target docs captured yet: do not advance to exploitation until a reproducible request template exists.")
    if bug_classes.get("validation"):
        validation.append("Apply PoC-generation patterns from FaultLine / PoCGen / web-PoC studies when escalating invariant or differential proofs into runtime evidence.")

    why_now: list[str] = []
    if release_entries:
        why_now.append(f"Recent release/changelog surface present ({len(release_entries)} source(s)) — new code or migrations often produce bounty-worthy gaps.")
    if repo_entries:
        why_now.append("Repository history shows recent security-significant changes worth probing before they become duplicate territory.")
    if signal_counter.get("graphql"):
        why_now.append("GraphQL is exposed or documented, and public research continues to show strong payout potential for auth/logic flaws in GraphQL APIs.")
    if not why_now:
        why_now.append("The current source mix still justifies a targeted recon sprint because the target surface is better documented than previously exploited.")

    kill_switches = [
        "Program exclusions or known issues explicitly cover the candidate behavior.",
        "The feature is disabled or unreachable on the real target, leaving only theoretical or stale-code paths.",
        "No path to E1/E2 evidence exists within scope and with benign payloads.",
    ]

    return {
        "variant": variant,
        "workflow_auth_graphql": workflow_auth_graphql,
        "validation": validation,
        "why_now": why_now,
        "kill_switches": kill_switches,
    }


def write_target_artifacts(target_dir: Path, registry: list[dict[str, Any]], design_refs: list[dict[str, Any]], tactic_refs: list[dict[str, Any]]) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    keywords = _target_keywords(target_dir, registry[0]["url"] if registry else f"https://{target_dir.name}")

    for entry in registry:
        entry["target_relevance"] = _compute_target_relevance(f"{entry.get('title', '')}\n{entry.get('notes', '')}", keywords) if entry.get("applicability") != "campaign" else 1.0

    registry_path = target_dir / "research_source_registry.json"
    registry_path.write_text(json.dumps(registry, indent=2, ensure_ascii=False), encoding="utf-8")

    gap_rows = build_gap_rows(registry)
    hypotheses = build_hypotheses(registry)
    summary = _summarize_target_surface(registry)

    brief_lines = [
        f"# Research Brief — {target_dir.name}",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Summary",
        f"- Campaign sources: {sum(1 for item in registry if item.get('applicability') == 'campaign')}",
        f"- Design references: {len(design_refs)}",
        f"- Tactic references: {len(tactic_refs)}",
        f"- Strongest bug classes: {', '.join(name for name, _ in summary['bug_classes'].most_common(5)) or 'none yet'}",
        f"- Surface signals: {', '.join(name for name, count in summary['signal_counter'].items() if count) or 'none yet'}",
        "",
        "## High-value design references",
    ]
    for ref in design_refs:
        brief_lines.append(f"- [{ref['authority']}] {ref['title']} — {ref['url']}")
    brief_lines.extend(["", "## High-value tactic references"])
    for ref in tactic_refs:
        brief_lines.append(f"- [{ref['authority']}] {ref['title']} — {ref['url']}")
    brief_lines.extend(["", "## Target-specific web signals"])
    for entry in [item for item in registry if item.get("applicability") == "campaign"][:12]:
        signals = [name for name, enabled in entry.get("surface_signals", {}).items() if enabled]
        signal_text = ", ".join(signals) if signals else "no standout signal"
        brief_lines.append(f"- {entry['title']} ({entry['source_type']}) — {signal_text}")
    (target_dir / "research_brief.md").write_text("\n".join(brief_lines) + "\n", encoding="utf-8")

    gap_lines = [f"# Research Gap Matrix — {target_dir.name}", "", "| Class | Public signal | Target signal | Gap | Candidate angle |", "|------|---------------|---------------|-----|-----------------|",]
    for row in gap_rows:
        gap_lines.append(
            f"| {row['class']} | {row['public_signal']} | {row['target_signal']} | {row['gap']} | {row['candidate_angle']} |"
        )
    (target_dir / "research_gap_matrix.md").write_text("\n".join(gap_lines) + "\n", encoding="utf-8")

    hypothesis_lines = [
        f"# Research Hypotheses — {target_dir.name}",
        "",
        "## Variant hypotheses",
    ]
    hypothesis_lines.extend(f"- {item}" for item in hypotheses["variant"])
    hypothesis_lines.extend(["", "## Workflow/Auth/GraphQL hypotheses"])
    hypothesis_lines.extend(f"- {item}" for item in hypotheses["workflow_auth_graphql"])
    hypothesis_lines.extend(["", "## PoC/validation hypotheses"])
    hypothesis_lines.extend(f"- {item}" for item in hypotheses["validation"])
    hypothesis_lines.extend(["", "## Why now"])
    hypothesis_lines.extend(f"- {item}" for item in hypotheses["why_now"])
    hypothesis_lines.extend(["", "## What would kill this hypothesis"])
    hypothesis_lines.extend(f"- {item}" for item in hypotheses["kill_switches"])
    (target_dir / "research_hypotheses.md").write_text("\n".join(hypothesis_lines) + "\n", encoding="utf-8")


def global_sync(
    gnosis_root: Path = DEFAULT_GNOSIS_ROOT,
    index_knowledge: bool = True,
    include_seeds: list[str] | None = None,
) -> dict[str, Any]:
    seeds = load_seed_registry()
    if include_seeds:
        include = set(include_seeds)
        seeds = [seed for seed in seeds if seed.get("id") in include]

    fetched_remote: list[dict[str, Any]] = []
    for seed in seeds:
        url = seed["url"]
        try:
            if index_knowledge:
                _maybe_index_url(url, True)
        except Exception:
            pass
        fetched_remote.append(
            {
                "id": seed["id"],
                "title": seed["title"],
                "url": url,
                "source_type": seed.get("source_type", _source_type_from_url(url)),
                "authority": seed["authority"],
                "applicability": seed["applicability"],
                "published_at": seed.get("published_at"),
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "freshness_days": _freshness_days(seed.get("published_at")),
                "domain": _extract_domain(url),
                "tags": seed.get("tags", []),
                "bug_classes": seed.get("bug_classes", []),
                "surface_signals": summarize_surface_signals(f"{seed['title']} {' '.join(seed.get('bug_classes', []))}"),
                "target_relevance": 0.5,
                "snapshot_path": "",
                "indexed_into_knowledge": index_knowledge,
                "notes": seed.get("notes", "Curated seed"),
            }
        )

    local_entries = build_local_research_entries(gnosis_root)
    return write_global_index(seeds, local_entries, fetched_remote)


def target_sync(
    target_dir: Path,
    target_url: str,
    source_urls: list[str] | None = None,
    repo_path: Path | None = None,
    index_knowledge: bool = True,
    limit: int = 14,
) -> list[dict[str, Any]]:
    target_dir.mkdir(parents=True, exist_ok=True)

    if GLOBAL_INDEX_PATH.exists():
        global_index = json.loads(GLOBAL_INDEX_PATH.read_text(encoding="utf-8"))
        global_entries = global_index.get("entries", [])
    else:
        global_entries = []

    design_refs = _select_reference_entries(global_entries, "design", limit=6)
    tactic_refs = _select_reference_entries(global_entries, "tactic", limit=6)

    candidate_urls = derive_target_candidate_urls(target_url)
    if source_urls:
        for url in source_urls:
            if url not in candidate_urls:
                candidate_urls.insert(0, url)
    candidate_urls = candidate_urls[:limit]

    registry: list[dict[str, Any]] = []
    for url in candidate_urls:
        entry = fetch_remote_source(
            url=url,
            target_dir=target_dir,
            authority="official" if _extract_domain(url) == _extract_domain(target_url) else "platform",
            applicability="campaign",
            enable_index=index_knowledge,
            notes="Target-derived candidate source",
        )
        if entry:
            registry.append(entry)

    if repo_path:
        repo_entry = _repo_signal_entry(repo_path, target_dir)
        if repo_entry:
            registry.append(repo_entry)

    # Append global references after campaign sources so the registry carries
    # both target-specific evidence and reusable prior art.
    registry.extend(design_refs)
    registry.extend(tactic_refs)

    if not registry:
        raise ResearchSyncError("No research sources could be collected")

    write_target_artifacts(target_dir, registry, design_refs, tactic_refs)
    return registry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Research-first sync for bug bounty hunting")
    sub = parser.add_subparsers(dest="command", required=True)

    global_parser = sub.add_parser("global-sync", help="Sync global research seeds into knowledge/index artifacts")
    global_parser.add_argument("--gnosis-root", default=str(DEFAULT_GNOSIS_ROOT))
    global_parser.add_argument("--no-index", action="store_true", help="Skip indexing remote seeds into knowledge.db")
    global_parser.add_argument("--include-seed", action="append", default=[], help="Sync only selected seed IDs")

    target_parser = sub.add_parser("target-sync", help="Build target-specific research artifacts")
    target_parser.add_argument("target_dir")
    target_parser.add_argument("--url", required=True, help="Canonical target URL")
    target_parser.add_argument("--source-url", action="append", default=[], help="Extra source URLs (program page, hacktivity, docs, etc.)")
    target_parser.add_argument("--repo", help="Local repository path for repo-history analysis")
    target_parser.add_argument("--no-index", action="store_true", help="Skip indexing remote sources into knowledge.db")
    target_parser.add_argument("--limit", type=int, default=14, help="Maximum number of remote URLs to attempt")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "global-sync":
        payload = global_sync(
            gnosis_root=Path(args.gnosis_root).expanduser(),
            index_knowledge=not args.no_index,
            include_seeds=args.include_seed,
        )
        print(json.dumps({
            "result": "PASS",
            "index": str(GLOBAL_INDEX_PATH.relative_to(PROJECT_ROOT)),
            "digest": str(GLOBAL_DIGEST_PATH.relative_to(PROJECT_ROOT)),
            "entries": len(payload.get("entries", [])),
        }, indent=2, ensure_ascii=False))
        return 0

    if args.command == "target-sync":
        registry = target_sync(
            target_dir=Path(args.target_dir),
            target_url=args.url,
            source_urls=args.source_url,
            repo_path=Path(args.repo).expanduser().resolve() if args.repo else None,
            index_knowledge=not args.no_index,
            limit=args.limit,
        )
        print(json.dumps({
            "result": "PASS",
            "target_dir": args.target_dir,
            "source_count": len(registry),
            "artifacts": [
                str(Path(args.target_dir) / "research_source_registry.json"),
                str(Path(args.target_dir) / "research_brief.md"),
                str(Path(args.target_dir) / "research_gap_matrix.md"),
                str(Path(args.target_dir) / "research_hypotheses.md"),
            ],
        }, indent=2, ensure_ascii=False))
        return 0

    parser.error(f"Unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
