#!/usr/bin/env python3
"""Knowledge Web Fetcher — fetch security articles into FTS5 database.

Fetches web content via r.jina.ai reader API and indexes into the
web_articles table in knowledge/knowledge.db.
"""

import argparse
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "knowledge" / "knowledge.db"
MAX_CONTENT_BYTES = 50 * 1024  # 50KB cap

# Domain -> category auto-mapping
DOMAIN_CATEGORIES = {
    "portswigger.net": "web",
    "blog.portswigger.net": "web",
    "googleprojectzero.blogspot.com": "browser",
    "project-zero.issues.chromium.org": "browser",
    "blog.assetnote.io": "web",
    "blog.doyensec.com": "web",
    "securitylab.github.com": "web",
    "doar-e.github.io": "binary",
    "connormcgarr.github.io": "kernel",
    "github.blog": "general",
    "blog.cloudflare.com": "cloud",
    "aws.amazon.com": "cloud",
    "research.nccgroup.com": "general",
    "blog.trailofbits.com": "general",
    "samcurry.net": "web",
    "bugs.chromium.org": "browser",
    "arxiv.org": "research",
    "ctftime.org": "ctf",
    "medium.com": "general",
    "infosecwriteups.com": "web",
    "hackerone.com": "bugbounty",
    "bugcrowd.com": "bugbounty",
    "blog.quarkslab.com": "binary",
    "blog.ret2.io": "binary",
    "blog.exodusintel.com": "binary",
    "starlabs.sg": "binary",
    "blog.immunefi.com": "web3",
    "medium.com/@peckshield": "web3",
    "rekt.news": "web3",
    "blog.openzeppelin.com": "web3",
    "blog.solidityscan.com": "web3",
    "pwning.systems": "kernel",
    "seclists.org": "general",
    "paper.seebug.org": "general",
    "labs.watchtowr.com": "web",
    "blog.wiz.io": "cloud",
    "rhinosecuritylabs.com": "cloud",
    "projectzero.google": "research",
    "openai.com": "research",
    "xbow.com": "bugbounty",
    "theori.io": "research",
    "trailofbits.com": "research",
    "www.trailofbits.com": "research",
    "ndss-symposium.org": "research",
    "aclanthology.org": "research",
    "usenix.org": "research",
    "darpa.mil": "research",
    "semgrep.dev": "web",
    "intigriti.com": "bugbounty",
}

# Auto-tag keywords
TAG_KEYWORDS = {
    "xss": "xss",
    "sql injection": "sqli",
    "sqli": "sqli",
    "buffer overflow": "bof",
    "heap": "heap",
    "use-after-free": "uaf",
    "use after free": "uaf",
    "race condition": "race",
    "toctou": "toctou",
    "reentrancy": "reentrancy",
    "ssrf": "ssrf",
    "csrf": "csrf",
    "rce": "rce",
    "remote code execution": "rce",
    "privilege escalation": "privesc",
    "kernel": "kernel",
    "firmware": "firmware",
    "prototype pollution": "prototype-pollution",
    "deserialization": "deserialization",
    "path traversal": "path-traversal",
    "directory traversal": "path-traversal",
    "command injection": "cmdi",
    "idor": "idor",
    "authentication bypass": "auth-bypass",
    "jwt": "jwt",
    "oauth": "oauth",
    "xxe": "xxe",
    "ssti": "ssti",
    "template injection": "ssti",
    "crlf": "crlf",
    "open redirect": "open-redirect",
    "cors": "cors",
    "websocket": "websocket",
    "graphql": "graphql",
    "api": "api",
    "smart contract": "smart-contract",
    "solidity": "solidity",
    "flash loan": "flash-loan",
    "variant analysis": "variant-analysis",
    "business logic": "business-logic",
    "proof of vulnerability": "pov",
    "proof-of-vulnerability": "pov",
    "proof of concept": "poc",
    "proof-of-concept": "poc",
    "exploit generation": "aeg",
    "automated exploit generation": "aeg",
    "agentic": "agentic",
    "multi-agent": "multi-agent",
    "validator": "validation",
    "validation": "validation",
}


def _extract_domain(url: str) -> str:
    """Extract domain from URL."""
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1).lower() if m else ""


def _categorize(domain: str, content: str) -> str:
    """Auto-categorize based on domain and content."""
    # Direct domain match
    for d, cat in DOMAIN_CATEGORIES.items():
        if d in domain:
            return cat
    # Subdomain match
    parts = domain.split(".")
    if len(parts) >= 2:
        base = ".".join(parts[-2:])
        if base in DOMAIN_CATEGORIES:
            return DOMAIN_CATEGORIES[base]
    return "general"


def _auto_tag(content: str) -> str:
    """Scan content for known vulnerability keywords and return tags."""
    content_lower = content.lower()
    found_tags = set()
    for keyword, tag in TAG_KEYWORDS.items():
        if keyword in content_lower:
            found_tags.add(tag)
    return ", ".join(sorted(found_tags))


def _extract_title(content: str) -> str:
    """Extract title from markdown content."""
    for line in content.split("\n", 30):
        line = line.strip()
        if line.startswith("# "):
            return line[2:].strip()
        # jina.ai often puts Title: at top
        if line.startswith("Title:"):
            return line[6:].strip()
    return ""


def _clean_content(content: str) -> str:
    """Strip navigation noise from jina.ai markdown output.

    Strategy: find the first real paragraph of article text (>80 chars,
    starts with a letter, low link density) and keep everything from there.
    Then filter out remaining noise lines (footers, social, images).
    """
    lines = content.split("\n")

    # --- Phase 1: Find article body start ---
    # Skip jina metadata, then find the first substantial paragraph
    body_start = 0
    for i, line in enumerate(lines):
        stripped = line.strip()

        # Skip jina metadata
        if stripped.startswith(("Title:", "URL Source:", "Published Time:", "Markdown Content:")):
            continue

        # A "real paragraph" = substantial plain text after stripping links
        link_count = stripped.count("](")
        text_clean = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', stripped)
        plain_len = len(text_clean.strip())
        if (plain_len > 80
                and text_clean.strip()[0].isalpha()
                and link_count <= 3):
            # Walk back to find preceding heading if any
            body_start = i
            for j in range(i - 1, max(0, i - 10), -1):
                s = lines[j].strip()
                if s.startswith("#") and len(s) > 4 and s.count("](") == 0:
                    body_start = j
                    break
            break

    # --- Phase 2: Filter noise from body ---
    cleaned = []
    for line in lines[body_start:]:
        stripped = line.strip()

        # Skip empty-ish lines
        if not stripped:
            cleaned.append("")
            continue

        # Link density check
        link_count = stripped.count("](")
        text_clean = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', stripped)
        text_len = len(text_clean.strip())

        # Skip: high link density with little text (nav menus)
        if link_count >= 2 and text_len < 40:
            continue

        # Skip: pure image lines with no text
        if stripped.startswith("![") and text_len < 15:
            continue

        # Skip: social share / empty link blocks
        if stripped.startswith("*   [](http"):
            continue

        # Skip: checkbox-only lines
        if stripped in ("- [x]", "- [ ]", "- [x] "):
            continue

        # Skip: footer boilerplate
        lower = stripped.lower()
        if any(fp in lower for fp in (
            "cookie", "privacy policy", "terms of service", "© 20",
            "all rights reserved", "subscribe to our newsletter",
            "sign up for", "follow us on", "share this article",
            "back to all articles", "related research",
        )):
            continue

        cleaned.append(line)

    if not cleaned:
        return content

    result = "\n".join(cleaned).strip()
    result = re.sub(r'\n{4,}', '\n\n\n', result)
    return result


def _ensure_table(db_path: Path):
    """Ensure web_articles table exists in the database."""
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS web_articles USING fts5(
                title, content, category, tags,
                source_url UNINDEXED, domain UNINDEXED, fetch_date UNINDEXED,
                tokenize = 'porter ascii'
            )
        """)
        conn.commit()
    finally:
        conn.close()


def fetch_url(url: str, db_path: Path = DB_PATH, verbose: bool = True) -> bool:
    """Fetch a single URL and index into web_articles table."""
    _ensure_table(db_path)

    domain = _extract_domain(url)
    jina_url = f"https://r.jina.ai/{url}"

    if verbose:
        print(f"Fetching: {url}")

    try:
        req = urllib.request.Request(jina_url, headers={
            "Accept": "text/markdown",
            "User-Agent": "Terminator-Knowledge-Fetcher/1.0",
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        if verbose:
            print(f"  ERROR: {e}")
        return False

    if not content.strip() or len(content.strip()) < 100:
        if verbose:
            print(f"  SKIP: Content too short ({len(content)} bytes)")
        return False

    # Reject error pages, 404s, Cloudflare challenges
    ERROR_TITLES = (
        "page not found", "404", "not found", "just a moment",
        "page non trouvée", "access denied", "forbidden",
        "error", "captcha", "verify you are human",
    )
    raw_title = _extract_title(content) or ""
    if raw_title and raw_title.lower().strip().rstrip(".!") in ERROR_TITLES:
        if verbose:
            print(f"  SKIP: Error page detected ({raw_title!r})")
        return False
    # Also reject by partial match for common patterns
    title_lower = raw_title.lower()
    if any(ep in title_lower for ep in ("page not found", "404", "just a moment", "not found |", "access denied")):
        if verbose:
            print(f"  SKIP: Error page detected ({raw_title!r})")
        return False

    # Truncate to 50KB
    if len(content) > MAX_CONTENT_BYTES:
        content = content[:MAX_CONTENT_BYTES]

    # Clean navigation noise before indexing
    title = _extract_title(content) or url.split("/")[-1]
    content = _clean_content(content)

    # Reject if cleaned content is too thin (likely error page or empty shell)
    if len(content.strip()) < 500:
        if verbose:
            print(f"  SKIP: Content too thin after cleaning ({len(content.strip())} chars)")
        return False

    category = _categorize(domain, content)
    tags = _auto_tag(content)
    fetch_date = datetime.now().strftime("%Y-%m-%d")

    conn = sqlite3.connect(str(db_path))
    try:
        # Check for duplicate
        cur = conn.execute(
            "SELECT rowid FROM web_articles WHERE source_url = ?", (url,)
        )
        existing = cur.fetchone()
        if existing:
            # Update existing
            conn.execute(
                "DELETE FROM web_articles WHERE source_url = ?", (url,)
            )

        conn.execute(
            "INSERT INTO web_articles (title, content, category, tags, source_url, domain, fetch_date) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (title, content, category, tags, url, domain, fetch_date)
        )
        conn.commit()
        action = "Updated" if existing else "Indexed"
        if verbose:
            print(f"  {action}: {title[:80]} [{category}] ({len(content)} bytes, {len(tags.split(', ')) if tags else 0} tags)")
        return True
    except sqlite3.OperationalError as e:
        if verbose:
            print(f"  DB ERROR: {e}")
        return False
    finally:
        conn.close()


def bulk_fetch(url_file: str, db_path: Path = DB_PATH, delay: float = 1.0):
    """Fetch URLs from a text file (one per line, # comments allowed)."""
    filepath = Path(url_file)
    if not filepath.exists():
        print(f"File not found: {url_file}")
        return

    urls = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            # Skip empty lines, comments (#), markdown headings (#/##/###), and non-URL lines
            if not line or line.startswith("#") or line.startswith(">"):
                continue
            if line.startswith("http://") or line.startswith("https://"):
                urls.append(line)

    print(f"Fetching {len(urls)} URLs from {url_file}")
    success = 0
    failed = 0

    for i, url in enumerate(urls, 1):
        print(f"\n[{i}/{len(urls)}]", end=" ")
        ok = False
        for attempt in range(3):
            ok = fetch_url(url, db_path)
            if ok:
                break
            if attempt < 2:
                print(f"  Retry {attempt+1}/2...")
                time.sleep(delay * 2)

        if ok:
            success += 1
        else:
            failed += 1

        if i < len(urls):
            time.sleep(delay)

    print(f"\n{'='*60}")
    print(f"Bulk fetch complete: {success} success, {failed} failed out of {len(urls)}")


def update_stale(db_path: Path = DB_PATH, max_age_days: int = 30):
    """Re-fetch articles older than max_age_days."""
    _ensure_table(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT source_url, fetch_date FROM web_articles").fetchall()
    finally:
        conn.close()

    cutoff = datetime.now()
    stale = []
    for row in rows:
        try:
            fetched = datetime.strptime(row["fetch_date"], "%Y-%m-%d")
            if (cutoff - fetched).days > max_age_days:
                stale.append(row["source_url"])
        except (ValueError, TypeError):
            stale.append(row["source_url"])

    if not stale:
        print("No stale articles to update.")
        return

    print(f"Updating {len(stale)} stale articles (>{max_age_days} days old)")
    for i, url in enumerate(stale, 1):
        print(f"\n[{i}/{len(stale)}]", end=" ")
        fetch_url(url, db_path)
        time.sleep(1.0)


def show_stats(db_path: Path = DB_PATH):
    """Show web_articles table statistics."""
    _ensure_table(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        count = conn.execute("SELECT COUNT(*) as cnt FROM web_articles").fetchone()["cnt"]
        if count == 0:
            print("web_articles: 0 articles (empty)")
            return

        # Category breakdown
        cats = conn.execute(
            "SELECT category, COUNT(*) as cnt FROM web_articles GROUP BY category ORDER BY cnt DESC"
        ).fetchall()

        # Domain breakdown
        domains = conn.execute(
            "SELECT domain, COUNT(*) as cnt FROM web_articles GROUP BY domain ORDER BY cnt DESC LIMIT 20"
        ).fetchall()

        print(f"web_articles: {count} articles")
        print(f"\nBy category:")
        for row in cats:
            print(f"  {row['category']}: {row['cnt']}")
        print(f"\nTop domains:")
        for row in domains:
            print(f"  {row['domain']}: {row['cnt']}")
    finally:
        conn.close()


def cli_search(query: str, db_path: Path = DB_PATH, limit: int = 10):
    """Quick CLI search of web_articles."""
    _ensure_table(db_path)
    # Import escape function from knowledge_indexer
    sys.path.insert(0, str(Path(__file__).parent))
    from knowledge_indexer import escape_fts5

    escaped = escape_fts5(query)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        results = conn.execute(
            "SELECT *, rank FROM web_articles WHERE web_articles MATCH ? ORDER BY rank LIMIT ?",
            (escaped, limit)
        ).fetchall()

        if not results:
            print(f"No results for '{query}'")
            return

        print(f"Results for '{query}': {len(results)}")
        for i, r in enumerate(results, 1):
            title = r["title"][:80] if r["title"] else "untitled"
            cat = r["category"]
            domain = r["domain"]
            tags = r["tags"][:60] if r["tags"] else ""
            print(f"  {i}. {title}")
            print(f"     [{cat}] {domain} | Tags: {tags}")
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Knowledge Web Fetcher — fetch security articles into FTS5 database"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # fetch
    sub = subparsers.add_parser("fetch", help="Fetch a single URL")
    sub.add_argument("url", help="URL to fetch")

    # bulk
    sub = subparsers.add_parser("bulk", help="Bulk fetch from URL list file")
    sub.add_argument("file", help="Text file with URLs (one per line)")
    sub.add_argument("--delay", type=float, default=1.0, help="Delay between fetches (seconds)")

    # update
    sub = subparsers.add_parser("update", help="Re-fetch stale articles")
    sub.add_argument("--max-age", type=int, default=30, help="Max age in days (default 30)")

    # stats
    subparsers.add_parser("stats", help="Show web_articles statistics")

    # search
    sub = subparsers.add_parser("search", help="Search web_articles")
    sub.add_argument("query", help="Search query")
    sub.add_argument("--limit", type=int, default=10)

    args = parser.parse_args()

    if args.command == "fetch":
        fetch_url(args.url)
    elif args.command == "bulk":
        bulk_fetch(args.file, delay=args.delay)
    elif args.command == "update":
        update_stale(max_age_days=args.max_age)
    elif args.command == "stats":
        show_stats()
    elif args.command == "search":
        cli_search(args.query, limit=args.limit)


if __name__ == "__main__":
    main()
