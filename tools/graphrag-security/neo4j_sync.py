#!/usr/bin/env python3
"""
neo4j_sync.py — Sync GraphRAG Parquet output to Neo4j
Reads entities.parquet, relationships.parquet, communities.parquet
and MERGEs them into Neo4j graph database.
"""

import os
import sys
import subprocess
from pathlib import Path


def ensure_package(package_name: str, import_name: str = None):
    """Install package if not available."""
    import_name = import_name or package_name
    try:
        __import__(import_name)
    except ImportError:
        print(f"[neo4j_sync] Installing {package_name}...", file=sys.stderr)
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", package_name],
            check=False, capture_output=True
        )


ensure_package("pandas")
ensure_package("pyarrow")
ensure_package("neo4j")

import pandas as pd  # noqa: E402
from neo4j import GraphDatabase  # noqa: E402

# Configuration from env vars with defaults
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "terminator")

SCRIPT_DIR = Path(__file__).parent.resolve()
OUTPUT_DIR = SCRIPT_DIR / "output"

# Entity type → Neo4j label mapping
ENTITY_LABEL_MAP = {
    "CVE": "Vulnerability",
    "CWE": "Vulnerability",
    "VULNERABILITY": "Vulnerability",
    "PRODUCT": "Technology",
    "VENDOR": "Target",
    "BINARY": "Service",
    "SERVICE": "Service",
    "TECHNIQUE": "Exploit",
    "TOOL": "Technology",
    "PROTECTION": "Technology",
    "PRIMITIVE": "Exploit",
    "PLATFORM": "Target",
    "OUTCOME": "Finding",
    "LESSON": "Finding",
    "PERSON": "Actor",
    "ORGANIZATION": "Target",
    "PROTOCOL": "Technology",
    "FUNCTION": "Service",
    "CHALLENGE": "Finding",
}

DEFAULT_LABEL = "Entity"


def get_neo4j_label(entity_type: str) -> str:
    """Map GraphRAG entity type to Neo4j label."""
    if not entity_type:
        return DEFAULT_LABEL
    return ENTITY_LABEL_MAP.get(entity_type.upper(), DEFAULT_LABEL)


def find_parquet_files(output_dir: Path) -> dict:
    """Find GraphRAG parquet output files."""
    files = {}
    search_dirs = [output_dir, output_dir / "artifacts"]

    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for pattern, key in [
            ("*entities*.parquet", "entities"),
            ("*relationships*.parquet", "relationships"),
            ("*communities*.parquet", "communities"),
            ("*community_reports*.parquet", "community_reports"),
        ]:
            matches = list(search_dir.glob(pattern))
            if matches and key not in files:
                files[key] = max(matches, key=lambda p: p.stat().st_mtime)

    return files


def sync_entities(session, df: pd.DataFrame) -> int:
    """MERGE entities into Neo4j."""
    count = 0
    for _, row in df.iterrows():
        entity_id = str(row.get("id", row.get("human_readable_id", "")))
        title = str(row.get("title", row.get("name", entity_id)))
        entity_type = str(row.get("type", ""))
        description = str(row.get("description", ""))[:500]
        label = get_neo4j_label(entity_type)

        query = (
            f"MERGE (e:Entity {{id: $id}}) "
            f"SET e:{label} "
            f"SET e.title = $title, e.type = $type, "
            f"e.description = $description, e.updated_at = datetime()"
        )
        try:
            session.run(query, id=entity_id, title=title,
                        type=entity_type, description=description)
            count += 1
        except Exception as ex:
            print(f"[neo4j_sync] Entity MERGE error ({entity_id}): {ex}", file=sys.stderr)

    print(f"[neo4j_sync] Merged {count} entities")
    return count


def sync_relationships(session, df: pd.DataFrame) -> int:
    """MERGE relationships into Neo4j."""
    count = 0
    for _, row in df.iterrows():
        src = str(row.get("source", row.get("source_id", "")))
        tgt = str(row.get("target", row.get("target_id", "")))
        rel_type = str(row.get("type", row.get("relationship_type", "RELATES_TO")))
        description = str(row.get("description", ""))[:300]
        weight = float(row.get("weight", row.get("combined_degree", 1.0)))

        # Sanitize relationship type for Cypher
        rel_type_safe = rel_type.upper().replace(" ", "_").replace("-", "_")
        if not rel_type_safe:
            rel_type_safe = "RELATES_TO"

        query = (
            f"MATCH (src:Entity {{id: $src}}) "
            f"MATCH (tgt:Entity {{id: $tgt}}) "
            f"MERGE (src)-[r:{rel_type_safe}]->(tgt) "
            f"SET r.description = $description, r.weight = $weight, r.updated_at = datetime()"
        )
        try:
            session.run(query, src=src, tgt=tgt,
                        description=description, weight=weight)
            count += 1
        except Exception as ex:
            print(f"[neo4j_sync] Rel MERGE error ({src}->{tgt}): {ex}", file=sys.stderr)

    print(f"[neo4j_sync] Merged {count} relationships")
    return count


def sync_communities(session, df: pd.DataFrame) -> int:
    """MERGE community nodes into Neo4j."""
    count = 0
    for _, row in df.iterrows():
        community_id = str(row.get("id", row.get("community", "")))
        level = int(row.get("level", 0))
        title = str(row.get("title", f"Community {community_id}"))
        summary = str(row.get("summary", ""))[:500]
        size = int(row.get("size", 0))

        query = (
            "MERGE (c:Community {id: $id}) "
            "SET c.level = $level, c.title = $title, "
            "c.summary = $summary, c.size = $size, c.updated_at = datetime()"
        )
        try:
            session.run(query, id=community_id, level=level,
                        title=title, summary=summary, size=size)
            count += 1
        except Exception as ex:
            print(f"[neo4j_sync] Community MERGE error ({community_id}): {ex}", file=sys.stderr)

    print(f"[neo4j_sync] Merged {count} communities")
    return count


def create_indexes(session):
    """Create Neo4j indexes for query performance."""
    indexes = [
        "CREATE INDEX entity_id IF NOT EXISTS FOR (e:Entity) ON (e.id)",
        "CREATE INDEX entity_title IF NOT EXISTS FOR (e:Entity) ON (e.title)",
        "CREATE INDEX vuln_id IF NOT EXISTS FOR (v:Vulnerability) ON (v.id)",
        "CREATE INDEX community_id IF NOT EXISTS FOR (c:Community) ON (c.id)",
    ]
    for idx_query in indexes:
        try:
            session.run(idx_query)
        except Exception:
            pass


def main():
    print(f"[neo4j_sync] Connecting to Neo4j at {NEO4J_URI}")

    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        driver.verify_connectivity()
    except Exception as e:
        print(f"[neo4j_sync] ERROR: Cannot connect to Neo4j: {e}", file=sys.stderr)
        sys.exit(1)

    parquet_files = find_parquet_files(OUTPUT_DIR)

    if not parquet_files:
        print(f"[neo4j_sync] No parquet files found in {OUTPUT_DIR}", file=sys.stderr)
        print("[neo4j_sync] Run 'graphrag index' first to generate output files")
        driver.close()
        sys.exit(0)

    print(f"[neo4j_sync] Found: {list(parquet_files.keys())}")

    with driver.session() as session:
        create_indexes(session)

        if "entities" in parquet_files:
            try:
                df = pd.read_parquet(parquet_files["entities"])
                print(f"[neo4j_sync] Entities: {len(df)} rows")
                sync_entities(session, df)
            except Exception as e:
                print(f"[neo4j_sync] WARNING: Failed to read entities: {e}", file=sys.stderr)

        if "relationships" in parquet_files:
            try:
                df = pd.read_parquet(parquet_files["relationships"])
                print(f"[neo4j_sync] Relationships: {len(df)} rows")
                sync_relationships(session, df)
            except Exception as e:
                print(f"[neo4j_sync] WARNING: Failed to read relationships: {e}", file=sys.stderr)

        if "communities" in parquet_files:
            try:
                df = pd.read_parquet(parquet_files["communities"])
                print(f"[neo4j_sync] Communities: {len(df)} rows")
                sync_communities(session, df)
            except Exception as e:
                print(f"[neo4j_sync] WARNING: Failed to read communities: {e}", file=sys.stderr)

    driver.close()
    print("[neo4j_sync] Sync completed successfully")


if __name__ == "__main__":
    main()
