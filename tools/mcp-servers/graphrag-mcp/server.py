#!/usr/bin/env python3
"""GraphRAG Security MCP server: unified security knowledge graph search."""
import subprocess
import json
import os
import sys

from mcp.server.fastmcp import FastMCP

# Add parent dir to path for exploit_search import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit_search

mcp = FastMCP("graphrag-security")

GRAPHRAG_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../graphrag-security")
EXPLOITDB = os.path.expanduser("~/exploitdb/searchsploit")
POC_DIR = os.path.expanduser("~/PoC-in-GitHub")


def _run_graphrag(method: str, query: str, timeout: int = 60) -> str:
    """Run graphrag query command and return stdout."""
    graphrag_root = os.path.abspath(GRAPHRAG_ROOT)
    if not os.path.isdir(graphrag_root):
        return f"GraphRAG root not found at {graphrag_root}. Initialize with knowledge_ingest first."
    try:
        result = subprocess.run(
            ["graphrag", "query", "--root", graphrag_root, "--method", method, "--query", query],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout.strip()
        if not output and result.stderr:
            return f"[graphrag stderr] {result.stderr[:500]}"
        return output if output else "(no output)"
    except subprocess.TimeoutExpired:
        return f"graphrag query timed out after {timeout}s"
    except FileNotFoundError:
        return "graphrag binary not found. Install: pip install graphrag"
    except Exception as e:
        return f"graphrag error: {str(e)}"


@mcp.tool()
def knowledge_search(query: str, mode: str = "local") -> str:
    """Search the security knowledge graph using GraphRAG local search.

    Args:
        query: Search query (e.g., 'heap overflow exploitation techniques', 'CVE-2021-44228')
        mode: Search mode: 'local' (entity-focused), 'global' (community summary), 'drift' (exploratory)
    """
    valid_modes = {"local", "global", "drift"}
    if mode not in valid_modes:
        mode = "local"
    return _run_graphrag(mode, query, timeout=60)


@mcp.tool()
def knowledge_global(query: str) -> str:
    """Search security knowledge graph using GraphRAG global (community-level) search.

    Args:
        query: High-level question about security patterns, attack categories, or vulnerability classes
    """
    return _run_graphrag("global", query, timeout=60)


@mcp.tool()
def knowledge_drift(query: str) -> str:
    """Exploratory drift search across the security knowledge graph.

    Args:
        query: Open-ended exploration query to discover related concepts
    """
    return _run_graphrag("drift", query, timeout=60)


@mcp.tool()
def exploit_lookup(query: str) -> str:
    """Search ExploitDB, PoC-in-GitHub, and trickest-cve for exploits matching query.

    Args:
        query: CVE ID (e.g., 'CVE-2021-44228') or keyword (e.g., 'apache log4j rce')
    """
    return exploit_search.unified_search(query)


@mcp.tool()
def similar_findings(description: str) -> str:
    """Find similar past security findings using GraphRAG local search on the description.

    Args:
        description: Description of a vulnerability or finding to find similar cases
    """
    return _run_graphrag("local", description, timeout=60)


@mcp.tool()
def knowledge_ingest(file_path: str, doc_type: str = "unknown") -> str:
    """Ingest a new document into the security knowledge graph.

    Args:
        file_path: Absolute path to the document to ingest (markdown, txt, etc.)
        doc_type: Document type hint: 'writeup', 'report', 'technique', 'cve', 'unknown'
    """
    graphrag_root = os.path.abspath(GRAPHRAG_ROOT)
    script = os.path.join(graphrag_root, "incremental_index.sh")

    if not os.path.exists(file_path):
        return f"File not found: {file_path}"

    if not os.path.exists(script):
        # Fallback: copy file to graphrag input dir and note manual indexing needed
        input_dir = os.path.join(graphrag_root, "input")
        os.makedirs(input_dir, exist_ok=True)
        dest = os.path.join(input_dir, os.path.basename(file_path))
        try:
            import shutil
            shutil.copy2(file_path, dest)
            return (
                f"Copied {file_path} to {dest}. "
                f"incremental_index.sh not found — run 'graphrag index --root {graphrag_root}' manually to index."
            )
        except Exception as e:
            return f"Error copying file: {str(e)}"

    try:
        result = subprocess.run(
            ["bash", script, file_path, doc_type],
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout.strip()
        if result.returncode != 0:
            return f"Ingest failed (rc={result.returncode}): {result.stderr[:500]}"
        return output if output else f"Ingested {file_path} as {doc_type}"
    except subprocess.TimeoutExpired:
        return "Ingest timed out after 120s"
    except Exception as e:
        return f"Ingest error: {str(e)}"


@mcp.tool()
def knowledge_graph_query(cypher: str) -> str:
    """Run a Cypher query against the Neo4j attack graph.

    Args:
        cypher: Cypher query string (e.g., 'MATCH (n:Vulnerability) RETURN n LIMIT 10')
    """
    cli_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "../../attack_graph/cli.py"
    )
    cli_path = os.path.abspath(cli_path)

    if not os.path.exists(cli_path):
        return f"Attack graph CLI not found at {cli_path}. Is Neo4j/attack_graph configured?"

    try:
        result = subprocess.run(
            ["python3", cli_path, "query", cypher],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout.strip()
        if result.returncode != 0:
            stderr = result.stderr[:300]
            if "connection refused" in stderr.lower() or "neo4j" in stderr.lower():
                return f"Neo4j unavailable: {stderr}"
            return f"Query error (rc={result.returncode}): {stderr}"
        return output if output else "(no results)"
    except subprocess.TimeoutExpired:
        return "Cypher query timed out after 30s"
    except FileNotFoundError:
        return "python3 not found"
    except Exception as e:
        return f"Graph query error: {str(e)}"


if __name__ == "__main__":
    mcp.run()
