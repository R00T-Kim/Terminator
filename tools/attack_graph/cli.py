#!/usr/bin/env python3
"""
Attack Surface Graph CLI
Usage:
    python3 tools/attack_graph/cli.py ingest --file recon.json
    python3 tools/attack_graph/cli.py query --name critical_vulns
    python3 tools/attack_graph/cli.py query --name exploitable_services --target example.com
    python3 tools/attack_graph/cli.py export --target example.com --out report.json
    python3 tools/attack_graph/cli.py init
    python3 tools/attack_graph/cli.py list-queries
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from tools.attack_graph.graph import AttackGraph
from tools.attack_graph.queries import QUERIES


def cmd_init(args, graph):
    graph.initialize_schema()
    print("[OK] Schema initialized.")


def cmd_ingest(args, graph):
    if not args.file:
        print("Error: --file required for ingest", file=sys.stderr)
        sys.exit(1)
    with open(args.file) as f:
        data = json.load(f)
    graph.ingest_from_json(data)
    print(f"[OK] Ingested data for target: {data.get('target')}")


def cmd_query(args, graph):
    query_name = args.name
    if query_name not in QUERIES:
        print(f"Error: Unknown query '{query_name}'. Use list-queries to see available.", file=sys.stderr)
        sys.exit(1)

    cypher = QUERIES[query_name]
    params = {}
    if args.target:
        params["target_name"] = args.target
    if args.severity:
        params["severity"] = args.severity

    results = graph._run(cypher, **params)
    print(json.dumps(results, indent=2, default=str))


def cmd_export(args, graph):
    if not args.target:
        print("Error: --target required for export", file=sys.stderr)
        sys.exit(1)
    data = graph.export_to_json(args.target)
    if args.out:
        with open(args.out, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"[OK] Exported to {args.out}")
    else:
        print(json.dumps(data, indent=2, default=str))


def cmd_list_queries(args, graph):
    print("Available queries:")
    for name in sorted(QUERIES.keys()):
        first_line = QUERIES[name].strip().split("\n")[0].strip()
        print(f"  {name:<35} -- {first_line[:60]}")


def main():
    parser = argparse.ArgumentParser(
        description="Terminator Attack Surface Graph CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("command", choices=["init", "ingest", "query", "export", "list-queries"],
                        help="Command to run")
    parser.add_argument("--file", "-f", help="JSON file to ingest")
    parser.add_argument("--target", "-t", help="Target name for queries/export")
    parser.add_argument("--name", "-n", help="Query name (use list-queries to see all)")
    parser.add_argument("--severity", "-s", help="Severity filter (critical/high/medium/low)")
    parser.add_argument("--out", "-o", help="Output file for export")
    parser.add_argument("--uri", default=os.getenv("NEO4J_URI", "bolt://localhost:7687"))
    parser.add_argument("--user", default=os.getenv("NEO4J_USER", "neo4j"))
    parser.add_argument("--password", default=os.getenv("NEO4J_PASSWORD", "terminator"))

    args = parser.parse_args()

    try:
        with AttackGraph(args.uri, args.user, args.password) as graph:
            dispatch = {
                "init": cmd_init,
                "ingest": cmd_ingest,
                "query": cmd_query,
                "export": cmd_export,
                "list-queries": cmd_list_queries,
            }
            dispatch[args.command](args, graph)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
