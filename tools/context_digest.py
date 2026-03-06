#!/usr/bin/env python3
"""Create cached structured digests for text, files, or directories."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.coordination import CoordinationStore, build_digest_payload, stable_session_id


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run_gemini(project_root: Path, mode: str, target: Path, extra: str | None = None) -> tuple[str, str]:
    script = project_root / "tools" / "gemini_query.sh"
    if not script.exists():
        return "", "gemini_unavailable"

    cmd = [str(script), mode, str(target)]
    if extra:
        cmd.append(extra)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90,
            cwd=str(project_root),
        )
    except (OSError, subprocess.TimeoutExpired):
        return "", "gemini_unavailable"

    if result.returncode != 0:
        return "", "gemini_failed"
    return result.stdout.strip(), "gemini-3-pro-preview"


def _summarize_file(path: Path, max_lines: int = 120) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if len(lines) > max_lines:
        lines = lines[:max_lines]
    return "\n".join(lines)


def _summarize_dir(path: Path, glob: str) -> str:
    files = sorted(path.rglob(glob))
    preview = [f"{candidate.relative_to(path)}" for candidate in files[:50]]
    return "\n".join(str(item) for item in preview)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create shared context digests")
    parser.add_argument("--session")
    parser.add_argument("--cwd", default=".")
    parser.add_argument("--kind", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--generated-by", default="context_digest")
    parser.add_argument("--mode", default="summarize")
    parser.add_argument("--source-ref", action="append", default=[])
    parser.add_argument("--metadata-json")
    parser.add_argument("--prefer-gemini", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--file")
    parser.add_argument("--dir")
    parser.add_argument("--glob", default="*.py")
    parser.add_argument("--text")
    parser.add_argument("--stdin", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    project_root = PROJECT_ROOT
    store = CoordinationStore.from_env(project_root)
    session_id = args.session or stable_session_id(args.cwd)

    if args.stdin:
        raw_text = Path("/dev/stdin").read_text(encoding="utf-8", errors="replace")
        source_kind = "stdin"
        source_target = None
    elif args.text is not None:
        raw_text = args.text
        source_kind = "text"
        source_target = None
    elif args.file:
        source_target = Path(args.file).resolve()
        raw_text = _summarize_file(source_target, max_lines=4000)
        source_kind = "file"
    elif args.dir:
        source_target = Path(args.dir).resolve()
        raw_text = _summarize_dir(source_target, args.glob)
        source_kind = "dir"
    else:
        raise SystemExit("one of --stdin, --text, --file, or --dir is required")

    cache_basis = {
        "kind": args.kind,
        "title": args.title,
        "mode": args.mode,
        "source_kind": source_kind,
        "source_refs": args.source_ref,
        "content_hash": _sha256_bytes(raw_text.encode("utf-8", errors="replace")),
    }
    cache_key = hashlib.sha256(json.dumps(cache_basis, sort_keys=True).encode("utf-8")).hexdigest()

    summary_text = raw_text
    model = "heuristic"
    if args.prefer_gemini and source_target is not None:
        gemini_mode = "summarize-dir" if source_kind == "dir" else args.mode
        gemini_output, model = _run_gemini(project_root, gemini_mode, source_target, args.glob if source_kind == "dir" else None)
        if gemini_output:
            summary_text = gemini_output
        else:
            model = "heuristic"

    metadata = json.loads(args.metadata_json) if args.metadata_json else {}
    payload = build_digest_payload(
        title=args.title,
        text=summary_text,
        kind=args.kind,
        source_refs=args.source_ref or ([str(source_target)] if source_target else []),
        generated_by=args.generated_by,
        model=model,
        metadata=metadata,
    )

    record = store.write_digest(session_id, payload, cache_key=cache_key, update_latest=True)
    print(json.dumps(record, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
