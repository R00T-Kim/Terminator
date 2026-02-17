#!/usr/bin/env python3
"""
LiteLLM Model Router for Terminator Security Agent
Replaces gemini_query.sh with a unified multi-model routing interface.

Usage:
    python model_router.py --mode reverse --file binary.elf
    python model_router.py --mode analyze --file vuln.py
    python model_router.py --mode ask --question "How does heap exploitation work?"
    python model_router.py --mode triage --file source.js
    python model_router.py --mode summarize --file large_decompile.c

Agent Role -> Model mapping (follows CLAUDE.md):
    reverser, trigger, scout, analyst, verifier, reporter -> sonnet
    solver, chain, critic, exploiter, triager_sim          -> opus
    simple lookups                                          -> haiku
"""

import os
import sys
import argparse
import litellm
from pathlib import Path

# Model routing table (agent role -> model alias)
ROLE_MODEL_MAP = {
    "reverser": "claude-sonnet",
    "trigger": "claude-sonnet",
    "scout": "claude-sonnet",
    "analyst": "claude-sonnet",
    "verifier": "claude-sonnet",
    "reporter": "claude-sonnet",
    "solver": "claude-opus",
    "chain": "claude-opus",
    "critic": "claude-opus",
    "exploiter": "claude-opus",
    "triager_sim": "claude-opus",
    "lookup": "claude-haiku",
}

# Mode -> preferred model (for standalone use)
MODE_MODEL_MAP = {
    "reverse": "gemini-pro",      # Large binary decompile (gemini has big context)
    "analyze": "claude-sonnet",   # Vulnerability analysis
    "triage": "gemini-pro",       # Quick pre-screening (cost efficient)
    "summarize": "gemini-pro",    # Large file summarization
    "summarize-dir": "gemini-pro",
    "protocol": "claude-opus",    # Protocol/state machine (needs deep reasoning)
    "bizlogic": "claude-opus",    # Business logic analysis
    "review": "claude-sonnet",    # Code review
    "ask": "claude-sonnet",       # General question
}

MAX_FILE_LINES = int(os.getenv("MAX_FILE_LINES", "5000"))


def read_file_content(file_path: str, max_lines: int = MAX_FILE_LINES) -> str:
    """Read file content with line limit."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    lines = path.read_text(errors="replace").splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines.append(f"\n... [TRUNCATED at {max_lines} lines] ...")
    return "\n".join(lines)


def build_system_prompt(mode: str) -> str:
    prompts = {
        "reverse": "You are an expert reverse engineer. Analyze the provided binary/decompiled code. Identify: 1) Key functions and their purpose, 2) Data structures, 3) Potential vulnerabilities, 4) Attack surface. Be concise and technical.",
        "analyze": "You are a security researcher specializing in vulnerability analysis. Analyze the code for security vulnerabilities. Focus on: CWE categories, exploit primitives, severity, and exploitation path. Output structured findings.",
        "triage": "You are a rapid vulnerability screener. Quickly identify if this code/target has HIGH/MEDIUM/LOW security risk. Provide a 3-sentence summary with risk level and top 2 concerns.",
        "summarize": "You are a technical summarizer. Summarize the key security-relevant aspects of this file. Focus on: entry points, data flows, authentication logic, and any obvious red flags.",
        "summarize-dir": "You are a codebase analyst. Summarize the security posture of this codebase. Identify: attack surface, key components, trust boundaries, and recommended analysis focus areas.",
        "protocol": "You are a protocol security analyst. Analyze this code for protocol/state machine vulnerabilities including: state confusion, replay attacks, race conditions, and message tampering.",
        "bizlogic": "You are a business logic security expert. Identify business logic flaws: broken access control, price manipulation, workflow bypass, and privilege escalation through logic errors.",
        "review": "You are a security code reviewer. Review this exploit/PoC code for: correctness, reliability, edge cases, and potential improvements. Identify any bugs in the exploit logic.",
        "ask": "You are a cybersecurity expert assistant. Answer the security question accurately and technically.",
    }
    return prompts.get(mode, prompts["ask"])


def route_query(
    mode: str,
    question: str = None,
    file_path: str = None,
    role: str = None,
    model_override: str = None,
) -> str:
    """Route a query to the appropriate model and return the response."""

    # Determine model
    if model_override:
        model = model_override
    elif role and role in ROLE_MODEL_MAP:
        model = ROLE_MODEL_MAP[role]
    else:
        model = MODE_MODEL_MAP.get(mode, "claude-sonnet")

    # Build messages
    system_prompt = build_system_prompt(mode)
    user_content = ""

    if file_path:
        file_content = read_file_content(file_path)
        user_content += f"```\n{file_content}\n```\n\n"

    if question:
        user_content += question
    elif not file_path:
        user_content = "Analyze the provided content."

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]

    # LiteLLM proxy or direct call
    litellm_base_url = os.getenv("LITELLM_BASE_URL")
    litellm_api_key = os.getenv("LITELLM_MASTER_KEY", os.getenv("ANTHROPIC_API_KEY"))

    if litellm_base_url:
        # Use LiteLLM proxy
        response = litellm.completion(
            model=model,
            messages=messages,
            api_base=litellm_base_url,
            api_key=litellm_api_key,
        )
    else:
        # Direct provider call (fallback)
        response = litellm.completion(
            model=model,
            messages=messages,
        )

    return response.choices[0].message.content


def route_query_tracked(
    mode: str,
    question: str = None,
    file_path: str = None,
    role: str = None,
    model_override: str = None,
    session_id: str = None,
    target: str = None,
) -> str:
    """Route query with infrastructure tracking (logs to agent_runs if session provided)."""
    import time
    start = time.time()

    result = route_query(mode, question, file_path, role, model_override)

    duration = int(time.time() - start)

    # Log to infrastructure if session provided
    if session_id:
        try:
            from tools.dag_orchestrator.agent_bridge import log_run_start, log_run_complete
            model = model_override or ROLE_MODEL_MAP.get(role, MODE_MODEL_MAP.get(mode, "unknown"))
            run_id = log_run_start(session_id, role or f"llm_{mode}", target or "unknown", model)
            log_run_complete(run_id, "COMPLETED", duration, f"Mode: {mode}", [])
        except Exception:
            pass  # Infrastructure down — don't break the query

    return result


def main():
    parser = argparse.ArgumentParser(description="Terminator Model Router")
    parser.add_argument("--mode", "-m", default="ask",
                        choices=list(MODE_MODEL_MAP.keys()),
                        help="Analysis mode")
    parser.add_argument("--file", "-f", help="File to analyze")
    parser.add_argument("--question", "-q", help="Question or prompt")
    parser.add_argument("--role", "-r", help="Agent role for model routing")
    parser.add_argument("--model", help="Override model selection")
    parser.add_argument("--dir", "-d", help="Directory for summarize-dir mode")
    parser.add_argument("--session", "-s", help="Session ID for infrastructure tracking")
    parser.add_argument("--target", "-t", help="Target identifier for tracking")

    args = parser.parse_args()

    # Handle summarize-dir mode
    if args.mode == "summarize-dir" and args.dir:
        dir_path = Path(args.dir)
        summaries = []
        for f in sorted(dir_path.rglob("*"))[:20]:  # limit to 20 files
            if f.is_file() and f.suffix in {".py", ".js", ".ts", ".go", ".rs", ".c", ".cpp", ".sol"}:
                try:
                    content = read_file_content(str(f), max_lines=500)
                    summaries.append(f"### {f.name}\n{content[:2000]}")
                except Exception:
                    pass
        combined = "\n\n".join(summaries)
        if args.session:
            result = route_query_tracked(
                mode="summarize-dir",
                question=f"Summarize the security posture of directory: {args.dir}\n\n{combined}",
                file_path=None,
                role=args.role,
                model_override=args.model,
                session_id=args.session,
                target=args.target,
            )
        else:
            result = route_query(
                mode="summarize-dir",
                question=f"Summarize the security posture of directory: {args.dir}\n\n{combined}",
                file_path=None,
                role=args.role,
                model_override=args.model,
            )
        print(result)
        return

    try:
        if args.session:
            result = route_query_tracked(
                mode=args.mode,
                question=args.question,
                file_path=args.file,
                role=args.role,
                model_override=args.model,
                session_id=args.session,
                target=args.target,
            )
        else:
            result = route_query(
                mode=args.mode,
                question=args.question,
                file_path=args.file,
                role=args.role,
                model_override=args.model,
            )
        print(result)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Model router error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
