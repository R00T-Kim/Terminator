#!/usr/bin/env python3
"""Flag Pattern Detector — CTF flag detection with strict validation.

Adapted from PentestGPT's _detect_flags() and FLAG_PATTERNS with additional
Terminator-specific patterns (DH, GoN, CYAI) and a strict validation mode
inspired by PentestGPT's benchmark OutputParser.

Zero external dependencies — Python 3.12 stdlib only (re, sys, dataclasses).

Usage:
    # Programmatic
    from tools.flag_detector import detect_flags, FlagMatch
    matches = detect_flags("output with DH{test_flag_123}", strict=True)

    # CLI
    echo "output with DH{test_flag_123}" | python3 tools/flag_detector.py
    python3 tools/flag_detector.py "text with FLAG{...}"
    python3 tools/flag_detector.py --strict "text with FLAG{ab}"

Original: PentestGPT/pentestgpt/core/controller.py (_detect_flags, FLAG_PATTERNS)
"""

import re
import sys
from dataclasses import dataclass
from typing import List, Tuple

# --- Pattern definitions ----------------------------------------------------

# Each entry: (compiled_regex, pattern_name, is_named_format)
# is_named_format=True means PREFIX{content} style, used for strict validation.
_PATTERN_DEFS: List[Tuple[str, str, bool]] = [
    # Specific named patterns FIRST (checked before generic_ctf to get correct
    # pattern_name attribution via the seen-set dedup).
    #
    # PentestGPT base patterns
    (r"flag\{[^\}]+\}", "flag", True),
    (r"FLAG\{[^\}]+\}", "FLAG", True),
    (r"HTB\{[^\}]+\}", "HTB", True),
    (r"CTF\{[^\}]+\}", "CTF", True),
    # Terminator-specific patterns (from CLAUDE.md Flag Formats)
    (r"DH\{[^\}]+\}", "DH", True),
    (r"GoN\{[^\}]+\}", "GoN", True),
    (r"CYAI\{[^\}]+\}", "CYAI", True),
    # Generic catch-all (MUST be after all specific named patterns)
    (r"[A-Za-z0-9_]+\{[^\}]+\}", "generic_ctf", True),
    # Hex hash pattern
    (r"\b[a-f0-9]{32}\b", "hex32", False),
]

# Pre-compiled patterns for performance
_COMPILED_PATTERNS: List[Tuple[re.Pattern[str], str, bool]] = [
    (re.compile(pat, re.IGNORECASE), name, is_named)
    for pat, name, is_named in _PATTERN_DEFS
]

# Strict validation thresholds
_MIN_NAMED_CONTENT_LEN = 4    # Minimum chars inside braces for named patterns
_MIN_HEX_LEN = 32             # Minimum length for hex patterns (already enforced by regex)


# --- Data structures --------------------------------------------------------

@dataclass
class FlagMatch:
    """A detected flag match with metadata."""

    flag: str               # The full matched flag string
    pattern_name: str       # Which pattern matched (e.g., "DH", "hex32", "generic_ctf")
    position: int           # Character offset in the input text
    strict_valid: bool      # Whether this match passes strict validation


# --- Core detection ---------------------------------------------------------

def detect_flags(text: str, strict: bool = False) -> List[FlagMatch]:
    """Detect potential flags in text.

    Scans the input text against all known flag patterns (PentestGPT base +
    Terminator-specific). Returns deduplicated matches ordered by position.

    Args:
        text: Text to search for flags.
        strict: If True, apply strict validation rules:
                - Named patterns (PREFIX{content}): content must be >= 4 chars.
                - Hex patterns: must be exactly 32 hex chars (already enforced).
                This filters out trivial/false-positive matches.

    Returns:
        List of FlagMatch objects, deduplicated by flag string, ordered by
        position in the input text.
    """
    if not text:
        return []

    seen: set[str] = set()
    matches: List[FlagMatch] = []

    for compiled, name, is_named in _COMPILED_PATTERNS:
        for m in compiled.finditer(text):
            flag = m.group(0)
            if flag in seen:
                continue
            seen.add(flag)

            # Always compute strict_valid truthfully so callers can inspect it
            valid = _validate_strict(flag, is_named)

            matches.append(
                FlagMatch(
                    flag=flag,
                    pattern_name=name,
                    position=m.start(),
                    strict_valid=valid,
                )
            )

    # Sort by position for stable output
    matches.sort(key=lambda fm: fm.position)

    if strict:
        matches = [fm for fm in matches if fm.strict_valid]

    return matches


def detect_flags_simple(text: str) -> List[str]:
    """Simplified interface — returns just the flag strings.

    Convenience wrapper for quick use. No strict validation.

    Args:
        text: Text to search for flags.

    Returns:
        List of unique flag strings found.
    """
    return [fm.flag for fm in detect_flags(text, strict=False)]


# --- Strict validation ------------------------------------------------------

def _validate_strict(flag: str, is_named: bool) -> bool:
    """Apply strict validation to a flag match.

    Args:
        flag: The matched flag string.
        is_named: Whether this is a PREFIX{content} format.

    Returns:
        True if the flag passes strict validation.
    """
    if is_named:
        # Extract content between braces
        brace_start = flag.find("{")
        brace_end = flag.rfind("}")
        if brace_start == -1 or brace_end == -1:
            return False
        content = flag[brace_start + 1 : brace_end]
        if len(content) < _MIN_NAMED_CONTENT_LEN:
            return False
        # Reject if content is all identical chars (e.g., "aaaa")
        if len(set(content)) == 1:
            return False
        return True
    else:
        # Hex pattern: regex already enforces 32 chars, but double-check
        hex_only = flag.strip()
        if len(hex_only) < _MIN_HEX_LEN:
            return False
        # Reject all-zero or trivial patterns
        if len(set(hex_only)) <= 2:
            return False
        return True


# --- CLI interface ----------------------------------------------------------

def _format_match(fm: FlagMatch, show_strict: bool = False) -> str:
    """Format a FlagMatch for terminal display."""
    parts = [
        f"  [{fm.pattern_name:12s}]",
        f"pos={fm.position:<6d}",
        f"{fm.flag}",
    ]
    if show_strict:
        validity = "VALID" if fm.strict_valid else "REJECTED"
        parts.append(f"  ({validity})")
    return " ".join(parts)


def main() -> None:
    """CLI entry point.

    Usage:
        python3 flag_detector.py "text with FLAG{...}"
        echo "output" | python3 flag_detector.py
        python3 flag_detector.py --strict "text with FLAG{ab}"
    """
    strict = False
    text_args: List[str] = []

    for arg in sys.argv[1:]:
        if arg in ("--strict", "-s"):
            strict = True
        elif arg in ("-h", "--help"):
            _print_help()
            return
        else:
            text_args.append(arg)

    # Read from args or stdin
    if text_args:
        text = " ".join(text_args)
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        _print_help()
        return

    matches = detect_flags(text, strict=False)

    if not matches:
        print("No flags detected.")
        return

    # If strict mode, show all but mark validity
    if strict:
        valid_count = sum(1 for fm in matches if fm.strict_valid)
        print(f"Detected {len(matches)} pattern(s), {valid_count} pass strict validation:")
    else:
        print(f"Detected {len(matches)} flag(s):")

    print("-" * 60)
    for fm in matches:
        # In strict mode, always show strict_valid status
        if strict:
            validity = "VALID" if fm.strict_valid else "REJECTED"
            print(f"  [{fm.pattern_name:12s}] pos={fm.position:<6d} {fm.flag}  ({validity})")
        else:
            print(f"  [{fm.pattern_name:12s}] pos={fm.position:<6d} {fm.flag}")
    print("-" * 60)

    if strict:
        valid_flags = [fm.flag for fm in matches if fm.strict_valid]
        if valid_flags:
            print(f"\nStrict-valid flags: {', '.join(valid_flags)}")
        else:
            print("\nNo flags passed strict validation.")


def _print_help() -> None:
    """Print CLI help."""
    print("Usage: python3 flag_detector.py [--strict] \"text with flags\"")
    print("       echo \"output\" | python3 flag_detector.py [--strict]")
    print()
    print("Flag Pattern Detector for Terminator CTF/Bug Bounty pipeline.")
    print("Adapted from PentestGPT FLAG_PATTERNS with Terminator additions.")
    print()
    print("Options:")
    print("  --strict, -s  Apply strict validation (min 4 chars in braces,")
    print("                reject trivial patterns)")
    print()
    print("Supported patterns:")
    for _, name, is_named in _PATTERN_DEFS:
        fmt = "PREFIX{content}" if is_named else "raw hex"
        print(f"  {name:15s} ({fmt})")
    print()
    print("Programmatic usage:")
    print("  from tools.flag_detector import detect_flags, FlagMatch")
    print('  matches = detect_flags("output text", strict=True)')


if __name__ == "__main__":
    main()
