"""
Pre-defined pipelines: ctf_pwn, ctf_rev, bounty, firmware.
Each pipeline is a factory function that returns a configured AgentDAG.
"""
from .dag import AgentDAG, AgentNode


def _make_node(name: str, role: str, model: str, description: str = "",
               effort: str = "default", max_turns: int = None) -> AgentNode:
    return AgentNode(name=name, role=role, model=model, description=description,
                     effort=effort, max_turns=max_turns)


def ctf_pwn_pipeline(challenge_name: str = "challenge") -> AgentDAG:
    """
    CTF Pwn 6-agent pipeline (CLAUDE.md 기준):
    reverser → trigger → chain → critic → verifier → reporter
    """
    dag = AgentDAG(name=f"ctf_pwn_{challenge_name}", max_workers=1)  # sequential

    dag.add_node(_make_node("reverser", "reverser", "sonnet",
                             "Binary structure analysis, attack surface mapping",
                             effort="high", max_turns=40))
    dag.add_node(_make_node("trigger", "trigger", "sonnet",
                             "Crash exploration, minimal reproduction, primitive identification"))
    dag.add_node(_make_node("chain", "chain", "opus",
                             "Exploit chain: leak → overwrite → shell",
                             effort="high", max_turns=60))
    dag.add_node(_make_node("critic", "critic", "opus",
                             "Cross-validation of all artifacts, logic error detection",
                             effort="high", max_turns=30))
    dag.add_node(_make_node("verifier", "verifier", "sonnet",
                             "Local 3x reproduction, then remote flag extraction"))
    dag.add_node(_make_node("reporter", "reporter", "sonnet",
                             "Write knowledge/challenges/<name>.md writeup"))

    dag.add_edge("reverser", "trigger")
    dag.add_edge("trigger", "chain")
    dag.add_edge("chain", "critic")
    dag.add_edge("critic", "verifier")
    # Feedback edge: verifier can send back to chain on failure
    dag.add_edge("verifier", "chain", feedback=True)
    dag.add_edge("verifier", "reporter")

    return dag


def ctf_rev_pipeline(challenge_name: str = "challenge") -> AgentDAG:
    """
    CTF Reversing/Crypto 4-agent pipeline:
    reverser → solver → critic → verifier → reporter
    """
    dag = AgentDAG(name=f"ctf_rev_{challenge_name}", max_workers=1)

    dag.add_node(_make_node("reverser", "reverser", "sonnet",
                             "Binary/VM/algorithm analysis",
                             effort="high", max_turns=40))
    dag.add_node(_make_node("solver", "solver", "opus",
                             "Reverse computation, solver implementation (z3/GDB oracle)",
                             effort="high", max_turns=50))
    dag.add_node(_make_node("critic", "critic", "opus",
                             "Verify solver logic and address calculations",
                             effort="high", max_turns=30))
    dag.add_node(_make_node("verifier", "verifier", "sonnet",
                             "Run solve.py, verify flag format"))
    dag.add_node(_make_node("reporter", "reporter", "sonnet",
                             "Write writeup"))

    dag.add_edge("reverser", "solver")
    dag.add_edge("solver", "critic")
    dag.add_edge("critic", "verifier")
    dag.add_edge("critic", "solver", feedback=True)  # critic→solver feedback
    dag.add_edge("verifier", "reporter")

    return dag


def bounty_pipeline(target_name: str = "target") -> AgentDAG:
    """
    Bug Bounty v12 pipeline (Explore Lane + Prove Lane):
    EXPLORE LANE:
      target_evaluator → scout+analyst+threat_modeler+patch_hunter (parallel)
        → workflow_auditor+web_tester (parallel, Phase 1.5)
    PROVE LANE:
      → exploiter → reporter_draft → critic+architect (parallel)
        → triager_sim → reporter_final
    """
    dag = AgentDAG(name=f"bounty_{target_name}", max_workers=4)

    # Phase 0
    dag.add_node(_make_node("target_evaluator", "target_evaluator", "sonnet",
                             "GO/NO-GO gate: ROI, competition, tech stack match, novelty score"))

    # Phase 1 (parallel) — Explore Lane
    dag.add_node(_make_node("scout", "scout", "sonnet",
                             "Recon + duplicate pre-screen + program context + workflow_map.md"))
    dag.add_node(_make_node("analyst", "analyst", "sonnet",
                             "CVE matching, source analysis, vulnerability candidates"))
    dag.add_node(_make_node("threat_modeler", "threat_modeler", "sonnet",
                             "Trust boundary map, role matrix, state machines, invariants"))
    dag.add_node(_make_node("patch_hunter", "patch_hunter", "sonnet",
                             "Security commit diff analysis, variant candidate search"))

    # Phase 1.5 (parallel) — Explore Lane deep
    dag.add_node(_make_node("workflow_auditor", "workflow_auditor", "sonnet",
                             "Workflow state transition mapping, anomaly detection"))
    dag.add_node(_make_node("web_tester", "web_tester", "sonnet",
                             "Request-level testing + workflow pack testing"))

    # Phase 2 — Prove Lane
    dag.add_node(_make_node("exploiter", "exploiter", "opus",
                             "PoC development + Evidence Tier classification (E1-E4)",
                             effort="high", max_turns=60))

    # Phase 3
    dag.add_node(_make_node("reporter_draft", "reporter", "sonnet",
                             "Draft report with CVSS"))

    # Phase 4 (parallel review)
    dag.add_node(_make_node("critic", "critic", "opus",
                             "Fact-check: CWE, dates, function names, line numbers",
                             effort="high", max_turns=30))
    dag.add_node(_make_node("architect", "architect", "opus",
                             "Framing review: attacker perspective"))

    # Phase 4.5
    dag.add_node(_make_node("triager_sim", "triager_sim", "opus",
                             "Adversarial triage simulation: SUBMIT/STRENGTHEN/KILL"))

    # Phase 5
    dag.add_node(_make_node("reporter_final", "reporter", "sonnet",
                             "Final report + ZIP packaging"))

    # Edges — Phase 0 → Phase 1 (all 4 parallel)
    dag.add_edge("target_evaluator", "scout")
    dag.add_edge("target_evaluator", "analyst")
    dag.add_edge("target_evaluator", "threat_modeler")
    dag.add_edge("target_evaluator", "patch_hunter")

    # Phase 1 → Phase 1.5
    # workflow_auditor depends on scout+analyst+threat_modeler+patch_hunter
    dag.add_edge("scout", "workflow_auditor")
    dag.add_edge("analyst", "workflow_auditor")
    dag.add_edge("threat_modeler", "workflow_auditor")
    dag.add_edge("patch_hunter", "workflow_auditor")
    # web_tester depends on scout+analyst
    dag.add_edge("scout", "web_tester")
    dag.add_edge("analyst", "web_tester")

    # Phase 1.5 → Phase 2
    dag.add_edge("workflow_auditor", "exploiter")
    dag.add_edge("web_tester", "exploiter")
    # Also feed Phase 1 outputs directly to exploiter
    dag.add_edge("threat_modeler", "exploiter")
    dag.add_edge("patch_hunter", "exploiter")

    # Phase 2 → Phase 3 → Phase 4
    dag.add_edge("exploiter", "reporter_draft")
    dag.add_edge("reporter_draft", "critic")
    dag.add_edge("reporter_draft", "architect")
    dag.add_edge("critic", "triager_sim")
    dag.add_edge("architect", "triager_sim")
    dag.add_edge("triager_sim", "reporter_final")
    # Feedback: triager_sim → reporter_draft for STRENGTHEN
    dag.add_edge("triager_sim", "reporter_draft", feedback=True)

    return dag


def firmware_pipeline(firmware_name: str = "firmware") -> AgentDAG:
    """
    Firmware analysis pipeline:
    reverser → scanner (parallel: CVE+secrets) → exploiter → reporter
    """
    dag = AgentDAG(name=f"firmware_{firmware_name}", max_workers=3)

    dag.add_node(_make_node("reverser", "reverser", "sonnet",
                             "Firmware unpacking, filesystem extraction, binary inventory"))

    # Parallel scanning
    dag.add_node(_make_node("cve_scanner", "analyst", "sonnet",
                             "Service/library version → CVE matching via searchsploit"))
    dag.add_node(_make_node("secret_scanner", "scout", "sonnet",
                             "Hardcoded credentials, API keys, private keys via trufflehog"))
    dag.add_node(_make_node("code_scanner", "analyst", "sonnet",
                             "Static analysis: command injection, buffer overflow patterns"))

    dag.add_node(_make_node("exploiter", "exploiter", "opus",
                             "PoC for highest-value findings"))
    dag.add_node(_make_node("reporter", "reporter", "sonnet",
                             "Firmware security report"))

    dag.add_edge("reverser", "cve_scanner")
    dag.add_edge("reverser", "secret_scanner")
    dag.add_edge("reverser", "code_scanner")
    dag.add_edge("cve_scanner", "exploiter")
    dag.add_edge("secret_scanner", "exploiter")
    dag.add_edge("code_scanner", "exploiter")
    dag.add_edge("exploiter", "reporter")

    return dag


# Registry of all pipelines
PIPELINES = {
    "ctf_pwn": ctf_pwn_pipeline,
    "ctf_rev": ctf_rev_pipeline,
    "bounty": bounty_pipeline,
    "firmware": firmware_pipeline,
}


def get_pipeline(name: str, target: str = "target") -> AgentDAG:
    """Get a pipeline by name."""
    if name not in PIPELINES:
        raise ValueError(f"Unknown pipeline '{name}'. Available: {list(PIPELINES.keys())}")
    return PIPELINES[name](target)
