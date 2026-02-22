#!/usr/bin/env python3
"""
Claude Code CLI handler for DAG nodes.
Bridges dag.py execution to actual Claude Code agent spawning via subprocess.
"""
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, Any, Optional

from .dag import AgentNode
from .agent_bridge import ROLE_ARTIFACTS, check_artifacts, log_run_start, log_run_complete


class ArtifactMissingError(Exception):
    """Raised when expected agent artifacts are not found after execution."""
    pass


class ClaudeAgentHandler:
    """
    DAG node handler that spawns Claude Code agents via CLI subprocess.
    Used by dag.py's AgentDAG.run() to execute each pipeline node.
    """

    # Model mapping per CLAUDE.md spec
    ROLE_MODELS = {
        "reverser": "sonnet",
        "trigger": "sonnet",
        "solver": "opus",
        "chain": "opus",
        "critic": "opus",
        "verifier": "sonnet",
        "reporter": "sonnet",
        "scout": "sonnet",
        "analyst": "sonnet",
        "exploiter": "opus",
        "target_evaluator": "sonnet",
        "triager_sim": "opus",
        "architect": "opus",
    }

    def __init__(self, work_dir: str, session_id: str, target: str,
                 claude_path: str = "claude", dry_run: bool = False):
        self.work_dir = work_dir
        self.session_id = session_id
        self.target = target
        self.claude_path = claude_path
        self.dry_run = dry_run

    def create_handler(self, role: str) -> Callable:
        """Factory: returns a handler function for a specific agent role."""
        def handler(node: AgentNode, context: dict) -> dict:
            return self._execute_agent(node, role, context)
        return handler

    def _build_handoff_prompt(self, role: str, node: AgentNode, context: dict) -> str:
        """Build structured HANDOFF prompt for the agent."""
        # Collect previous agent outputs from context
        prev_outputs = []
        for key, value in context.items():
            if key.endswith("_output") and isinstance(value, dict):
                prev_role = key.replace("_output", "")
                artifacts = value.get("artifacts", [])
                if artifacts:
                    prev_outputs.append(
                        f"[HANDOFF from @{prev_role}]\n"
                        f"- Artifacts: {', '.join(artifacts)}\n"
                        f"- Status: {value.get('status', 'unknown')}"
                    )

        handoff_block = "\n\n".join(prev_outputs) if prev_outputs else "No previous agent outputs."

        prompt = f"""You are the @{role} agent for target: {self.target}
Working directory: {self.work_dir}

## Previous Agent Results
{handoff_block}

## Your Task
{node.description}

## Rules
- Save all artifacts to: {self.work_dir}/
- Expected outputs: {', '.join(ROLE_ARTIFACTS.get(role, ['(none)']))}
- When done, output a summary of your findings.
- Follow all rules from your agent definition (.claude/agents/{role}.md)
"""
        return prompt

    def _execute_agent(self, node: AgentNode, role: str, context: dict) -> dict:
        """Execute a single agent via Claude Code CLI."""
        prompt = self._build_handoff_prompt(role, node, context)
        model = node.model or self.ROLE_MODELS.get(role, "sonnet")

        # DB logging
        run_id = log_run_start(self.session_id, role, self.target, model)
        start_time = time.time()

        if self.dry_run:
            print(f"  [DRY-RUN] Would execute @{role} (model={model})")
            print(f"  [DRY-RUN] Prompt length: {len(prompt)} chars")
            duration = 0
            log_run_complete(run_id, "DRY_RUN", 0, f"Dry run for {role}")
            return {"status": "dry_run", "role": role, "artifacts": []}

        # Execute via Claude Code CLI
        cmd = [
            self.claude_path, "-p", prompt,
            "--permission-mode", "bypassPermissions",
            "--model", model,
            "--output-format", "json",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=node.timeout,
                cwd=self.work_dir,
                text=True,
            )

            duration = int(time.time() - start_time)

            # Parse output
            output_text = result.stdout
            try:
                output_json = json.loads(output_text)
                summary = output_json.get("result", output_text[:500])
            except (json.JSONDecodeError, TypeError):
                summary = output_text[:500] if output_text else "(no output)"

            if result.returncode != 0:
                error_msg = result.stderr[:500] if result.stderr else f"Exit code {result.returncode}"
                log_run_complete(run_id, "FAILED", duration, error_msg)
                raise RuntimeError(f"@{role} failed: {error_msg}")

            # Check artifacts
            artifact_check = check_artifacts(self.work_dir, role)

            if not artifact_check["complete"] and artifact_check["expected"]:
                missing = artifact_check["missing"]
                log_run_complete(run_id, "PARTIAL", duration,
                                 f"Missing artifacts: {missing}",
                                 artifact_check["found"])
                # Don't fail hard — some agents (reporter) write elsewhere
                print(f"  [WARN] @{role} missing artifacts: {missing}")

            log_run_complete(
                run_id, "COMPLETED", duration, summary,
                artifact_check["found"]
            )

            return {
                "status": "completed",
                "role": role,
                "artifacts": artifact_check["found"],
                "missing": artifact_check["missing"],
                "duration": duration,
                "summary": summary,
            }

        except subprocess.TimeoutExpired:
            duration = int(time.time() - start_time)
            log_run_complete(run_id, "TIMEOUT", duration, f"Timeout after {node.timeout}s")
            raise TimeoutError(f"@{role} timed out after {node.timeout}s")

    def attach_to_dag(self, dag) -> None:
        """Attach handlers to all nodes in a DAG based on their roles."""
        for name, node in dag.nodes.items():
            node.handler = self.create_handler(node.role)
