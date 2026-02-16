# Terminator Integration Guide: PentestGPT Patterns

Detailed integration examples showing how to apply PentestGPT's patterns to Terminator's Agent Teams pipeline.

---

## 1. EventBus Integration: Real-Time Agent Monitoring

### Current Flow (Blocking)
```
Orchestrator
  → Task(reverser) [BLOCKS]
    ← reversal_map.md
  → Task(trigger) [BLOCKS]
    ← trigger_report.md
  → Task(chain) [BLOCKS]
    ← solve.py
```

### Proposed Flow (Event-Driven)
```
Orchestrator
  ├─ spawn_agent(reverser)
  │  └─ [async] Wait for REVERSER_COMPLETE event
  │     ├─ Payload: reversal_map.md, artifact_path
  │     └─ Trigger: agent_result._emit_event()
  │
  ├─ spawn_agent(trigger)
  │  └─ [async] Wait for TRIGGER_COMPLETE event
  │
  └─ Parallel monitoring:
     ├─ EventBus.subscribe(FLAG_FOUND, log_flag)
     ├─ EventBus.subscribe(AGENT_ERROR, escalate_to_architect)
     └─ EventBus.subscribe(COST_THRESHOLD, warn_user)
```

### Implementation

```python
# terminator/orchestrator.py
from terminator.core.events import EventBus, TerminatorEventType, Event

class Orchestrator:
    def __init__(self, config: CTFConfig):
        self.config = config
        self.events = EventBus.get()
        self.artifacts = {}

        # Subscribe to agent events
        self.events.subscribe(TerminatorEventType.REVERSER_COMPLETE, self._on_reverser_complete)
        self.events.subscribe(TerminatorEventType.FLAG_FOUND, self._on_flag_found)
        self.events.subscribe(TerminatorEventType.AGENT_ERROR, self._on_agent_error)

    async def run_pipeline(self, challenge_path: str):
        """Run reverser → trigger → chain → verifier pipeline."""
        print("[*] Starting CTF pipeline")

        # Phase 1: Reverser
        await self._spawn_reverser(challenge_path)
        await self._wait_for(TerminatorEventType.REVERSER_COMPLETE, timeout=600)

        # Phase 2: Trigger (if needed)
        if "pwn" in self.artifacts.get("challenge_type", ""):
            await self._spawn_trigger()
            await self._wait_for(TerminatorEventType.TRIGGER_COMPLETE, timeout=300)

        # Phase 3: Chain/Solver
        await self._spawn_chain_or_solver()
        await self._wait_for(TerminatorEventType.CHAIN_COMPLETE, timeout=900)

        # Phase 4: Verifier
        await self._spawn_verifier()
        await self._wait_for(TerminatorEventType.VERIFIER_COMPLETE, timeout=600)

    async def _spawn_reverser(self, challenge_path: str):
        """Spawn reverser agent and wait for artifact."""
        print("[*] Spawning @reverser")
        prompt = self._build_reverser_prompt(challenge_path)
        task_id = Task(
            subagent_type="general-purpose",
            mode="bypassPermissions",
            name="reverser",
            prompt=prompt,
        )
        # Task starts in background; orchestrator waits for event

    async def _wait_for(self, event_type: TerminatorEventType, timeout: int) -> dict:
        """Wait for specific event with timeout."""
        event_received = asyncio.Event()
        result = {}

        def handler(event: Event):
            result.update(event.data)
            event_received.set()

        self.events.subscribe(event_type, handler)
        try:
            await asyncio.wait_for(event_received.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            print(f"[!] Agent timeout waiting for {event_type.name}")
            raise
        finally:
            self.events.unsubscribe(event_type, handler)

        return result

    def _on_reverser_complete(self, event: Event):
        """Handle reverser completion."""
        print("[+] Reverser complete")
        self.artifacts["reversal_map"] = event.data.get("artifact_path")
        self.artifacts["challenge_type"] = event.data.get("challenge_type")

    def _on_flag_found(self, event: Event):
        """Handle flag detection (from any agent)."""
        flag = event.data.get("flag")
        context = event.data.get("context")
        print(f"[!] FLAG FOUND: {flag}")
        print(f"    Context: {context[:100]}...")

    def _on_agent_error(self, event: Event):
        """Handle agent failure."""
        agent_name = event.data.get("agent_name")
        error = event.data.get("error")
        print(f"[!] {agent_name} failed: {error}")
```

---

## 2. Agent Prompt Update: "Never Give Up" Section

### Before (current reverser.md)
```markdown
# Reverser - Binary Analysis Agent

Your task is to analyze the binary and create a detailed reversal map.
...
```

### After (PentestGPT pattern)

```markdown
# Reverser - Binary Analysis Agent

## CRITICAL RULE: Complete Analysis Required

Your task is INCOMPLETE until you have produced reversal_map.md with:
- [ ] Challenge type identified (pwn, reversing, crypto, web)
- [ ] Key functions (main, vulnerable function, exploit target)
- [ ] Protection mechanisms (ASLR, PIE, RELRO, NX, stack canary)
- [ ] Attack surface clearly mapped
- [ ] Recommended solver/chain strategy (not your job to solve, just recommend)

**Do NOT provide partial analysis.** If something is unclear:
1. Use more detailed disassembly (r2 -AA)
2. Use GDB to trace execution
3. Check strings for hints
4. Re-read binary metadata

**Time spent is NOT a valid reason to stop.** Complexity is the point.

## Fallback Strategies (when analysis blocked)

**If disassembly is unclear:**
- Try different architectures (x86 vs x64 vs ARM)
- Use objdump + readelf to cross-verify
- Check imports to understand library usage
- Trace execution with GDB to see actual flow

**If control flow is too complex:**
- Identify only critical path (main → vulnerable function)
- Use call graphs (r2: `agf`)
- Look for obvious exploitation targets (strcpy, sprintf, gets)

**If protections are unclear:**
- Run checksec: `checksec --file=./binary`
- Test with GDB: disabling ASLR locally with `set disable-randomization on`
- Read ELF headers: `readelf -l ./binary`

## Output Format

```markdown
# Reversal Map: [challenge_name]

## Challenge Type
- Category: [pwn/reversing/crypto/web]
- Sub-category: [buffer overflow/ROP/heap/etc]

## Key Findings
- Entry: [address/symbol]
- Vulnerable function: [name at 0x...]
- Exploitation vector: [brief]

## Protections
- ASLR: [yes/no]
- PIE: [yes/no]
- RELRO: [full/partial/none]
- NX: [yes/no]
- Canary: [yes/no]

## Attack Strategy (for next agent)
If pwn: "Leak libc via [method], then ROP to system()"
If reversing: "Reverse key generation via GDB stepping"

## Questions for Solver
- What's the exact offset for buffer overflow?
- Should we leak or directly overwrite?
```
```

---

## 3. Session Persistence: Directory Structure

### File Layout

```
~/.terminator/
├── sessions/
│   └── dhcc_20260215_143022/          # session_id
│       ├── session.json               # SessionInfo serialized
│       ├── artifacts/
│       │   ├── reversal_map.md
│       │   ├── trigger_report.md
│       │   ├── solve.py
│       │   └── verify_log.txt
│       └── logs/
│           ├── orchestrator.log
│           ├── reverser.log
│           ├── chain.log
│           └── verifier.log
└── config.json                         # User preferences
```

### SessionInfo Schema

```python
# terminator/core/session.py

@dataclass
class CTFSession:
    session_id: str                    # dhcc_20260215_143022
    challenge_name: str                # dhcc, unibitmap, etc
    created_at: datetime
    status: SessionStatus              # idle, reverser_running, etc

    # Pipeline state
    current_phase: str                 # "reverser", "chain", "verifier"
    phases_completed: list[str]        # ["reverser", "trigger"]

    # Artifacts
    reversal_map_path: str | None
    trigger_report_path: str | None
    chain_exploit_path: str | None
    verify_results: dict[str, Any]

    # User context
    user_instructions: list[str]       # Injected hints from user
    challenge_description: str

    # Tracking
    flags_found: list[str]
    total_cost_usd: float
    last_activity: datetime
    last_error: str | None

    # Metadata
    agent_models: dict[str, str]       # {"reverser": "sonnet", "chain": "opus"}

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "challenge_name": self.challenge_name,
            "created_at": self.created_at.isoformat(),
            "status": self.status.value,
            "current_phase": self.current_phase,
            "phases_completed": self.phases_completed,
            "reversal_map_path": self.reversal_map_path,
            "trigger_report_path": self.trigger_report_path,
            "chain_exploit_path": self.chain_exploit_path,
            "verify_results": self.verify_results,
            "user_instructions": self.user_instructions,
            "challenge_description": self.challenge_description,
            "flags_found": self.flags_found,
            "total_cost_usd": self.total_cost_usd,
            "last_activity": self.last_activity.isoformat(),
            "last_error": self.last_error,
            "agent_models": self.agent_models,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CTFSession":
        return cls(
            session_id=data["session_id"],
            challenge_name=data["challenge_name"],
            created_at=datetime.fromisoformat(data["created_at"]),
            status=SessionStatus(data["status"]),
            current_phase=data.get("current_phase", "idle"),
            phases_completed=data.get("phases_completed", []),
            reversal_map_path=data.get("reversal_map_path"),
            trigger_report_path=data.get("trigger_report_path"),
            chain_exploit_path=data.get("chain_exploit_path"),
            verify_results=data.get("verify_results", {}),
            user_instructions=data.get("user_instructions", []),
            challenge_description=data.get("challenge_description", ""),
            flags_found=data.get("flags_found", []),
            total_cost_usd=data.get("total_cost_usd", 0.0),
            last_activity=datetime.fromisoformat(data.get("last_activity", datetime.now().isoformat())),
            last_error=data.get("last_error"),
            agent_models=data.get("agent_models", {}),
        )

class SessionStore:
    SESSIONS_DIR = Path.home() / ".terminator" / "sessions"

    def __init__(self, sessions_dir: Path | None = None):
        self._sessions_dir = sessions_dir or self.SESSIONS_DIR
        self._sessions_dir.mkdir(parents=True, exist_ok=True)
        self._current: CTFSession | None = None

    def create(self, challenge_name: str, description: str) -> CTFSession:
        """Create new session."""
        session_id = f"{challenge_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session = CTFSession(
            session_id=session_id,
            challenge_name=challenge_name,
            created_at=datetime.now(),
            status=SessionStatus.IDLE,
            challenge_description=description,
        )
        self._current = session
        self.save(session)
        return session

    def load(self, session_id: str) -> CTFSession | None:
        """Load session from disk."""
        session_file = self._sessions_dir / session_id / "session.json"
        if not session_file.exists():
            return None

        with open(session_file) as f:
            data = json.load(f)

        self._current = CTFSession.from_dict(data)
        return self._current

    def save(self, session: CTFSession) -> None:
        """Save session to disk."""
        session_dir = self._sessions_dir / session.session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        session_file = session_dir / "session.json"
        with open(session_file, "w") as f:
            json.dump(session.to_dict(), f, indent=2)

    def list_sessions(self) -> list[CTFSession]:
        """List all saved sessions."""
        sessions = []
        for session_dir in self._sessions_dir.iterdir():
            session_file = session_dir / "session.json"
            if session_file.exists():
                with open(session_file) as f:
                    data = json.load(f)
                sessions.append(CTFSession.from_dict(data))
        return sorted(sessions, key=lambda s: s.created_at, reverse=True)

    def update_phase(self, phase: str) -> None:
        """Update current phase."""
        if self._current:
            self._current.current_phase = phase
            self._current.phases_completed.append(phase)
            self._current.last_activity = datetime.now()
            self.save(self._current)

    def add_artifact(self, artifact_name: str, path: str) -> None:
        """Record artifact location."""
        if self._current:
            if artifact_name == "reversal_map":
                self._current.reversal_map_path = path
            elif artifact_name == "trigger_report":
                self._current.trigger_report_path = path
            elif artifact_name == "chain_exploit":
                self._current.chain_exploit_path = path
            self.save(self._current)

    def add_flag(self, flag: str) -> None:
        """Record found flag."""
        if self._current and flag not in self._current.flags_found:
            self._current.flags_found.append(flag)
            self.save(self._current)
```

---

## 4. Orchestrator Idle Recovery (PentestGPT Pattern)

### Problem
Agents sometimes hang on long operations (deep reversing, brute-force). How to detect and recover?

### Solution: Periodic Status Check

```python
# terminator/orchestrator.py

async def run_with_recovery(self, challenge_path: str, check_interval: int = 60):
    """
    Run pipeline with idle detection and recovery.

    If agent is idle > check_interval seconds, send a prompt to continue.
    """
    print("[*] Starting pipeline with idle recovery")

    try:
        # Spawn initial agent
        await self._spawn_reverser(challenge_path)

        # Wait with periodic checks
        max_idle_time = 300  # 5 minutes max idle
        last_activity = datetime.now()

        while not self._phase_complete(TerminatorEventType.REVERSER_COMPLETE):
            # Check agent status
            if (datetime.now() - last_activity).total_seconds() > max_idle_time:
                print("[!] Agent idle too long, sending recovery message")

                # Check if artifacts exist
                if os.path.exists(self.artifacts["reversal_map"]):
                    print("[+] Found reversal_map.md, moving to next phase")
                    self.events.emit(Event(
                        type=TerminatorEventType.REVERSER_COMPLETE,
                        data={"artifact_path": self.artifacts["reversal_map"]}
                    ))
                    break
                else:
                    # Send recovery instruction
                    recovery_prompt = """
                    You've been working on this for a while. Status check:
                    - Have you analyzed all functions?
                    - Have you documented protections?
                    - Is reversal_map.md complete?

                    If not, continue. If yes, save reversal_map.md and report completion.
                    """
                    self.events.emit(Event(
                        type=TerminatorEventType.INSTRUCTION_INJECT,
                        data={"instruction": recovery_prompt}
                    ))
                    last_activity = datetime.now()

            await asyncio.sleep(check_interval)

    except asyncio.TimeoutError:
        print("[!] Pipeline timeout")
        raise
```

---

## 5. Enhanced Flag Detection: All Agents

### Current: Only Verifier Checks for Flags

```python
# .claude/agents/verifier.md
# Internal check only: compare output to flag file
```

### Proposed: All Agents Emit FLAG_FOUND Events

```python
# terminator/core/utils.py

FLAG_PATTERNS = [
    r"flag\{[^\}]+\}",
    r"FLAG\{[^\}]+\}",
    r"DH\{[^\}]+\}",
    r"CYAI\{[^\}]+\}",
    r"GoN\{[^\}]+\}",
    r"\b[a-f0-9]{32}\b",
]

def detect_flags(text: str) -> list[str]:
    """Extract all potential flags from text."""
    flags = []
    for pattern in FLAG_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            flag = match.group(0)
            if flag not in flags:
                flags.append(flag)
    return flags

# Usage in each agent prompt:
# .claude/agents/reverser.md
def complete_reverser_task(challenge_path: str):
    # ... analysis ...
    output = generate_reversal_map(challenge_path)

    # Check for flags in output
    flags = detect_flags(output)
    if flags:
        SendMessage(
            type="message",
            recipient="team-lead",
            content=f"Flags found during analysis:\n" + "\n".join(flags),
            summary=f"{len(flags)} flags detected in output"
        )
```

### Orchestrator Aggregates All Flags

```python
# terminator/orchestrator.py

def __init__(self):
    self.flags_found = set()
    self.events.subscribe(TerminatorEventType.FLAG_FOUND, self._on_flag_found)

def _on_flag_found(self, event: Event):
    flag = event.data.get("flag")
    context = event.data.get("context", "")
    source_agent = event.data.get("source_agent", "unknown")

    self.flags_found.add(flag)
    self.session.add_flag(flag)

    print(f"[!] FLAG: {flag}")
    print(f"    Source: {source_agent}")
    print(f"    Context: {context[:80]}")
```

---

## 6. Cost Breakdown: Tracking Token Usage

### Per-Agent Cost Tracking

```python
# terminator/orchestrator.py

@dataclass
class AgentMetrics:
    name: str
    model: str
    cost_usd: float
    tokens_in: int
    tokens_out: int
    duration_sec: float
    status: str  # success, timeout, error

class MetricsCollector:
    def __init__(self):
        self.metrics: dict[str, AgentMetrics] = {}

    def record_agent(self, metrics: AgentMetrics):
        self.metrics[metrics.name] = metrics

    def total_cost(self) -> float:
        return sum(m.cost_usd for m in self.metrics.values())

    def report(self) -> str:
        lines = ["Agent Cost Breakdown:"]
        for name, m in self.metrics.items():
            lines.append(f"  {name:12} {m.model:8} ${m.cost_usd:6.4f}  {m.tokens_in:6}→{m.tokens_out:6}  {m.duration_sec:6.1f}s")
        lines.append(f"  {'TOTAL':12} {'':8} ${self.total_cost():6.4f}")
        return "\n".join(lines)

# In orchestrator:
metrics = MetricsCollector()

# After each agent completes:
agent_result = await spawn_agent(...)
metrics.record_agent(AgentMetrics(
    name="reverser",
    model="sonnet",
    cost_usd=agent_result.get("cost_usd"),
    tokens_in=agent_result.get("tokens_in"),
    tokens_out=agent_result.get("tokens_out"),
    duration_sec=(datetime.now() - start_time).total_seconds(),
    status="success"
))

# Final report:
print(metrics.report())
```

---

## 7. CLI Interface: Resume Sessions

### Current
```bash
terminator.sh ctf path/to/challenge.zip
```

### Enhanced
```bash
# Start new
terminator.sh ctf path/to/challenge.zip --new

# Resume saved session
terminator.sh ctf --resume dhcc_20260215_143022

# List sessions
terminator.sh sessions --list

# View session details
terminator.sh sessions --show dhcc_20260215_143022

# Delete old session
terminator.sh sessions --delete dhcc_20260215_143022
```

### Implementation

```bash
#!/bin/bash
# terminator.sh

case "$1" in
    ctf)
        if [[ "$2" == "--resume" ]]; then
            session_id="$3"
            python -m terminator.cli ctf --resume "$session_id"
        else
            challenge_path="$2"
            python -m terminator.cli ctf "$challenge_path"
        fi
        ;;

    sessions)
        case "$2" in
            --list)
                python -m terminator.cli sessions list
                ;;
            --show)
                session_id="$3"
                python -m terminator.cli sessions show "$session_id"
                ;;
            --delete)
                session_id="$3"
                python -m terminator.cli sessions delete "$session_id"
                ;;
        esac
        ;;
esac
```

---

## Implementation Checklist

- [ ] **Week 1: Backend & Events**
  - [ ] Create `terminator/core/backend.py` (abstract interface)
  - [ ] Create `terminator/core/events.py` (EventBus + event types)
  - [ ] Update orchestrator to use events

- [ ] **Week 2: Sessions**
  - [ ] Create `terminator/core/session.py` (SessionStore)
  - [ ] Update orchestrator to save/load sessions
  - [ ] Add `--resume` CLI flag

- [ ] **Week 3: Enhanced Prompts**
  - [ ] Update `.claude/agents/*.md` with "Never-Stop" section
  - [ ] Add fallback strategies to each agent
  - [ ] Add flag detection to all agents

- [ ] **Week 4: Metrics & Validation**
  - [ ] Create `terminator/core/validator.py` (local testing)
  - [ ] Add cost tracking per agent
  - [ ] Add idle recovery logic

---

**Integration difficulty**: Medium (copy patterns from PentestGPT)
**Benefit**: Better observability, fault tolerance, session persistence
**Time estimate**: 4 weeks (2-3 hours/day)

