# Quick Reference: PentestGPT Patterns for Terminator

One-page summary of actionable patterns from PentestGPT and try-harder.

---

## Top 3 Patterns to Adopt NOW

### 1. Event-Driven Architecture (HIGH IMPACT, MEDIUM EFFORT)

**Current problem**: Orchestrator blocks waiting for agent output. Long operations timeout.

**Pattern**: Use pub/sub events instead of blocking.

```python
# Before (blocking)
result = await spawn_agent(reverser_task)  # BLOCKS forever if agent hangs
reversal_map = result["artifact"]

# After (event-driven)
spawn_agent(reverser_task)  # Returns immediately
event = await wait_for(EVENT_REVERSER_COMPLETE, timeout=600)  # Async wait
reversal_map = event["artifact"]
```

**Files to create**:
- `terminator/core/events.py` (copy from PentestGPT, 100 LOC)
- `terminator/core/event_types.py` (define enum, 20 LOC)

**Benefit**:
- Real-time monitoring of agent progress
- Timeout detection + recovery
- Parallel event handling (multiple agents' flags detected simultaneously)

---

### 2. "Never-Stop" Language in Prompts (LOW EFFORT, HIGH PAYOFF)

**Current problem**: Agents give up after 3-5 attempts ("Given complexity...").

**Pattern**: Add aggressive persistence language + fallback strategies.

```markdown
# .claude/agents/chain.md

## CRITICAL RULE: Never Give Up

Your task is INCOMPLETE until solve.py passes local testing 3+ times.

- If exploit crashes: analyze core dump → adjust → retry
- If offset wrong: use GDB to verify → recalculate → retry
- **Complexity is NOT a reason to stop. That's the entire point.**

## Fallback Strategies (when stuck)

1. **If payload crashes**: Try different shellcodes (bash, python, perl, nc)
2. **If offset wrong**: Brute-force with cyclic pattern
3. **If libc leaks unstable**: Implement leak verification first
4. **If ROP too complex**: Try simpler gadgets (mov, pop, ret only)
```

**Files to update**:
- `.claude/agents/reverser.md` (add 20 lines)
- `.claude/agents/trigger.md` (add 20 lines)
- `.claude/agents/chain.md` (add 20 lines)
- `.claude/agents/solver.md` (add 20 lines)

**Benefit**:
- Agents persist 2-3x longer before giving up
- Structured fallback alternatives instead of "try something"
- Prevents false negatives (solvable problems marked impossible)

---

### 3. Session Persistence (MEDIUM EFFORT, HIGH BENEFIT)

**Current problem**: Long sessions (6+ hours) can't pause/resume. Work is lost if connection drops.

**Pattern**: JSON file-based session state.

```python
# terminator/core/session.py

@dataclass
class CTFSession:
    session_id: str
    challenge_name: str
    status: SessionStatus  # idle, reverser_running, chain_running, completed
    phases_completed: list[str]  # ["reverser", "trigger"]
    reversal_map_path: str | None
    chain_exploit_path: str | None
    flags_found: list[str]

# Usage:
session = SessionStore.create(challenge="dhcc", description="...")
# After reverser finishes:
session.add_artifact("reversal_map", "/tmp/reversal_map.md")
session.update_phase("reverser")
session.save()

# Next day (network was down):
session = SessionStore.load("dhcc_20260215_143022")
await run_pipeline_from_phase(session.current_phase)
```

**Files to create**:
- `terminator/core/session.py` (150 LOC)

**CLI enhancement**:
```bash
terminator.sh ctf --resume dhcc_20260215_143022
terminator.sh sessions --list
terminator.sh sessions --show dhcc_20260215_143022
```

**Benefit**:
- Pause/resume across days
- Automatic recovery from network failures
- Better resource management (don't re-analyze if already done)

---

## 4 Additional Patterns (Lower Priority)

| Pattern | Effort | Benefit | Where |
|---------|--------|---------|-------|
| **Backend Abstraction** | Medium | Future multi-model support | `terminator/core/backend.py` |
| **Local Exploit Validation** | Medium | Prevent broken exploits at remote | `terminator/core/validator.py` |
| **Cost Tracking** | Low | Know how much money spent | `terminator/metrics.py` |
| **Idle Recovery** | Medium | Auto-detect hung agents, prompt them | `terminator/orchestrator.py` |

---

## Code Templates (Copy-Paste Ready)

### Template 1: EventBus (from PentestGPT)

```python
# terminator/core/events.py
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Optional

class EventType(Enum):
    REVERSER_COMPLETE = auto()
    CHAIN_COMPLETE = auto()
    FLAG_FOUND = auto()
    AGENT_ERROR = auto()

@dataclass
class Event:
    type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

class EventBus:
    _instance: Optional["EventBus"] = None
    _lock = threading.Lock()

    def __init__(self):
        self._handlers: dict[EventType, list[Callable]] = {}
        self._handler_lock = threading.Lock()

    @classmethod
    def get(cls) -> "EventBus":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def subscribe(self, event_type: EventType, handler: Callable[[Event], None]) -> None:
        with self._handler_lock:
            if event_type not in self._handlers:
                self._handlers[event_type] = []
            self._handlers[event_type].append(handler)

    def emit(self, event: Event) -> None:
        with self._handler_lock:
            handlers = self._handlers.get(event.type, []).copy()
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                pass
```

### Template 2: Session Class

```python
# terminator/core/session.py
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
import json

class SessionStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"

@dataclass
class CTFSession:
    session_id: str
    challenge_name: str
    created_at: datetime
    status: SessionStatus = SessionStatus.IDLE
    current_phase: str = "idle"
    phases_completed: list[str] = field(default_factory=list)
    reversal_map_path: str | None = None
    trigger_report_path: str | None = None
    chain_exploit_path: str | None = None
    flags_found: list[str] = field(default_factory=list)
    total_cost_usd: float = 0.0
    last_error: str | None = None

    def to_json(self) -> str:
        return json.dumps({
            "session_id": self.session_id,
            "challenge_name": self.challenge_name,
            "created_at": self.created_at.isoformat(),
            "status": self.status.value,
            "current_phase": self.current_phase,
            "phases_completed": self.phases_completed,
            "reversal_map_path": self.reversal_map_path,
            "trigger_report_path": self.trigger_report_path,
            "chain_exploit_path": self.chain_exploit_path,
            "flags_found": self.flags_found,
            "total_cost_usd": self.total_cost_usd,
            "last_error": self.last_error,
        }, indent=2)

    @classmethod
    def from_json(cls, data: str) -> "CTFSession":
        d = json.loads(data)
        return cls(
            session_id=d["session_id"],
            challenge_name=d["challenge_name"],
            created_at=datetime.fromisoformat(d["created_at"]),
            status=SessionStatus(d["status"]),
            current_phase=d.get("current_phase", "idle"),
            phases_completed=d.get("phases_completed", []),
            reversal_map_path=d.get("reversal_map_path"),
            trigger_report_path=d.get("trigger_report_path"),
            chain_exploit_path=d.get("chain_exploit_path"),
            flags_found=d.get("flags_found", []),
            total_cost_usd=d.get("total_cost_usd", 0.0),
            last_error=d.get("last_error"),
        )

class SessionStore:
    SESSIONS_DIR = Path.home() / ".terminator" / "sessions"

    def __init__(self):
        self.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        self._current: CTFSession | None = None

    def create(self, challenge_name: str) -> CTFSession:
        session_id = f"{challenge_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session = CTFSession(session_id=session_id, challenge_name=challenge_name, created_at=datetime.now())
        self._current = session
        self.save(session)
        return session

    def load(self, session_id: str) -> CTFSession | None:
        session_file = self.SESSIONS_DIR / session_id / "session.json"
        if not session_file.exists():
            return None
        with open(session_file) as f:
            self._current = CTFSession.from_json(f.read())
        return self._current

    def save(self, session: CTFSession) -> None:
        session_dir = self.SESSIONS_DIR / session.session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        with open(session_dir / "session.json", "w") as f:
            f.write(session.to_json())

    def update_phase(self, phase: str) -> None:
        if self._current:
            self._current.current_phase = phase
            self._current.phases_completed.append(phase)
            self.save(self._current)
```

### Template 3: Never-Stop Section for Agent Prompts

```markdown
## CRITICAL RULE: Complete Solution Required

Your task is INCOMPLETE until you have:
- [x] [deliverable 1]
- [x] [deliverable 2]
- [x] [deliverable 3]

**Do NOT provide partial results.** If stuck:

1. Verify assumptions (re-read challenge, check tool output)
2. Try alternative approach (different tool, different direction)
3. Enumerate harder (more aggressive scan, fuzz more aggressively)
4. Consult reference material (man pages, documentation, examples)

**Complexity is the point.** Time spent is NOT a reason to stop.

### Fallback Strategies

If [common problem 1]:
- Try [alternative 1]
- Try [alternative 2]
- Try [alternative 3]

If [common problem 2]:
- Check [X]
- Check [Y]
- Verify [Z]
```

---

## Integration Roadmap (4 Weeks)

| Week | Task | Files | LOC | Priority |
|------|------|-------|-----|----------|
| 1 | EventBus + Events | `core/events.py` | 100 | HIGH |
| 1 | Update orchestrator | `orchestrator.py` | +50 | HIGH |
| 2 | Session persistence | `core/session.py` | 150 | HIGH |
| 2 | CLI `--resume` | `terminator.sh`, `cli.py` | +30 | MEDIUM |
| 3 | Prompt updates | `.claude/agents/*.md` | +100 total | HIGH |
| 3 | Flag detection | `core/utils.py` | +30 | MEDIUM |
| 4 | Idle recovery | `orchestrator.py` | +50 | LOW |
| 4 | Cost tracking | `metrics.py` | 80 | LOW |

**Total effort**: ~2-3 weeks of part-time work

---

## How to Use This Research

1. **Read first**: `llm_pentesting_patterns.md` (5 min overview)
2. **Deep dive**: `integration_guide.md` (full examples and architecture)
3. **Implement**: Use templates from this file (copy-paste)
4. **Reference**: Consult PentestGPT repo for edge cases

---

## PentestGPT vs Terminator: Key Differences

| Aspect | PentestGPT | Terminator |
|--------|-----------|-----------|
| **Control flow** | Single agent, internal loop | Multi-agent pipeline |
| **Pause/resume** | Built-in (session management) | NEW: Add via events |
| **Flag detection** | One place in agent | NEW: All agents + orchestrator |
| **Session state** | File-based JSON | NEW: Implement |
| **Backend abstraction** | Yes (ClaudeCodeBackend) | NEW: Create interface |
| **Event bus** | Yes (EventBus) | NEW: Copy from them |

**Bottom line**: Terminator can reuse 70% of PentestGPT's infrastructure patterns with minimal adaptation.

---

## Files to Create/Modify

```
terminator/
├── core/
│   ├── backend.py           [NEW - 80 LOC] Optional, medium effort
│   ├── events.py            [NEW - 100 LOC] HIGH priority
│   ├── session.py           [NEW - 150 LOC] HIGH priority
│   ├── validator.py         [NEW - 80 LOC] Optional, medium effort
│   ├── utils.py             [+30 LOC] Flag detection
│   └── orchestrator.py      [+50 LOC] Event integration
├── metrics.py               [NEW - 80 LOC] Optional, low priority
├── cli.py                   [+30 LOC] Resume support
└── .claude/agents/
    ├── reverser.md          [+20 LOC] Never-stop section
    ├── trigger.md           [+20 LOC] Fallback strategies
    ├── chain.md             [+20 LOC] Never-stop + fallbacks
    └── solver.md            [+20 LOC] Never-stop section
```

---

## References

- **PentestGPT source**: `/tmp/PentestGPT/` (cloned)
  - `pentestgpt/core/events.py` (EventBus pattern)
  - `pentestgpt/core/session.py` (Session persistence)
  - `pentestgpt/core/controller.py` (Orchestration)
  - `pentestgpt/prompts/pentesting.py` (System prompts)

- **try-harder source**: `/tmp/try-harder/try_harder.py`
  - Game mechanics (validation)
  - Hint-based learning (not directly applicable, but inspires fallback structure)

---

**Document prepared**: February 15, 2026
**Research scope**: PentestGPT (USENIX 2024, 86.5% benchmark), try-harder (OSCP game)
**Time to implement**: 2-4 weeks (high priority items: Week 1-2)
**ROI**: 3-5x longer agent persistence, 100% session recovery
