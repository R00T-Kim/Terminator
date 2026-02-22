# Immunefi Target Candidates — 2026-02-22

Pre-evaluated targets for next bug bounty campaigns. Based on v5 pipeline rules.

## Selection Criteria (v5 Hard NO-GO)
- 3+ audits = AUTO NO-GO
- 100+ resolved reports = AUTO NO-GO
- 3+ years operational = AUTO NO-GO
- Fork with all audit fixes applied = AUTO NO-GO

---

## Tier 1: High Priority (GO candidates)

### Ethena (NEW scope expansion)
- **Bounty**: Up to $3,000,000
- **Scope**: New contracts added recently (scope expansion)
- **Audits**: ~2 (manageable)
- **Why GO**: Fresh scope = less picked over, very high bounty ceiling
- **Risk**: High competition due to bounty size
- **Pre-check**: Verify exact new scope contracts on Immunefi page

### Alchemix V3
- **Bounty**: Up to $300,000
- **Scope**: V3 contracts (new architecture)
- **Audits**: ~1-2 on V3
- **Why GO**: New version = new code, existing V2 audits don't cover V3
- **Risk**: V2 was mature, but V3 is fresh
- **Pre-check**: Verify V3 scope is separate from V2

### BENQI
- **Bounty**: Up to $500,000
- **Scope**: Avalanche lending protocol
- **Audits**: ~2
- **Why GO**: Avalanche-specific, less competition than Ethereum L1
- **Risk**: Compound fork — check if original audit fixes applied
- **Pre-check**: Fork analysis required (check original C4/Sherlock findings)

---

## Tier 2: Moderate Priority (CONDITIONAL GO)

### Inverse Finance
- **Bounty**: Up to $100,000
- **Scope**: FiRM lending protocol
- **Audits**: ~2-3 (borderline)
- **Why CONDITIONAL**: Novel lending design (FiRM), but close to audit limit
- **Pre-check**: Count exact audits, check resolved reports

### Exactly Protocol
- **Bounty**: Up to $50,000
- **Scope**: Fixed/variable rate lending
- **Audits**: ~1-2
- **Why CONDITIONAL**: Lower bounty but less competition
- **Pre-check**: Verify LOC, check if Optimism deployment is in scope

### DeFi Saver
- **Bounty**: Up to $350,000
- **Scope**: DeFi automation (recipe system)
- **Audits**: ~2
- **Why CONDITIONAL**: Complex recipe/strategy system = larger attack surface
- **Risk**: Integration-heavy (Aave, Compound, Maker interactions)
- **Pre-check**: Verify which integrations are in scope

---

## Tier 3: Monitor (Not yet ready)

### Protocols with recent scope changes
- Monitor Immunefi announcements for new programs
- Newly listed protocols (< 1 month) have lowest competition
- Set WebSearch alert for "new immunefi program" weekly

---

## Evaluation Workflow
```
For each candidate:
1. target_evaluator Phase 0 (30 min max)
2. Check OOS exclusion list (v5 CapyFi lesson)
3. Check audit count (v5 hard NO-GO)
4. Check on-chain config (v6 Kiln lesson)
5. GO → Phase 0.5 tool scan
```

## Historical ROI Reference
| Hours Invested | Finding Rate | Revenue |
|---------------|-------------|---------|
| < 2 hours | 0% (too shallow) | $0 |
| 2-4 hours | ~5% (tool + Level 2) | Low |
| 4-8 hours | ~15% (deep Level 3-4) | Medium |
| 8+ hours | Diminishing returns | Watch time-box |

**Sweet spot**: 4-6 hours per target with tool-first gate.
