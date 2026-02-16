# Awesome Offensive MCP — New Servers for Terminator

Analysis of [awesome-offensive-mcp](https://github.com/R00T-Kim/awesome-offensive-mcp) repository. Identifies which MCP servers would enhance Terminator's CTF solving and bug bounty capabilities.

---

## Current Stack (Already Integrated)
- ✅ **mcp-gdb** — GDB debugging
- ✅ **radare2-mcp** — Binary disassembly/decompilation
- ✅ **pentest-mcp** — nmap, nikto, john, hashcat
- ✅ **frida-mcp** — Dynamic binary instrumentation
- ✅ **ghidra-mcp** — NSA decompiler (headless)
- ✅ **context7** — Documentation lookup
- ✅ **playwright** — Browser automation

---

## Recommended New Servers (Prioritized)

### PHASE 1: High Impact (Implement ASAP)

#### 1. **pwno-mcp** — GDB/pwndbg Integration
- **GitHub**: https://github.com/pwno-io/pwno-mcp
- **What**: pwndbg convenience functions (vmmap, checksec, ropper integration)
- **Why**: Reduces exploit dev boilerplate vs raw gdb
- **Impact**:
  - CTF pwn: leak automation, ROP gadget finding (⭐⭐⭐)
  - Bug Bounty: post-exploitation (⭐⭐)

#### 2. **Nuclei MCP** — Template-Based Web Scanning
- **GitHub**: https://github.com/addcontent/nuclei-mcp
- **What**: 10K+ community vulnerability templates for auto-matching CVE patterns
- **Why**: Faster than manual gobuster+nikto combo
- **Impact**:
  - CTF web: automatic CVE pattern matching (⭐⭐⭐)
  - Bug Bounty: rapid surface mapping (⭐⭐⭐)

#### 3. **Burp Suite MCP** — Web Application Scanner
- **GitHub**: https://github.com/PortSwigger/mcp-server
- **What**: Industry-standard scanner with SQLi, XXE, SSRF, crypto vulnerability detection
- **Why**: Gold standard for web security testing
- **Impact**:
  - CTF web: comprehensive vulnerability detection (⭐⭐⭐)
  - Bug Bounty: primary finding source (⭐⭐⭐)

#### 4. **codeql-mcp** — Variant Analysis
- **GitHub**: https://github.com/JordyZomer/codeql-mcp
- **What**: GitHub CodeQL queries for finding vulnerability variants
- **Why**: Once a CVE is found, auto-search similar patterns in codebase
- **Impact**:
  - CTF source: find similar bugs in different files (⭐⭐⭐)
  - Bug Bounty: reuse successful CVE pattern (⭐⭐⭐)
- **Integration note**: Pairs with `analyst` agent for variant hunting

---

### PHASE 2: Medium Priority (If Resources Available)

#### 5. **Slither MCP** — Solidity Smart Contract Analysis
- **GitHub**: https://github.com/trailofbits/slither-mcp
- **What**: 30+ vulnerability classes for blockchain/DeFi
- **Why**: Blockchain CTF/bounty increasingly common
- **Impact**:
  - CTF blockchain: Solidity challenges (⭐⭐)
  - Bug Bounty: Web3/DeFi protocols (⭐⭐⭐)

#### 6. **Greptile MCP** — Semantic Code Search
- **GitHub**: https://github.com/greptileai/greptile-vscode
- **What**: LLM-powered code search vs regex grep
- **Why**: Faster vulnerability discovery in large codebases
- **Impact**:
  - CTF source: find vulnerable function quickly (⭐⭐)
  - Bug Bounty: monorepo analysis (⭐⭐⭐)

#### 7. **GitHub MCP Server** — GitHub API Integration
- **GitHub**: https://github.com/github/github-mcp-server
- **What**: Full API for secret scanning, repo analysis
- **Why**: Find similar vulns in other public repos
- **Impact**:
  - CTF/Bounty: variant hunting across GitHub (⭐⭐)

---

### PHASE 3: Specialized Domains (Optional)

#### 8. **IDA Pro MCP** — Premium RE
- **GitHub**: https://github.com/mrexodia/ida-pro-mcp
- **What**: IDA signatures, FLIRT, type recovery (requires IDA Pro license)
- **Why**: More powerful than r2/Ghidra for obfuscated binaries
- **Impact**:
  - CTF reversing: complex obfuscation (⭐⭐⭐)
  - Bug Bounty: binary backend analysis (⭐)
- **Cost**: IDA Pro license required (~$900-$5000)

#### 9. **Binary Ninja MCP** — Fast RE
- **GitHub**: https://github.com/MCPPhalanx/binaryninja-mcp
- **What**: Lightweight decompiler, good for MIPS/ARM/exotic architectures
- **Why**: Alternative to r2/Ghidra for non-x86
- **Impact**:
  - CTF reversing: MIPS/ARM challenges (⭐⭐)
  - Bug Bounty: firmware analysis (⭐⭐)

#### 10. **Metasploit MCP** — Exploit Automation
- **GitHub**: https://github.com/GH05TCREW/MetasploitMCP
- **What**: Control Metasploit modules, pre-built exploits
- **Why**: Faster than writing PoC from scratch for known CVEs
- **Impact**:
  - CTF pwn: known vulns (format string, ROP) (⭐⭐)
  - Bug Bounty: automate exploitation (⭐)

#### 11. **BloodHound MCP AI** — Active Directory Attacks
- **GitHub**: https://github.com/MorDavid/BloodHound-MCP-AI
- **What**: AD attack path visualization and analysis
- **Why**: Enterprise bounties with Windows AD
- **Impact**:
  - CTF AD: privilege escalation paths (⭐⭐)
  - Bug Bounty: enterprise networks (⭐⭐)

#### 12. **WinDBG EXT MCP** — Windows Kernel Debugging
- **GitHub**: https://github.com/NadavLor/windbg-ext-mcp
- **What**: Kernel debugger for crash dump analysis
- **Why**: Windows driver/kernel challenges
- **Impact**:
  - CTF Windows RE: driver reversing (⭐)
  - Bug Bounty: kernel exploits (⭐)

---

## Skip List (Not Valuable for Terminator)

❌ **Shodan/ZoomEye/AlienVault OTX** — OSINT only (not tactical)
❌ **Volatility MCP** — Forensics only (not CTF/bounty focused)
❌ **Terraform/Kubernetes/AWS MCP** — Infrastructure scanning (not exploitation)
❌ **VirusTotal MCP** — Malware reputation (limited value for CTF/bounty)
❌ **Database MCPs** (PostgreSQL, MySQL, MongoDB) — Only if CTF includes DB challenges; not universal

---

## Summary Table

| MCP | GitHub URL | Category | CTF | Bounty | Priority |
|-----|-----------|----------|-----|--------|----------|
| pwno-mcp | pwno-io/pwno-mcp | Exploit Dev | ⭐⭐⭐ | ⭐⭐ | **P1** |
| Nuclei MCP | addcontent/nuclei-mcp | Web Scanning | ⭐⭐⭐ | ⭐⭐⭐ | **P1** |
| Burp Suite MCP | PortSwigger/mcp-server | Web Vuln | ⭐⭐⭐ | ⭐⭐⭐ | **P1** |
| codeql-mcp | JordyZomer/codeql-mcp | Variant Analysis | ⭐⭐⭐ | ⭐⭐⭐ | **P1** |
| Slither MCP | trailofbits/slither-mcp | Smart Contracts | ⭐⭐ | ⭐⭐⭐ | **P2** |
| Greptile MCP | greptileai/greptile-vscode | Code Search | ⭐⭐ | ⭐⭐⭐ | **P2** |
| GitHub MCP | github/github-mcp-server | Variant Hunt | ⭐⭐ | ⭐⭐ | **P2** |
| IDA Pro MCP | mrexodia/ida-pro-mcp | RE Premium | ⭐⭐⭐ | ⭐ | **P3** |
| Binary Ninja MCP | MCPPhalanx/binaryninja-mcp | RE Fast | ⭐⭐ | ⭐⭐ | **P3** |
| Metasploit MCP | GH05TCREW/MetasploitMCP | Exploit DB | ⭐⭐ | ⭐ | **P3** |
| BloodHound MCP | MorDavid/BloodHound-MCP-AI | AD Attacks | ⭐⭐ | ⭐⭐ | **P3** |
| WinDBG EXT MCP | NadavLor/windbg-ext-mcp | Windows Debug | ⭐ | ⭐ | **P3** |

---

## Implementation Roadmap

| Phase | Server | Timeline | Effort | ROI |
|-------|--------|----------|--------|-----|
| **P1** | pwno-mcp | Week 1 | Low | High |
| **P1** | Nuclei MCP | Week 1 | Low | High |
| **P1** | Burp Suite MCP | Week 2 | Medium | High |
| **P1** | codeql-mcp | Week 2 | Medium | High |
| **P2** | Slither MCP | Week 3 | Low | Medium |
| **P2** | Greptile MCP | Week 3 | Low | High |
| **P2** | GitHub MCP | Week 4 | Low | Medium |
| **P3** | IDA Pro MCP | TBD | High | Medium |
| **P3** | Binary Ninja MCP | TBD | Medium | Medium |
| **P3** | Metasploit MCP | TBD | Low | Low |
| **P3** | BloodHound MCP | TBD | Medium | Medium |

---

## Key Statistics

- **Total MCP servers in awesome-offensive-mcp**: 40+
- **Recommended for Terminator**: 12 new servers
- **New capabilities unlocked**:
  - Web exploitation (Nuclei, Burp Suite)
  - Variant analysis (codeql, GitHub MCP)
  - Blockchain (Slither)
  - Premium RE (IDA, Binary Ninja)
  - Exploit automation (Metasploit)

---

*Analysis Date: 2026-02-15*
*Source: https://github.com/R00T-Kim/awesome-offensive-mcp*
