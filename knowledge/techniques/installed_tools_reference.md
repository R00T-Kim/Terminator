# Installed Bug Bounty & Security Tools Reference

**Updated**: 2026-02-15

## PATH Setup (every new shell)
```bash
export GOPATH=$HOME/gopath
export PATH=$HOME/go/bin:$GOPATH/bin:$HOME/.local/bin:$HOME/tools/mitmproxy:$HOME/tools/codeql:$PATH
```
Add to `~/.bashrc` as needed. New Bash tool calls need explicit PATH or absolute paths.

---

## Go-based Tools (`~/gopath/bin/`)

| Tool | Version | Command | Purpose |
|------|---------|---------|---------|
| **ffuf** | 2.1.0-dev | `~/gopath/bin/ffuf` | Web fuzzer (dirs, params, vhosts) |
| **nuclei** | 3.7.0 | `~/gopath/bin/nuclei` | Vulnerability scanner (template-based) |
| **subfinder** | 2.12.0 | `~/gopath/bin/subfinder` | Subdomain discovery (passive) |
| **katana** | 1.4.0 | `~/gopath/bin/katana` | Web crawler/spider |
| **httpx** | 1.8.1 | `~/gopath/bin/httpx` | HTTP toolkit (probe, tech detect) |
| **naabu** | latest | `~/gopath/bin/naabu` | Port scanner (needs libpcap) |
| **dalfox** | 2.12.0 | `~/gopath/bin/dalfox` | XSS scanner |
| **gau** | latest | `~/gopath/bin/gau` | Get All URLs (Wayback+OTX+CC) |
| **waybackurls** | latest | `~/gopath/bin/waybackurls` | Wayback Machine URL fetcher |
| **interactsh-client** | 1.3.0 | `~/gopath/bin/interactsh-client` | OOB interaction server (SSRF/blind tests) |
| **gh** | 2.45.0 | `/usr/bin/gh` | GitHub CLI (PRs, issues, API) |

### Quick Usage
```bash
# Subdomain enumeration
~/gopath/bin/subfinder -d target.com -o subs.txt

# Probe live hosts
cat subs.txt | ~/gopath/bin/httpx -o live.txt

# Port scan
~/gopath/bin/naabu -host target.com -p 1-10000

# Directory fuzzing
~/gopath/bin/ffuf -u https://target.com/FUZZ -w ~/SecLists/Discovery/Web-Content/common.txt

# Vulnerability scan
~/gopath/bin/nuclei -u https://target.com -t ~/nuclei-templates/

# Web crawling
~/gopath/bin/katana -u https://target.com -d 3

# XSS scanning
~/gopath/bin/dalfox url https://target.com/search?q=test

# URL collection
echo "target.com" | ~/gopath/bin/gau --o urls.txt
echo "target.com" | ~/gopath/bin/waybackurls > wayback.txt

# OOB interaction server (SSRF/blind testing)
~/gopath/bin/interactsh-client
```

---

## Python-based Tools (`~/.local/bin/` or `~/miniconda3/bin/`)

| Tool | Command | Purpose |
|------|---------|---------|
| **arjun** | `arjun` | HTTP parameter discovery |
| **dirsearch** | `dirsearch` | Directory/file bruteforcer |
| **trufflehog** | `~/gopath/bin/trufflehog` | Secret/credential scanner (v3.93.3, 800+ types, validation) |
| **commix** | `python3 ~/commix/commix.py` | Command injection exploitation |
| **SSRFmap** | `python3 ~/SSRFmap/ssrfmap.py` | SSRF exploitation (18+ modules: AWS, Redis, FastCGI) |
| **sqlmap** | `/usr/bin/sqlmap` | SQL injection automation |
| **mitmproxy** | `~/tools/mitmproxy/mitmproxy` | HTTP(S) intercept proxy (v12.2.1) |
| **fuxploider** | `python3 ~/fuxploider/fuxploider.py` | File upload vulnerability scanner/exploiter |
| **codeql** | `~/tools/codeql/codeql` | Semantic code analysis (variant hunting, taint tracking) |

### Quick Usage
```bash
# Parameter discovery
arjun -u https://target.com/api/endpoint

# Directory bruteforce
dirsearch -u https://target.com -w ~/SecLists/Discovery/Web-Content/common.txt

# Secret scanning in git repo (verified secrets only)
~/gopath/bin/trufflehog git https://github.com/org/repo --only-verified
~/gopath/bin/trufflehog git file://. --only-verified  # local repo

# Command injection
python3 ~/commix/commix.py -u "https://target.com/api?cmd=test"

# SSRF exploitation (18+ modules)
python3 ~/SSRFmap/ssrfmap.py -r request.txt -p url -m readfiles  # read local files
python3 ~/SSRFmap/ssrfmap.py -r request.txt -p url -m aws  # AWS metadata

# SQL injection
sqlmap -u "https://target.com/api?id=1" --batch

# HTTP proxy
~/tools/mitmproxy/mitmproxy -p 8080
~/tools/mitmproxy/mitmdump -p 8080 -w dump.flow  # headless
```

---

## Payload & CVE Reference Databases

| Collection | Path | Size | Purpose |
|-----------|------|------|---------|
| **PayloadsAllTheThings** | `~/PayloadsAllTheThings/` | 22 MB | 70+ vuln category payloads (SQLi, XSS, SSRF, XXE, etc.) |
| **trickest-cve** | `~/trickest-cve/` | 745 MB | 154K+ CVE PoC files (1999-2026, auto-updated) |
| **ExploitDB** | `~/exploitdb/` | — | 47K+ exploits (`searchsploit <query>`) |
| **PoC-in-GitHub** | `~/PoC-in-GitHub/` | — | 8K+ GitHub PoC references |
| **corkami/collisions** | `~/collisions/` | 97 MB | Hash collision techniques (MD5, SHA-1 — crypto CTF reference) |

### Quick Usage
```bash
# PayloadsAllTheThings — grab payloads for specific vuln type
cat ~/PayloadsAllTheThings/"SQL Injection"/README.md | head -100
cat ~/PayloadsAllTheThings/"SSRF"/README.md | head -100
ls ~/PayloadsAllTheThings/  # list all 70+ categories

# trickest-cve — find CVE PoCs
ls ~/trickest-cve/2025/ | grep -i <keyword>
cat ~/trickest-cve/2025/CVE-2025-NNNNN.md  # CVE details + PoC links

# ExploitDB
~/exploitdb/searchsploit <service> <version>

# PoC-in-GitHub
ls ~/PoC-in-GitHub/2025/ | grep -i <keyword>
```

---

## Wordlists

| Collection | Path | Size |
|-----------|------|------|
| **SecLists** | `~/SecLists/` | 2.5 GB |

Key wordlists:
- `~/SecLists/Discovery/Web-Content/common.txt` — general web dirs
- `~/SecLists/Discovery/Web-Content/raft-large-directories.txt` — large dir list
- `~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` — subdomain list
- `~/SecLists/Fuzzing/` — fuzzing payloads
- `~/SecLists/Passwords/` — password lists
- `~/SecLists/Payloads/` — injection payloads

---

## Nuclei Custom Template (에이전트가 직접 작성 가능)

```yaml
# ~/custom-templates/my-vuln.yaml
id: custom-ssrf-check
info:
  name: Custom SSRF Detection
  author: terminator
  severity: high
  tags: ssrf,custom

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/fetch?url=http://169.254.169.254/latest/meta-data/"
    matchers:
      - type: word
        words:
          - "ami-id"
          - "instance-id"
        condition: or
```

```bash
# 커스텀 템플릿 실행
nuclei -u https://target.com -t ~/custom-templates/ -jsonl-export results.jsonl
```

---

## Pre-existing Tools (from CTF setup)

| Tool | Purpose |
|------|---------|
| **pwntools** | Exploit development framework |
| **gdb** + pwndbg + GEF | Binary debugging (GEF: `source ~/gef/gef.py`, 93 commands) |
| **r2** (radare2) | Disassembly/decompilation |
| **angr** | Symbolic execution |
| **z3-solver** | SMT solver |
| **ROPgadget/ropper** | ROP gadget finders |
| **one_gadget** | One-shot execve gadget finder |
| **ghidra** (MCP) | Decompilation |
| **frida** (MCP) | Dynamic instrumentation |
| **jadx** | APK/DEX decompiler |
| **searchsploit** | ExploitDB search (`~/exploitdb/`) |
| **seccomp-tools** | Seccomp filter analysis |

---

## MCP Servers (Claude Code integrations)

| MCP | Tools | Purpose |
|-----|-------|---------|
| **mcp-gdb** | gdb_start, gdb_command, etc. | GDB debugging |
| **radare2-mcp** | open_file, decompile, etc. | Binary analysis |
| **pentest-mcp** | nmapScan, gobuster, nikto, john, hashcat | Network/web pentesting |
| **frida-mcp** | attach, hook, execute_in_session | Dynamic instrumentation |
| **ghidra-mcp** | list_functions, get_pseudocode | Decompilation |
| **context7** | resolve-library-id, query-docs | Documentation lookup |
| **playwright** | browser automation | Web app testing |

---

## GDB Enhanced Features (GEF)

GEF provides 93 additional GDB commands for exploit development:
```bash
# Load GEF (instead of default pwndbg)
gdb -q -ex "source ~/gef/gef.py" ./binary

# Key GEF commands:
# checksec          — binary protections
# vmmap             — memory layout
# heap chunks       — heap state visualization
# pattern create/search — cyclic pattern for offset finding
# rop               — ROP gadget search
# format-string-helper — format string offset finder
# got               — GOT table display
# canary            — stack canary leak helper
# shellcode         — shellcode generator
# xinfo <addr>      — what section/mapping an address belongs to
```
**Note**: GEF and pwndbg cannot load simultaneously. Use `source ~/gef/gef.py` when GEF features needed, default GDB loads pwndbg.

---

## CodeQL (Semantic Code Analysis)

```bash
# Create database from source
~/tools/codeql/codeql database create /tmp/codeql-db --language=javascript --source-root=./src

# Run security queries
~/tools/codeql/codeql database analyze /tmp/codeql-db ~/tools/codeql/qlpacks/codeql/javascript-queries --format=sarif-latest --output=results.sarif

# Run specific query
~/tools/codeql/codeql query run path/to/query.ql --database=/tmp/codeql-db
```

---

## File Upload Exploitation (Fuxploider)

```bash
# Scan for file upload vulnerabilities
python3 ~/fuxploider/fuxploider.py -u https://target.com/upload

# With custom extensions
python3 ~/fuxploider/fuxploider.py -u https://target.com/upload -e php,phtml,php5,phar
```

---

## Web3 / Smart Contract Tools

| Tool | Version | Command | Purpose |
|------|---------|---------|---------|
| **Foundry (forge)** | 1.5.1 | `~/.foundry/bin/forge` | Solidity test framework, build, deploy |
| **Foundry (cast)** | 1.5.1 | `~/.foundry/bin/cast` | Ethereum RPC CLI (call, send, decode, abi) |
| **Foundry (anvil)** | 1.5.1 | `~/.foundry/bin/anvil` | Local Ethereum node (fork mainnet) |
| **Foundry (chisel)** | 1.5.1 | `~/.foundry/bin/chisel` | Solidity REPL |
| **Slither** | latest | `~/.local/bin/slither` (pipx) | Solidity static analyzer (100+ detectors) |
| **Mythril** | latest | `~/.local/bin/myth` (pipx) | EVM bytecode symbolic execution |
| **cargo-audit** | 0.22.1 | `cargo audit` | Rust dependency vulnerability scanner (RUSTSEC DB) |
| **cargo-fuzz** | 0.13.1 | `cargo fuzz` | Rust libFuzzer integration (coverage-guided) |

### Quick Usage
```bash
# Foundry PATH (add to shell if needed)
export PATH=$HOME/.foundry/bin:$PATH

# Solidity compilation + test
forge build
forge test -vvv

# Static analysis (Slither)
slither . --detect reentrancy-eth,arbitrary-send-eth

# Symbolic execution (Mythril)
myth analyze contracts/Vulnerable.sol --execution-timeout 300

# Rust dependency audit
cd /path/to/rust-project && cargo audit

# Rust fuzz target
cargo fuzz init
cargo fuzz run <target> -- -max_total_time=300

# Anvil local fork
anvil --fork-url https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY

# Cast: read contract
cast call 0xContractAddr "balanceOf(address)" 0xUserAddr --rpc-url http://localhost:8545
```

### Slither Detectors (Bug Bounty 우선순위)
```bash
# Critical: 재진입, 임의 전송, selfdestruct
slither . --detect reentrancy-eth,reentrancy-no-eth,arbitrary-send-eth,suicidal

# High: 접근제어, 오라클 조작
slither . --detect unprotected-upgrade,controlled-delegatecall,tx-origin

# All detectors list
slither . --list-detectors
```

### Mythril Analysis Modes
```bash
# Quick scan (1-2min)
myth analyze contracts/Target.sol --execution-timeout 120

# Deep scan (10min+)
myth analyze contracts/Target.sol --execution-timeout 600 --max-depth 50

# From bytecode (on-chain)
myth analyze -a 0xContractAddress --rpc infura_url
```

## Needs sudo

nmap, ltrace, checksec, nikto, pwndbg, MobSF(docker), naabu(libpcap)
