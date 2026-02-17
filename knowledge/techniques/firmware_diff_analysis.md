# Firmware Diff Analysis Technique

## Overview
Binary patch diffing for vulnerability variant discovery in embedded firmware.

## Pipeline
1. **Firmware extraction**: .chk → binwalk → UBI (ubi_reader) → SquashFS (unsquashfs) → rootfs
2. **Binary identification**: file, checksec, strings, md5sum on key binaries
3. **Function-level diff**: r2 batch `afl~[0,2,3]` on both versions → diff
4. **Strings diff**: `strings binary | sort` → diff → identify new/removed strings
5. **Decompile changed functions**: Ghidra MCP or r2 `pdd`/`pdf`
6. **Variant search**: Same pattern in unpatched functions/scripts

## Key Learnings (NETGEAR Orbi RBR750, 2026-02-17)
- **r2 batch mode is fast**: `r2 -q -e "bin.cache=true" -c "aaa; afl~[0,2,3]" binary`
- **Ghidra MCP can be slow on large binaries (2MB+)** — use r2 as backup
- **Shell scripts are gold mines**: nvram→system() chains often unpatched
- **Same function, multiple paths**: A patched HTTP CGI path may have unpatched SOAP path
- **"Incomplete patch" framing > "new vulnerability"** for Bugcrowd/H1 triagers
- **Strings diff reveals patch intent**: new strings (host_check, X-Forwarded-For) show what was fixed
- **PIE address rebase**: function addresses shift between versions; compare by size, not address
- **dhcp6c unchanged**: Sometimes the real fix is in httpd (config generator), not the daemon itself

## Tools Used
- binwalk, ubi_reader, unsquashfs (extraction)
- r2 batch mode (function listing, xrefs, decompilation)
- Ghidra MCP (decompilation of specific functions)
- bash grep/diff (shell script analysis, strings comparison)

## NETGEAR-Specific Patterns
- httpd = monolithic web server, all CGI handlers + SOAP dispatcher
- fnvram = NETGEAR nvram wrapper, used in shell scripts
- agApi_*.sh = firewall/network config scripts, common injection targets
- genie.cgi = setup wizard handler, often pre-auth
- SOAP port 5000 = UPnP service, may lack auth checks
- inbound_policy_tbl, fwpt*, http_rmport = nvram keys for firewall rules
