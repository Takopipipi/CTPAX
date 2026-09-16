# Ghidra MCP - reverse engineering from OpenCode, Cursor, Claude Code, Codex

MCP-server that gives the agent Ghidra (decompiler, disassembler, auto-analysis),
deep PE inspection, full x64dbg automation (the model drives the debugger itself),
Cheat Engine-style memory scanning, server-response forgery (mock HTTPS server, TCP
proxy with byte rewriting, hosts redirection, JWT re-signing), GUI automation,
anti-debug/anti-VM reconnaissance, live PEB inspection, DLL injection, registry
snapshots with diffing, source-level recovery for managed code (Java via CFR, .NET
via dnfile), PDB symbol downloads from the Microsoft symbol server, crypto-constant
localization inside Ghidra programs, hardware breakpoints, TitanHide anti-anti-debug,
static binary analysis without Ghidra, crypto utilities, license-gate auto-discovery with
paste-ready patch suggestions, cross-build function mapping and PE diffing, Unity Il2Cpp
metadata dumps, in-process exception logging without a debugger, minidump forensics,
Metasploit, Wireshark (tshark/dumpcap) traffic analysis, and Nuclei vulnerability
scanning. 250 tools.

Key idea: analysis **persists**. A binary is imported into a Ghidra project under a name
derived from its SHA-256, so re-opening the same file is instant, and all renames,
comments, and types from a previous session remain in place.

## Installation

### CTPAX.bat - the one-shot installer

Double-click `CTPAX.bat` (source) or `CTPAX-Setup.exe` (the release build; no Python
needed on the target machine). It **asks Windows for administrator rights by itself**
(UAC), prints the banner, scans the fixed drives, picks the one with the most free
space, copies the whole project into `<drive>:\CTPAX`, then installs everything with a
live console progress bar - and it never asks you for paths: missing prerequisites are
downloaded into the toolkit folder automatically:

- **Ghidra** (latest release, ~540MB) -> `<drive>:\CTPAX\ghidra`
- **JDK 21** (Eclipse Temurin, ~200MB) -> `<drive>:\CTPAX\jdk`
- **x64dbg** (latest snapshot) -> `<drive>:\CTPAX\x64dbg`, plus the automation plugin and ScyllaHide
- **Nuclei** + its ~13k template repo, **Wireshark** CLI tools (winget)
- venv + Python dependencies for the server itself

At the end it registers the MCP server into every AI client it finds on the machine:
OpenCode, Cursor, Claude Code, Codex. Re-running is safe - it updates in place.

```
CTPAX.bat                 <- install into the biggest drive, register all detected clients
CTPAX.bat --check         <- show the plan (drives + target paths), install nothing
CTPAX.bat --engine-only   <- self-test: lay the sources down and load the engine, stop
CTPAX.bat --offline       <- skip all downloads
```

### install.bat - the classic path

```
install.bat
```

The script finds Ghidra and JDK 21+, creates a separate venv in `%LOCALAPPDATA%\GhidraMCP`,
installs dependencies, copies the server there, **starts it and verifies via its own
`doctor`** -- and only after successful verification registers it in `opencode.jsonc`.
Comments and formatting of your config are preserved; a timestamped backup is placed next
to it.

To register other clients, add `--cursor`, `--claude`, `--codex` (or `--all-clients` to
auto-detect and register each one found):

```
install.bat --all-clients
```

- Cursor: writes `mcpServers.ghidra` into the global `~/.cursor/mcp.json`
- Claude Code: writes `mcpServers.ghidra` into `~/.claude.json` (user scope)
- Codex: writes the `[mcp_servers.ghidra]` block into `~/.codex/config.toml`

Then restart the clients.

If something was not found automatically:

```
check.bat                                     just verify the environment
install.bat --ghidra "D:\ghidra_11.3_PUBLIC"
install.bat --java "C:\Program Files\Java\jdk-21"
install.bat --home "C:\Tools\GhidraMCP"       different install location
install.bat --heap 8G                         more JVM memory for large binaries
install.bat --cursor                          also register in Cursor
uninstall.bat                                 remove (will ask about projects separately)
uninstall.bat --cursor                        also remove the Cursor entry
```

Requirements: Python 3.10+, unpacked Ghidra 11+, JDK 21+ (JDK, not JRE -- need `jvm.dll`).
Ghidra: https://ghidra-sre.org, JDK: https://adoptium.net.

### One path limitation

JPype cannot start the JVM if any directory in the path to the Python interpreter ends with
`!`: a classpath element gets interpreted as a path inside a JAR archive. The installer
checks this up front and suggests `--home`. The sources themselves can live anywhere -- the
server runs from a copy in `%LOCALAPPDATA%\GhidraMCP`.

## How to use

Just ask in plain English, the agent picks the tools:

```
analyze E:\sample.exe -- what is it and how is it packed
find the license check in it and show the decompilation
this string gets decrypted -- find the key
patch the always-success check and save the patched file
find AES in the binary and show how the key is initialized
```

Typical workflow the agent follows:

1. **Quick scan** -- `file_info`, `detect_packing`, `file_strings`, `entropy_map`. Seconds,
   often enough by itself.
2. **Full Ghidra import** -- `open_binary` + `analyze` + `functions` + `decompile`. 10-30s
   on first pass; subsequent opens are instant.
3. **Code search** -- `functions` + `function_info` + `xrefs` + `decompile` (or
   `decompile_search` by regex/identifier). The agent finds the entry point and follows it.
4. **Patching** -- `patch` + `assemble` + `save`. Like a hex patcher but from a command.

## Tools (69 total)

### Ghidra: full API access

The typed tools (45 worker operations: programs, code, data, edits) cover the daily
workflow, and two tools unlock the remaining 100% of Ghidra's Java API:
`ghidra_eval_python` runs arbitrary Python inside the live Ghidra worker with
`currentProgram`, a ready decompiler, FlatProgramAPI, and JPype imports in scope --
bulk analysis passes, decompiler internals, anything. `ghidra_api_explore` is the
discovery half: search Ghidra's classes by regex, list any class's methods with
signatures from the live JVM, so the model looks up the exact call before running it.

### Program operations

| Category | Tools |
|---|---|
| Programs | `open_binary`, `list_programs`, `program_info`, `memory_blocks`, `entry_points`, `imports`, `exports`, `relocations` |
| Code | `functions`, `function_info`, `decompile`, `decompile_many`, `disassemble`, `xrefs`, `callgraph`, `decompile_search`, `pcode`, `list_symbols`, `list_strings` |
| Data | `read_memory`, `search_memory`, `data_at`, `data_types`, `list_labels` |
| Edits | `rename`, `set_comment`, `set_function_comment`, `set_signature`, `set_variable`, `apply_type`, `create_function`, `force_disassemble`, `assemble_preview`, `patch`, `bookmark`, `list_bookmarks`, `clear_code`, `run_ghidra_script` |

### Static analysis (8) -- no Ghidra needed, milliseconds

`file_info`, `detect_packing`, `entropy_map`, `file_strings`, `hexdump`, `find_bytes_in_file`,
`disassemble_bytes`, `yara_scan`.

### Crypto utilities (8)

`crypto_identify` (spot hidden constants in binaries -- AES S-box, ChaCha, RSA, RC4 ...),
`crypto_decode` (Base64/Hex/URL/...), `crypto_encode`, `crypto_xor` (+ brute-force),
`crypto_symmetric` (AES/DES/ChaCha/RC4), `crypto_classic` (Caesar/Vigenere/Atbash),
`crypto_hash`, `crypto_score` (rate likelihood of plaintext).

### PE inspection (10) -- pefile, no Ghidra needed

`pe_headers`, `pe_sections`, `pe_imports`, `pe_exports`, `pe_resources` (with extraction),
`pe_tls` (callback addresses), `pe_relocations`, `pe_overlay` (with extraction),
`pe_certificates`, `pe_heuristics` (suspicious-trait score and verdict).

### Dynamic analysis (15) -- debuggers, hardware breakpoints, anti-anti-debug

`debugger_environment` (what is installed: cdb, x64dbg, TitanHide), `debug_privilege_enable`,
`dbg_run` / `dbg_attach` (batch cdb/WinDbg commands against a target or a live PID),
`x64dbg_script` (generate script files for the Script tab), `x64dbg_launch`,
`hwbp_set` / `hwbp_list` / `hwbp_clear` (debug registers DR0-DR3 via SetThreadContext),
`stealth_hide_threads` (ThreadHideFromDebugger from usermode: no driver, no Secure Boot),
`titanhide_status` / `titanhide_hide` / `titanhide_unhide` (kernel-level anti-anti-debug
via IOCTL to \\.\\TitanHide), `kernel_debug_info` (bcdedit: kernel debug, test signing),
`drivers_list`.

Elevation is required for most dynamic tools, and cdb/x64dbg/TitanHide must be installed
separately -- every failing tool names exactly what is missing and how to get it.
ScyllaHide (usermode anti-anti-debug x64dbg plugin) is installed automatically and needs
no BIOS changes; TitanHide requires Secure Boot off + test signing, which is a BIOS-level
trade-off no script can bypass.

### Live x64dbg sessions (22) -- the model operates the debugger

Driven through the x64dbg-automate plugin (the installer fetches it from GitHub releases
automatically):

`xdbg_start` / `xdbg_attach` / `xdbg_stop` (session lifecycle; one debuggee at a time),
`xdbg_status`. Execution: `xdbg_bp_set` / `xdbg_bp_clear` / `xdbg_bp_list` (software and
hardware breakpoints), `xdbg_go` (with wait-for-next-stop), `xdbg_wait_stopped`,
`xdbg_pause`, `xdbg_stepi`, `xdbg_stepo`, `xdbg_skip` (advance rip without executing).
Inspection and patching: `xdbg_regs`, `xdbg_set_reg`, `xdbg_mem_read`, `xdbg_mem_write`,
`xdbg_disassemble`, `xdbg_assemble`, `xdbg_memmap`. Escape hatches: `xdbg_cmd` (any
x64dbg command), `xdbg_eval` (expression evaluation: symbols, `mod.base`, arithmetic).

A typical model-driven session: `xdbg_start` -> `xdbg_bp_set kernel32.CreateProcessW` ->
`xdbg_go(wait_stop_timeout=15)` -> `xdbg_regs` -> `xdbg_mem_read`/`xdbg_disassemble` ->
`xdbg_stepi` -> `xdbg_assemble`/`xdbg_mem_write` patch -> `xdbg_stop`.

### System and memory (15) -- Cheat Engine workflow, no debugger needed

`proc_list` / `proc_start` / `proc_kill` / `proc_modules` (base addresses for patches),
`window_list` / `window_send_text` / `window_close`,
`mem_scan` (scan, change the value in the target, rescan with `previous_file` until the
address list narrows to one), `mem_read_proc` / `mem_write_proc` (ReadProcessMemory /
WriteProcessMemory, code pages flipped writable automatically), `mem_strings_proc`
(live-memory strings with addresses), `reg_read` / `reg_write` / `reg_delete_value` /
`reg_enum_keys` (license state, trial flags), `netstat` (endpoints per pid).

### Requests and tokens (8) -- forgery and interception

`http_request` (any method, exact headers, no redirects followed, TLS verify optional),
`tcp_send` / `udp_send` (raw protocol replay), `dns_resolve`, `proxy_get` / `proxy_set`
(point WinINET apps at Burp/Fiddler and back), `jwt_decode` / `jwt_forge`
(HS256/384/512 re-signing, `alg:none` attack, weak-secret candidate testing).

### Server-response forgery (17) -- the target answers to *you*

`net_mock_start` / `net_mock_stop` / `net_mock_route` / `net_mock_routes` /
`net_mock_requests` (a real HTTP(S) server serving your answers: regex routes, binary
bodies, latency simulation, and a full log of what the target actually asked for),
`net_mock_certificate` (self-signed cert for HTTPS forgery + the certutil trust
command), `net_hosts_add` / `net_hosts_remove` / `net_hosts_list` (point the target's
api.vendor.com at your mock), `tcp_proxy_start` / `tcp_proxy_stop` / `tcp_proxy_rule` /
`tcp_proxy_traffic` (transparent logging proxy for non-HTTP protocols, with in-flight
byte rewriting - forge responses to protocols there is no schema for).

### GUI automation and file patching (7)

`input_click` / `input_type` / `input_key` (SendInput: real mouse and keyboard, works
on dialogs that ignore messages), `window_focus` / `window_rect` (coordinates for the
clicks), `file_patch` (in-place binary crack with .bak backup), `file_diff` (what did
the crack change, byte for byte).

### Reconnaissance and state hunting (12)

`triage` (one-shot static report: identity, packing, anti-debug map, verdict, next
steps), `antidebug_scan` (IsDebuggerPresent-family imports with what each check means,
VM/packer fingerprints, analyst-tool strings, ScyllaHide profile hint),
`peb_info` (live BeingDebugged / NtGlobalFlag / heap flags / real command line),
`dll_inject` / `dll_eject` (LoadLibraryW remote-thread instrumentation),
`reg_snapshot` / `reg_snapshot_diff` (activate the trial, diff, read exactly which keys
hold the license state), `file_watch_start` / `file_watch_read` / `file_watch_stop`
(same for files), `clipboard_get` / `clipboard_set`.

### Source-level recovery (6) -- managed code and symbols

`decompile_java` (CFR decompiler, auto-downloaded once: jars come back as per-class
.java sources with control flow, generics, and lambdas reconstructed),
`dotnet_inspect` / `dotnet_il` (type/method tables and user strings via dnfile, IL via
dncil -- the skeleton of the original C#; pair with de4dot/ILSpy for full source),
`pdb_path_from_binary` / `pdb_download` (read the RSDS debug directory, build the
symbol-server key, fetch the PDB from Microsoft -- after it sits next to the binary,
Ghidra names every function automatically),
`find_crypto_constants` (locate AES S-boxes, SHA/MD5 tables, ChaCha sigma, ASN.1 OIDs
inside the open Ghidra program and name the functions that hold them).

### Persistent cdb session (7) -- one attach, many batches

`dbg_session_start` / `dbg_session_attach` (the target is verified to exist BEFORE
anything spawns; a failed attach touches nothing -- this fixes the batch-mode bug
where a dead-PID attempt harmed a live process), `dbg_session_command`,
`dbg_session_batch` (multi-step flows: bp, g, dump, g -- per-command structured
output, session survives), `dbg_smart_breakpoint` (bp + run-to-hit + memory dumps +
continue in one call), `dbg_session_status` / `dbg_session_stop`.

### Process I/O and lifecycle (4)

`proc_start(capture=True)` keeps stdin/stdout: `proc_write` feeds prompts,
`proc_read` reads answers -- interactive crackmes run end to end. `proc_alive` /
`proc_wait_exit` track a pid without proc_list filtering.

### Session / management (~9)

`doctor`, `worker_status`/`worker_stop`/`worker_restart`, `worker_logs` -- control the
Ghidra subprocess. `job_start`/`job_status`/`job_list`/`job_cancel` -- background tasks.
`note_list` (text or regex search across every binary) / `note_add` / `note_export`
(markdown dump) -- findings persist per file hash between sessions.

## Tests

```
tests\run_tests.bat
```

- `tests\test_unit.py` -- 24 offline tests (crypto round-trips, JWT forge/weak-secret,
  notebook regex/export, PE parsing on a system binary, mock routing with query params,
  file patch disambiguation). Seconds, no server.
- `tests\test_e2e.py` -- 30 checks over the real MCP stdio protocol: registry count,
  doctor, crypto, PE/triage, interactive process I/O (proc_write/proc_read echo),
  proc_wait_exit codes, mem_scan narrow-roundtrip, mock server forgery + query routing,
  live cdb session (start/lm/conditional bp/dump/stop), and a full Ghidra flow
  (open/section-filtered functions/decompile/multi-target xrefs/crypto constants/eval).

## Architecture

```
OpenCode (stdio) --- MCP server (Python) --- Worker subprocess
                                                     |
                                                     +--- JVM (JPype -> pyghidra)
```

- MCP server is fast, never blocks on JVM. Accepts requests, queues them.
- Worker starts lazily on first `open_binary`; the imported binary is stored in a Ghidra
  project on disk. Multiple projects are open in parallel.
- Sessions -- each binary is stored in projects/ by SHA-256; filenames and project names
  are capped at 64 characters, nothing breaks.
- Static and crypto work independently of Ghidra: you can use them while Ghidra is still
  starting or not installed at all (everything except open_binary/decompile/... works).
