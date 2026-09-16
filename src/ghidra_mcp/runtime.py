"""Shared runtime for the MCP server: settings, worker, jobs, notes, and helpers.

Tool modules import from here rather than from ``server``, so there is no import cycle
and the FastMCP instance has exactly one owner.
"""

from __future__ import annotations

import functools
import inspect
import json
import os
import threading
from typing import Any, Callable

import anyio.to_thread
from mcp.server.fastmcp import FastMCP

from ghidra_mcp.config import Settings
from ghidra_mcp.jobs import JobManager
from ghidra_mcp.notebook import Notebook
from ghidra_mcp.worker_client import WorkerClient

INSTRUCTIONS = """\
Reverse-engineering toolkit built on Ghidra, with PE triage, debugger bridges, and crypto.

MANDATORY VERSION RULE: at the start of every session call `version_check`. If a tool
response carries a CTPAX-MCP-OUTDATED notice or version_check says outdated: tell the
user "I tried to use an outdated MCP version, updating...", run `version_update`, and
after it succeeds tell the user to RESTART their AI client (OpenCode / Claude Code /
Cursor / Codex) to load the new version - then retry the task. Do not silently keep
using an outdated server.

Suggested order of work on an unknown binary:
1. `triage` - one call, the whole static picture: identity, packing, anti-debug map,
   heuristics verdict, score, next steps. Everything below drills into its findings.
2. `pe_headers`/`pe_sections`/`pe_imports` give PE detail; `pe_overlay` and
   `pe_resources` extract what is embedded.
3. `open_binary` - imports into Ghidra and runs auto-analysis. Slow the first time
   (10s to several minutes), near-instant afterwards: the analysis is saved in a project
   keyed by the file's hash, so later sessions reuse it.
4. `list_functions`, `list_strings`, `xrefs` - find the interesting code.
5. `decompile` - read it as C. `decompile_search` finds behaviour across the whole
   binary when symbols are stripped.
6. `rename`, `set_signature`, `set_comment` - write down what you worked out. These
   persist, so the next session starts where this one stopped.
7. Dynamic follow-up: `debugger_environment` reports what is installed (cdb/WinDbg,
   x64dbg, TitanHide driver). `dbg_run`/`dbg_attach` batch debugger commands; `hwbp_set`
   arms hardware breakpoints through debug registers; `titanhide_hide` hides a PID at
   kernel level from anti-debug checks. Elevation is required for most of these.
8. Full x64dbg sessions: `xdbg_start` launches a target under x64dbg, then the model
   drives the debugger itself - `xdbg_bp_set`, `xdbg_go(wait_stop_timeout)`,
   `xdbg_regs`, `xdbg_mem_read`, `xdbg_stepi`, `xdbg_assemble`, `xdbg_mem_write`,
   `xdbg_pause`, `xdbg_skip`, `xdbg_stop`. Anything not covered by a typed tool goes
   through `xdbg_cmd` (any x64dbg command) and `xdbg_eval` (expression evaluation).
9. Cheat Engine workflow without a debugger: `proc_list` finds the pid, `mem_scan`
   narrows a value (scan, change it in the target, rescan with `previous_file`),
   `mem_read_proc`/`mem_write_proc` inspect and patch, `proc_modules` gives base
   addresses. `mem_strings_proc` pulls strings out of live memory; `peb_info` reads
   the anti-debug triad from the live PEB; `dll_inject` instruments from inside.
10. State discovery: `reg_snapshot` before running the target, `reg_snapshot_diff`
    after - the changed keys are the license/trial state. `file_watch_start` does the
    same for files. `clipboard_get`/`clipboard_set` round-trip whatever the app copies.
11. Requests and tokens: `http_request` forges any HTTP call (exact headers, no
    redirects followed, optional TLS verify off), `tcp_send`/`udp_send` replay raw
    protocols, `netstat` maps pids to connections, `proxy_set` points apps at an
    interception proxy. `jwt_decode`/`jwt_forge` inspect and re-sign tokens.
12. Forged server responses: `net_mock_start` + `net_mock_route` answer the target's
    API calls with your JSON; `net_hosts_add` points its domain at the mock;
    `net_mock_requests` reads what it really sent. For non-HTTP protocols,
    `tcp_proxy_start` + `tcp_proxy_rule` rewrite bytes in flight.
13. Driving the GUI: `window_focus` + `window_rect` + `input_click`/`input_type`/
    `input_key` operate dialogs that resist automation - activation windows, loaders.
    `file_patch`/`file_diff` close the loop with static binary cracks.
14. Source-level recovery: managed code first - `decompile_java` (CFR: jars come back
    as .java sources), `dotnet_inspect`/`dotnet_il` (types, methods, strings, IL);
    native code - `pdb_path_from_binary`/`pdb_download` (Windows binaries ship public
    symbols; a PDB next to the binary names everything in Ghidra automatically).
    `find_crypto_constants` localizes AES/SHA/MD5/ChaCha inside the open program.
15. License-gate hunting without reading 57k functions: `find_license_checks` correlates
    license strings, time APIs, registry reads, and HWID inputs into a ranked list of
    likely gate functions with decompiled snippets. `suggest_patches` turns a found
    comparison/jump into paste-ready byte patches (jcc->jmp, NOPs, inversion), every
    encoding assembled and length-validated for the exact address - apply with patch_bytes.
16. Builds and managed games: `pe_compare` diffs two builds (header drift, section
    shifts, import/export deltas, per-section diff runs, verdict); `function_map` matches
    functions between two analysed builds by code signature so names carry over instead
    of being redone. `unity_dump` parses global-metadata.dat (version, string literals,
    method tokens - the names Unity stripped).
17. Exception logging without a debugger: `exception_logger_start` launches a target with
    a logger DLL loaded via APC before its first instruction - vectored handler +
    unhandled-exception filter, exceptions append to %TEMP%\exclog_<pid>.log, read with
    `exception_logger_read` (code, faulting address, AV target, thread id). Use for
    crackmes whose checks throw, and for targets that fake or hook WER dumps.
    Forensics: `proc_mindump` (dump from OUTSIDE the process, so in-process hooks can't
    forge it) + `dump_analyze` (plausibility scoring - the fake-WER-dump filter).
    `proc_watch_start`/`proc_watch_read` log spawn/exit tree-wide with real cmdlines.
    `mock_record`+`mock_generate` turn a recorded upstream conversation into replayable
    mock routes with serve-time transforms for nonces and timestamps.
18. Traffic analysis with Wireshark's CLI: `ws_status` first (tools + interfaces;
    winget installs Wireshark when missing). `ws_capture_start`/`ws_capture_read`/
    `ws_capture_stop` capture with dumpcap (needs elevation); `ws_read_pcap` answers
    targeted questions (display_filter + fields), `ws_streams` is the triage table,
    `ws_follow_stream` reassembles a conversation, `ws_export_objects` pulls files out.
    `ws_pcap_from_proxy` converts a tcp_proxy JSONL log into a pcap - the MITM
    conversations this toolkit produces, viewable in follow-stream, rewrites included.
19. Metasploit (`msf_status` first): `msf_console` runs resource scripts (the universal
    hatch), `msf_venom` generates payloads, and the RPC path - `msf_rpc_start` then
    `msf_search`/`msf_module_info`/`msf_module_run`/`msf_sessions`/`msf_session_cmd` -
    drives modules and meterpreter sessions programmatically. Missing framework returns
    the exact install command (WSL: apt install metasploit-framework). Lab targets you
    are permitted to test - nothing here checks that for you.
20. Vulnerability scanning with Nuclei (`nuclei_status` first): `nuclei_scan` runs
    templates against authorized targets and returns parsed findings sorted by severity
    with a JSONL report path; narrow with severity/tags/template_ids or whole
    `workflow` chains; `custom_headers`/`vars` for auth'd hosts. `nuclei_templates_list`
    searches the 13k-template repo, `nuclei_templates_write` authors custom probes under
    ghidra-mcp-custom/ (validated on the spot). `nuclei_install`/`nuclei_templates_update`
    fetch the binary and repo when missing. Lab/owned targets only.
21. `crypto_*` - identify and undo encoding and encryption.

For anything that may take minutes, use `job_start` and poll `job_status`.
If a Ghidra tool fails, run `doctor` before anything else.
"""

SETTINGS = Settings.load()
SETTINGS.ensure_dirs()
WORKER = WorkerClient(SETTINGS)
JOBS = JobManager()
NOTES = Notebook(SETTINGS.notes_file)

mcp = FastMCP("ghidra", instructions=INSTRUCTIONS)

_register_tool = mcp.tool


def tool(*decorator_args: Any, **decorator_kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register a blocking tool function, running its body on a worker thread.

    FastMCP awaits a synchronous tool function directly on the event loop, so a call that
    takes a while - reading a 17 MB file, waiting on the Ghidra worker - stops the server
    from reading stdin. The client then sees nothing at all, including the reply to any
    request it sent in the meantime, and cancels everything with a -32001 timeout. Even
    starting a background job fails that way, which is the opposite of what job_start is
    for.

    Wrapping each tool in ``anyio.to_thread.run_sync`` keeps the loop free, so the server
    stays responsive to whatever else the client sends while a slow tool is in flight.
    """

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(function):
            return _register_tool(*decorator_args, **decorator_kwargs)(function)

        @functools.wraps(function)
        async def run_off_the_loop(*args: Any, **kwargs: Any) -> Any:
            call = functools.partial(function, *args, **kwargs)
            # abandon_on_cancel: if the client gives up, stop waiting for the thread
            # rather than holding the loop until a slow Ghidra call finishes.
            result = await anyio.to_thread.run_sync(call, abandon_on_cancel=True)
            # Version gate: an outdated install adds a SECOND content block after the
            # payload. Never prepend it to the text itself - strict clients and the
            # installer's smoke test parse content[0] as JSON and would break.
            try:
                from ghidra_mcp import version

                notice = version.stale_notice()
                if notice:
                    from mcp.types import TextContent

                    return [TextContent(type="text", text=str(result)), TextContent(type="text", text=notice)]
            except Exception:
                pass
            return result

        # FastMCP builds the schema from the signature and docstring, which functools.wraps
        # already copied across; only the coroutine-ness differs from the original.
        return _register_tool(*decorator_args, **decorator_kwargs)(run_off_the_loop)

    return decorate


# Tool modules call `mcp.tool()`; point that at the threading wrapper so every tool gets
# it without touching 69 call sites.
mcp.tool = tool  # type: ignore[method-assign]


def render(payload: Any, *, limit: int | None = None) -> str:
    """Serialise a result, truncating loudly rather than silently.

    A silent cut is worse than none: the model cannot tell "that is everything" from
    "there is more", and will happily conclude a function does not exist.
    """
    cap = limit or SETTINGS.max_output_chars
    text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    if len(text) <= cap:
        return text
    return (
        text[:cap]
        + f"\n\n... TRUNCATED: the result was {len(text)} characters, capped at {cap}. "
        "Narrow the request: a smaller 'limit', a 'filter', or 'offset' for the next page."
    )


def fail(exc: Exception, *, hint: str = "") -> str:
    """Turn an exception into something the model can act on."""
    payload: dict[str, Any] = {"error": f"{type(exc).__name__}: {exc}"}
    if hint:
        payload["hint"] = hint
    trace = getattr(exc, "trace", None)
    if trace and os.environ.get("GHIDRA_MCP_DEBUG") == "1":
        payload["trace"] = trace
    return render(payload)


def warm_worker() -> None:
    """Start the Ghidra worker (and its JVM) in the background at server startup.

    The first ghidra_* call otherwise pays the whole pyghidra boot (~20-60s, more on a
    slow VM) inside the client's request timeout - the usual "-32001 / Request timed
    out" report. A daemon thread absorbs that cost while the model reads the tool list.
    """
    def _boot() -> None:
        try:
            WORKER.ping()
        except Exception:
            pass  # doctor reports the real problem when a tool is actually called

    threading.Thread(target=_boot, name="ctpax-worker-warmup", daemon=True).start()


def ghidra(op: str, params: dict[str, Any] | None = None, *, timeout: float | None = None) -> str:
    """Call a worker operation and render the result, with actionable error hints."""
    try:
        return render(WORKER.call(op, params or {}, timeout=timeout))
    except Exception as exc:
        text = str(exc)
        hint = ""
        if "No program is open" in text:
            hint = "Call open_binary first, or pass the 'program' argument."
        elif "did not finish within" in text:
            hint = "Run this through job_start instead of a blocking call."
        elif "not become ready" in text or "failed to start" in text:
            hint = "Run the doctor tool to check the Ghidra and Java configuration."
        elif "read-only" in text:
            hint = "Set allow_write=true in config.json, or unset GHIDRA_MCP_READONLY."
        return fail(exc, hint=hint)


def clean(params: dict[str, Any]) -> dict[str, Any]:
    """Drop unset optional arguments so the worker's own defaults apply."""
    return {k: v for k, v in params.items() if v is not None}
