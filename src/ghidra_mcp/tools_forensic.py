"""MCP tools for memory forensics: real minidumps of live processes and
plausibility analysis of dumps found on disk (the fake-WER-dump filter), plus
in-process exception logging without a debugger."""

from __future__ import annotations

import os
from pathlib import Path

from ghidra_mcp import forensic
from ghidra_mcp.runtime import fail, mcp, render


@mcp.tool()
def proc_mindump(pid: int, out_path: str) -> str:
    """Write a real minidump of a live process via dbghelp!MiniDumpWriteDump.

    Taken from OUTSIDE the process, so in-process WER/MiniDump hooks never run and
    cannot forge the file (the Real-injector's fake WER dumps do not apply). Includes
    thread+context and handle data - enough for dump_analyze and WinDbg.
    """
    try:
        return render(forensic.proc_mindump(int(pid), out_path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def dump_analyze(path: str, live_pid: int | None = None) -> str:
    """Parse a minidump and score it for anti-forensic fakery.

    Checks the streams a forged dump gets wrong: absurd thread counts (422 threads in
    the Real dumps were fake), stack/context RVAs past EOF, zeroed or misaligned TEBs,
    context sizes that do not match the architecture. Pass live_pid to cross-check
    against the still-running process.
    """
    try:
        return render(forensic.dump_analyze(path, live_pid=live_pid))
    except Exception as exc:
        return fail(exc)


def _locate_exclog_dll() -> str | None:
    """The precompiled logger ships next to the package (native/exception_logger.dll)."""
    candidates = [
        Path(__file__).parent / "native" / "exception_logger.dll",
        Path(__file__).parent.parent.parent / "native" / "exception_logger.dll",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


@mcp.tool()
def exception_logger_start(path: str, arguments: str = "") -> str:
    """Start a target with the exception logger loaded BEFORE its first instruction.

    Creates the process suspended, queues kernel32!LoadLibraryW plus the logger's
    attach routine as APCs on the main thread, then resumes: the logger registers a
    vectored exception handler and an unhandled-exception filter before any target
    code runs - no debugger, nothing anti-debug can see. Exceptions (code, faulting
    address, AV target, thread id) append to %TEMP%\\exclog_<pid>.log; read it with
    exception_logger_read. The classic use: watch a crackme's key check throw or a
    game client's integrity checks fire, at full speed.
    """
    try:
        from ghidra_mcp import system

        dll = _locate_exclog_dll()
        if dll is None:
            return render({"error": "exception_logger.dll not found next to the package (native/)"})
        return render(system.proc_start_dll(path, arguments, dll))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def exception_logger_read(pid: int) -> str:
    """Read the exception log a logger-instrumented target has written so far.

    Lines look like ``exc code=c0000005 at=0x14001234a target=0x10 tid=1a2b`` - an
    access violation at 0x14001234a trying to touch 0x10 on thread 0x1a2b. Stack the
    addresses against the Ghidra analysis: the faulting addresses ARE the check code.
    """
    try:
        log_path = Path(os.environ.get("TEMP", ".")) / f"exclog_{int(pid)}.log"
        if not log_path.is_file():
            return render({"pid": pid, "log": str(log_path), "lines": [], "note": "no log yet - was it started with exception_logger_start?"})
        lines = [line for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
        return render({"pid": pid, "log": str(log_path), "count": len(lines), "lines": lines[-200:]})
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def exception_logger_inject(pid: int) -> str:
    """Load the exception logger into an ALREADY-RUNNING process (remote thread).

    The load itself works for any process you can open. Note: on current Windows the
    vectored handler registered this way only fires on the loading thread, so for
    full first-chance coverage prefer exception_logger_start (APC before first
    instruction). The unhandled-exception tap works process-wide either way.
    """
    try:
        from ghidra_mcp import maxi

        dll = _locate_exclog_dll()
        if dll is None:
            return render({"error": "exception_logger.dll not found next to the package (native/)"})
        return render(maxi.dll_inject(int(pid), dll))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def unity_dump(game_path: str, out_dir: str | None = None) -> str:
    """One-call Unity Il2Cpp inventory: metadata version, string literals, method tokens.

    ``game_path`` is the game root (folder with GameAssembly.dll) or the
    global-metadata.dat file. Writes the full method list (token + name, the join key
    into Ghidra) to il2cpp_methods.txt and every managed string literal - license
    messages, endpoints, key formats - to il2cpp_strings.txt next to the metadata.
    The names Unity stripped from the binary are all here.
    """
    try:
        from ghidra_mcp import unity_metadata

        return render(unity_metadata.unity_dump(game_path, out_dir=out_dir))
    except Exception as exc:
        return fail(exc)
