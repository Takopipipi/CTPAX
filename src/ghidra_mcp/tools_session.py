"""Session tools: diagnostics, worker control, background jobs, and the findings notebook."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from typing import Any

from ghidra_mcp.jobs import Job
from ghidra_mcp.runtime import JOBS, NOTES, SETTINGS, WORKER, fail, mcp, render


# --------------------------------------------------------------------------
# diagnostics
# --------------------------------------------------------------------------
@mcp.tool()
def doctor() -> str:
    """Check the installation: Ghidra, Java, the worker, and optional Python libraries.

    Run this first when any Ghidra tool fails. It distinguishes a broken install from a bad
    request, and reports the worker's log tail when start-up failed.
    """
    report: dict[str, Any] = {"settings": SETTINGS.describe(), "problems": SETTINGS.problems()}

    libraries: dict[str, Any] = {}
    for name, purpose in (
        ("lief", "PE/ELF/Mach-O parsing"),
        ("capstone", "raw disassembly"),
        ("yara", "YARA scanning"),
        ("Crypto", "AES/DES/ChaCha (pycryptodome)"),
        ("pefile", "extra PE detail"),
        ("elftools", "extra ELF detail"),
        ("jpype", "JVM bridge, used by the worker"),
        ("pyghidra", "Ghidra bindings, used by the worker"),
    ):
        try:
            module = __import__(name)
            libraries[name] = {
                "available": True,
                "version": getattr(module, "__version__", "unknown"),
                "for": purpose,
            }
        except Exception:
            libraries[name] = {"available": False, "for": purpose, "install": f"pip install {name}"}
    report["python_libraries"] = libraries
    report["python"] = {"executable": sys.executable, "version": sys.version.split()[0]}

    from ghidra_mcp import frida_mcp, managed

    managed_report: dict[str, Any] = {}
    try:
        managed_report["binary_ninja"] = managed.binaryninja_status()
    except Exception as exc:
        managed_report["binary_ninja"] = {"error": str(exc)}
    try:
        managed_report["frida"] = frida_mcp.status()
    except Exception as exc:
        managed_report["frida"] = {"error": str(exc)}
    try:
        from ghidra_mcp import lang_recover

        managed_report["python_decompilers"] = lang_recover.python_decompiler_status()
        managed_report["jvm_engines"] = {name: lang_recover.java_engine_status(name).get("ready", False) for name in ("cfr", "procyon", "jd")}
    except Exception as exc:
        managed_report["decompilers"] = {"error": str(exc)}
    try:
        from ghidra_mcp import managed as managed_module

        managed_report["dnspy"] = {"ready": (managed_module._dnspy_dir() / "dnSpy.exe").is_file()}
        managed_report["megadumper"] = {"ready": managed_module._megadumper_exe().is_file()}
        ilspy = managed_module._ilspycmd()
        managed_report["ilspycmd"] = {"ready": ilspy.get("found", False)}
    except Exception as exc:
        managed_report["managed_gui"] = {"error": str(exc)}
    report["managed_tools"] = managed_report
    report["worker"] = WORKER.describe()

    from ghidra_mcp import version as version_module

    report["version"] = {
        "installed": version_module.__version__,
        "latest": (version_module._peek() or {}).get("latest"),
        "outdated": bool(version_module.outdated()),
    }

    if not SETTINGS.problems():
        try:
            ready = WORKER.start()
            report["worker_ready"] = {
                "ghidra": ready.get("ghidra"),
                "startup_seconds": ready.get("startup_seconds"),
                "operations": len(ready.get("ops") or []),
            }
            report["worker_ping"] = WORKER.ping()
        except Exception as exc:
            report["worker_error"] = f"{type(exc).__name__}: {exc}"
            report["worker_log_tail"] = WORKER.log_tail(30)

    ready = not SETTINGS.problems() and bool(report.get("worker_ready"))
    report["verdict"] = "ready" if ready else "not ready: see problems and worker_error"
    return render(report)


@mcp.tool()
def worker_control(action: str = "status") -> str:
    """Manage the Ghidra worker: ``status``, ``start``, ``stop``, ``restart``, ``cancel``.

    ``cancel`` interrupts a running analysis while keeping the JVM warm, which is what you
    want when a decompile or analysis is taking too long. ``restart`` is the blunt instrument
    for a wedged worker; it loses nothing, since analysis is saved in the project.
    """
    action = (action or "status").lower()
    try:
        if action == "status":
            payload = WORKER.describe()
            if WORKER.running:
                payload["ping"] = WORKER.ping()
            return render(payload)
        if action == "start":
            return render({"started": WORKER.start()})
        if action == "stop":
            WORKER.stop()
            return render({"stopped": True})
        if action == "restart":
            return render({"restarted": WORKER.restart()})
        if action == "cancel":
            return render(
                {
                    "cancel_sent": WORKER.cancel(),
                    "note": "the in-flight operation will fail with 'cancelled'",
                }
            )
        return render(
            {"error": f"unknown action '{action}'", "valid": ["status", "start", "stop", "restart", "cancel"]}
        )
    except Exception as exc:
        return fail(exc)


# --------------------------------------------------------------------------
# background jobs
# --------------------------------------------------------------------------
# Only the operations that can genuinely run long are exposed as jobs; everything else
# is fast enough that a job would add latency rather than remove it.
_JOB_OPS: dict[str, tuple[str, float]] = {
    "open_binary": ("open", 7200.0),
    "analyze_program": ("analyze", 7200.0),
    "decompile_search": ("decompile_grep", 7200.0),
    "export_program": ("export", 7200.0),
    "run_ghidra_script": ("run_script", 7200.0),
    "decompile_many": ("decompile_many", 3600.0),
    "callgraph": ("callgraph", 1800.0),
    "list_strings": ("strings", 1800.0),
}

# Blocking tools name a few arguments more readably than the worker operations do.
_ARGUMENT_ALIASES = {"hex_bytes": "hex", "target": "address"}


@mcp.tool()
def job_start(tool: str, arguments: dict[str, Any] | None = None, label: str | None = None) -> str:
    """Run a slow Ghidra operation in the background and get a job id back immediately.

    Use this instead of a blocking call for anything that may take minutes: importing and
    analysing a large binary, ``decompile_search`` across a whole program, exporting full
    decompilation. The job keeps running between your other tool calls; poll ``job_status``.

    ``tool`` is one of: open_binary, analyze_program, decompile_search, export_program,
    run_ghidra_script, decompile_many, callgraph, list_strings. ``arguments`` takes the same
    fields as the tool itself.
    """
    if tool not in _JOB_OPS:
        return render({"error": f"'{tool}' cannot be run as a job", "supported": sorted(_JOB_OPS)})

    operation, timeout = _JOB_OPS[tool]
    params = {k: v for k, v in (arguments or {}).items() if v is not None}
    for source, destination in _ARGUMENT_ALIASES.items():
        if source in params:
            params[destination] = params.pop(source)

    required = {
        "open_binary": ("path", "program"),
        "decompile_search": ("query",),
        "export_program": ("output",),
        "decompile_many": ("functions",),
        "callgraph": ("function",),
    }.get(tool)
    if required and not any(params.get(name) for name in required):
        return render({"error": f"{tool} needs one of: {', '.join(required)}"})

    def body(job: Job) -> Any:
        job.note(f"worker op '{operation}'")
        job.set_progress(stage="starting")

        def watch() -> None:
            # Mirror the worker's progress frames into the job so job_status shows
            # movement instead of an opaque "running" for several minutes.
            while job.status == "running":
                progress = WORKER.last_progress
                if progress:
                    job.set_progress(**{k: v for k, v in progress.items() if k not in ("id", "at")})
                if job.cancelled:
                    WORKER.cancel()
                    return
                time.sleep(0.5)

        threading.Thread(target=watch, name=f"job-watch-{job.id}", daemon=True).start()
        result = WORKER.call(operation, params, timeout=timeout)
        job.note("finished")
        return result

    job = JOBS.start(label or tool, tool, body)
    return render(
        {
            "job_id": job.id,
            "tool": tool,
            "status": "running",
            "note": "poll job_status(job_id); the job continues across your other tool calls",
        }
    )


@mcp.tool()
def job_status(job_id: str, include_result: bool = True, log_lines: int = 15) -> str:
    """Check a background job: status, elapsed time, progress, and its result once finished."""
    job = JOBS.get(job_id)
    if job is None:
        return render({"error": f"no job '{job_id}'", "jobs": JOBS.list()[:10]})
    return render(job.describe(include_result=include_result, log_lines=log_lines))


@mcp.tool()
def job_list() -> str:
    """List background jobs, newest first, with status and latest progress."""
    return render({"jobs": JOBS.list()})


@mcp.tool()
def job_cancel(job_id: str) -> str:
    """Cancel a running job, interrupting the Ghidra operation behind it."""
    if JOBS.get(job_id) is None:
        return render({"error": f"no job '{job_id}'"})
    return render({"job_id": job_id, "cancel_requested": JOBS.cancel(job_id)})


# --------------------------------------------------------------------------
# findings notebook
# --------------------------------------------------------------------------
def _current_binary_key() -> tuple[str | None, str | None]:
    try:
        info = WORKER.call("info", {}, timeout=60)
        return (info.get("sha256") or info.get("md5") or info.get("program")), info.get("name")
    except Exception:
        return None, None


@mcp.tool()
def note_add(
    text: str,
    binary: str | None = None,
    tags: list[str] | None = None,
    label: str | None = None,
    confidence: str = "medium",
) -> str:
    """Record a finding about a binary, keyed by its hash so it survives into later sessions.

    Ghidra stores renames and comments; this stores the reasoning behind them - which
    algorithm a routine turned out to be, which key decrypts which blob, what is still
    unexplained. Write one self-contained finding per call. ``binary`` defaults to whatever
    program is currently open.
    """
    try:
        key = binary
        if not key:
            key, name = _current_binary_key()
            label = label or name
        if not key:
            return render(
                {"error": "no program is open, so there is nothing to attach this to", "hint": "pass 'binary' explicitly"}
            )
        return render({"binary": key, "note": NOTES.add(str(key), text, tags=tags, label=label, confidence=confidence)})
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def note_list(binary: str | None = None, query: str | None = None, regex: bool = False, limit: int = 50) -> str:
    """Read findings for a binary, or search across all of them (text or regex).

    Call this when you begin work on a binary: it is how you inherit what an earlier session
    already established instead of deriving it again. ``regex=true`` treats ``query`` as a
    pattern - ``license.*check``, ``AES|RC4``, ``key\\s+derivation``.
    """
    try:
        if binary:
            return render(NOTES.get(str(binary)))
        if query:
            return render(NOTES.search(query, regex=regex, limit=limit))
        key, _ = _current_binary_key()
        if key:
            current = NOTES.get(str(key))
            if current["note_count"]:
                return render(current)
        return render(
            {
                "binaries": NOTES.binaries(),
                "recent": NOTES.search(None, limit=limit)["notes"][:15],
            }
        )
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def note_export(out_path: str | None = None) -> str:
    """Export every note to a readable markdown file (default: notes_export.md in the home)."""
    try:
        path = NOTES.export(Path(out_path)) if out_path else NOTES.export()
        return render({"exported": True, "path": str(path), "size": path.stat().st_size})
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def note_remove(note_id: str, binary: str) -> str:
    """Delete a finding that turned out to be wrong, rather than leaving it to mislead later."""
    return render({"binary": binary, "note_id": note_id, "removed": NOTES.remove(str(binary), str(note_id))})
