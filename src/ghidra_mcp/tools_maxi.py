"""MCP tools for the maxi layer: triage, anti-debug scan, PEB, injection, registry
snapshots, clipboard, file watching."""

from __future__ import annotations

from ghidra_mcp import maxi
from ghidra_mcp.runtime import fail, mcp, render

_ADMIN = "needs an elevated session"


@mcp.tool()
def triage(path: str) -> str:
    """One-shot static triage of an unknown binary: identity, packing, anti-debug map, verdict.

    The opening move. Returns format/packer, the anti-debug import surface with what
    each check means, analyst-tool and VM strings, PE heuristics verdict, a triage
    score (clean / interesting / hostile), and concrete next steps. Replaces five
    separate calls.
    """
    try:
        return render(maxi.triage(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def antidebug_scan(path: str) -> str:
    """Scan a binary for anti-debug, anti-VM, and packer fingerprints (static).

    Lists which IsDebuggerPresent-family checks the target imports and what each one
    means in practice, which packer markers appear in its sections, and whether its
    strings name analyst tools. The ScyllaHide profile hint comes straight from this.
    """
    try:
        return render(maxi.antidebug_scan(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def peb_info(pid: int) -> str:
    """Read a live process's PEB: BeingDebugged, NtGlobalFlag, heap flags, real command line.

    Shows the actual values IsDebuggerPresent-family checks read - verify that your
    ScyllaHide patch took hold, or catch a target lying about its command line.
    """
    try:
        return render(maxi.peb_info(pid))
    except Exception as exc:
        return fail(exc, hint=_ADMIN)


@mcp.tool()
def dll_inject(pid: int, dll_path: str) -> str:
    """Load a DLL into a target via remote LoadLibraryW - your DllMain runs in-process.

    Classic instrumentation: hook APIs, patch behaviour, dump data from inside.
    Noisy by design (AV products flag remote threads); use on test machines and your
    own builds. Verify the load with proc_modules afterwards.
    """
    try:
        return render(maxi.dll_inject(pid, dll_path))
    except Exception as exc:
        return fail(exc, hint=_ADMIN)


@mcp.tool()
def dll_eject(pid: int, module_name: str) -> str:
    """Eject a DLL from a target via remote FreeLibrary."""
    try:
        return render(maxi.dll_eject(pid, module_name))
    except Exception as exc:
        return fail(exc, hint=_ADMIN)


@mcp.tool()
def reg_snapshot(key_path: str, name: str | None = None) -> str:
    """Snapshot a registry subtree for later diffing - find where the license lives.

    Snapshot before running/activating the target, then reg_snapshot_diff after: the
    changed values are exactly the state the check reads and writes.
    """
    try:
        return render(maxi.reg_snapshot(key_path, name))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def reg_snapshot_diff(name_before: str, name_after: str) -> str:
    """Diff two registry snapshots: added, removed, and changed values."""
    try:
        return render(maxi.reg_snapshot_diff(name_before, name_after))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def clipboard_get() -> str:
    """Read the clipboard text - what a target copies (keys, state) lands here."""
    try:
        return render(maxi.clipboard_get())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def clipboard_set(text: str) -> str:
    """Write text to the clipboard - preload a key before pasting into a target dialog."""
    try:
        return render(maxi.clipboard_set(text))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def file_watch_start(path: str, recursive: bool = True, name: str | None = None) -> str:
    """Watch a directory tree for created/modified/deleted files.

    The file-side twin of reg_snapshot: start watching, run the target, read exactly
    which config/license files it touched.
    """
    try:
        return render(maxi.file_watch_start(path, recursive=recursive, name=name))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def file_watch_read(name: str, clear: bool = False, limit: int = 100) -> str:
    """Read what a file watcher saw: created / modified / deleted paths."""
    try:
        return render(maxi.file_watch_read(name, clear=clear, limit=limit))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def file_watch_stop(name: str) -> str:
    """Stop a file watcher."""
    try:
        return render(maxi.file_watch_stop(name))
    except Exception as exc:
        return fail(exc)
