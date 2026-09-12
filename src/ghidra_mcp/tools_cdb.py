"""MCP tools for the persistent cdb session and the debugger workflow fixes."""

from __future__ import annotations

from ghidra_mcp import cdb_session
from ghidra_mcp.runtime import fail, mcp, render

_CDB = "cdb.exe comes with 'Debugging Tools for Windows'; debugger_environment shows the search result"


@mcp.tool()
def dbg_session_start(target: str, arguments: str = "") -> str:
    """Start a persistent cdb session on a target: one debugger, many command batches.

    THE workflow (replaces the unreliable batch dbg_attach):

      1. dbg_session_start("crackme.exe")          - session live, at initial breakpoint
      2. dbg_session_command("lm")                 - module list, for symbol qualification
      3. dbg_session_bp_set("crackme+0x3864")      - breakpoint, symbol resolves post-attach
      4. dbg_session_batch(["g", "db esp L64", "g"]) - run to hit, dump, continue
      5. dbg_session_step_over() / step_out()      - single steps as typed calls
      6. dbg_session_stop(detach=True)             - free the target, or kill it

    Unlike dbg_run (fresh debugger per call, all state lost), this session keeps
    breakpoints and registers between calls. Attach variant: dbg_session_attach.
    """
    try:
        return render(cdb_session.session_start(target, arguments))
    except Exception as exc:
        return fail(exc, hint=_CDB)


@mcp.tool()
def dbg_session_attach(pid: int) -> str:
    """Attach a persistent cdb session to a running process.

    The target is verified to exist BEFORE anything is spawned, and a failed attach
    leaves the process untouched - this fixes the batch-mode bug where a dead PID
    attempt harmed a live process.
    """
    try:
        return render(cdb_session.session_attach(pid))
    except Exception as exc:
        return fail(exc, hint="run elevated for other users' processes")


@mcp.tool()
def dbg_session_command(command: str, wait: float = 1.5) -> str:
    """Run one debugger command in the live cdb session and return its output."""
    try:
        return render(cdb_session.session_command(command, wait=wait))
    except Exception as exc:
        return fail(exc, hint="no session yet; dbg_session_start or dbg_session_attach first")


@mcp.tool()
def dbg_session_batch(commands: list[str], wait: float = 1.2) -> str:
    """Run a sequence of debugger commands in the live session, per-command output.

    The multi-breakpoint flow in one call: ``["bp 140001000", "g", "db esp L64", "g"]`` -
    each step's output comes back separately, the session stays up for the next batch.
    """
    try:
        return render(cdb_session.session_batch(commands, wait=wait))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def dbg_session_status() -> str:
    """State of the persistent cdb session: alive, target, debugee pid, log tail."""
    try:
        return render(cdb_session.session_status())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def dbg_session_stop(detach: bool = False) -> str:
    """End the persistent cdb session; detach=True frees the target instead of killing it."""
    try:
        return render(cdb_session.session_stop(detach=detach))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def dbg_smart_breakpoint(address: str, dumps: list[dict] | None = None, max_hits: int = 1, continue_after: bool = True, wait: float = 8.0) -> str:
    """Set a breakpoint, run to it, dump the requested memory, continue - one call.

    ``dumps``: ``[{"expr": "esp", "size": 64}, {"expr": "eax+0x20", "size": 16}]``.
    Replaces the four-step bp -> go -> mem_read -> go dance; the session stays alive
    for the next batch. Requires a live dbg_session.
    """
    try:
        return render(cdb_session.smart_breakpoint(address, dumps=dumps, max_hits=max_hits, continue_after=continue_after, wait=wait))
    except Exception as exc:
        return fail(exc)


# --------------------------------------------------------------------------
# typed wrappers for the common single-command flows
# --------------------------------------------------------------------------
@mcp.tool()
def dbg_session_step_over(wait: float = 1.5) -> str:
    """Step over one instruction in the live cdb session (pt: procedure step).

    Calls execute whole; returns the register dump after the step. The typed
    alternative to dbg_session_command("pt").
    """
    try:
        return render(cdb_session.session_command("pt", wait=wait))
    except Exception as exc:
        return fail(exc, hint="no session yet; dbg_session_start or dbg_session_attach first")


@mcp.tool()
def dbg_session_step_out(wait: float = 3.0) -> str:
    """Run until the current function returns in the live cdb session (gu: go up).

    The typed alternative to dbg_session_command("gu").
    """
    try:
        return render(cdb_session.session_command("gu", wait=wait))
    except Exception as exc:
        return fail(exc, hint="no session yet")


@mcp.tool()
def dbg_session_bp_set(address: str, condition: str | None = None, one_shot: bool = False) -> str:
    """Set a breakpoint in the live cdb session, optionally with a break condition.

    ``condition`` is a cdb expression (``eax==0``, ``poi(esp+4)==0x77``, ``ecx>5``) -
    the debugger breaks only when it is true. ``one_shot=True`` auto-clears the
    breakpoint after the first hit (the bu//1 form). Symbol + offset forms like
    ``crackme+0x3864`` resolve after attach - for names that need module qualification,
    use dbg_session_command("lm") first, or plain addresses.
    """
    try:
        prefix = "/1 " if one_shot else ""
        if condition:
            # j (expr) '' ; 'gc' - break when the condition holds, continue otherwise.
            command = f"bp {prefix}{address} \"j ({condition}) ''; 'gc'\""
        else:
            command = f"bp {prefix}{address}"
        return render(cdb_session.session_command(command, wait=1.0))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def dbg_session_go(wait: float = 3.0) -> str:
    """Resume the debuggee in the live cdb session (g) and return whatever printed.

    Use dbg_session_batch when you want g followed by a memory dump in one call.
    """
    try:
        return render(cdb_session.session_command("g", wait=wait))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def dbg_session_dump(expression: str, size: int = 64) -> str:
    """Dump memory at a cdb expression (db expr Lsize) in the live session.

    ``expression`` accepts registers and arithmetic: ``esp``, ``eax+0x20``,
    ``poi(esp)``. Returns the hexdump exactly as cdb printed it.
    """
    try:
        return render(cdb_session.session_command(f"db {expression} L{int(size)}", wait=1.0))
    except Exception as exc:
        return fail(exc)
