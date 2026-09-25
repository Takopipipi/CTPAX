"""MCP tools for the Frida integration: spawn/attach sessions, live JavaScript,
module/export enumeration, memory read/write, and export interception hooks."""

from __future__ import annotations

from ghidra_mcp import frida_mcp
from ghidra_mcp.runtime import fail, mcp, render


@mcp.tool()
def frida_status() -> str:
    """Frida availability, local device, and which pids have live sessions.

    Everything Frida here runs through this server's session registry; call this
    first to see whether the interceptors from earlier calls are still alive.
    """
    try:
        return render(frida_mcp.status())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def frida_ps(pattern: str | None = None) -> str:
    """List local processes as Frida sees them (pid + name); filter by name substring.

    Same list frida-ps shows. Attach to one of these pids to start instrumenting.
    """
    try:
        return render(frida_mcp.ps(pattern))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def frida_attach(pid: int) -> str:
    """Attach to a running process and keep the session for later calls.

    Needs the same privilege as the target; anti-debug targets may refuse. After
    attaching use frida_modules/frida_run/frida_hook, then frida_detach.
    """
    try:
        return render(frida_mcp.attach(pid))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def frida_spawn(path: str, arguments: str = "", resume: bool = False) -> str:
    """Spawn a program suspended under Frida, attach, and optionally resume.

    Set hooks with frida_run/frida_hook BEFORE resuming so startup code is visible;
    resume=True only on success paths. The spawned pid comes back for later calls.
    """
    try:
        return render(frida_mcp.spawn(path, arguments, resume=resume))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def frida_resume(pid: int) -> str:
    """Resume a spawned (suspended) process."""
    try:
        return render(frida_mcp.resume(pid))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def frida_detach(pid: int) -> str:
    """Detach from a process; JS agents and hooks go with it."""
    try:
        return render(frida_mcp.detach(pid))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def frida_kill(pid: int) -> str:
    """Kill the target process through the device."""
    try:
        return render(frida_mcp.kill(pid))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def frida_run(pid: int, javascript: str, wait: float = 3.0) -> str:
    """Load arbitrary JavaScript into the session; send() messages come back.

    The script stays loaded between calls, so state (a Module on load, an array you
    fill) persists. Messages accumulate; frida_events reads and clears them.
    """
    try:
        return render(frida_mcp.run(pid, javascript, wait=wait))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def frida_events(pid: int, clear: bool = True) -> str:
    """Read (and clear) messages accumulated by hooks and scripts since the last call."""
    try:
        return render(frida_mcp.events(pid, clear=clear))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def frida_hook(pid: int, module: str, export: str, wait: float = 5.0, extra_javascript: str = "") -> str:
    """Intercept an exported function; args and return land in frida_events.

    Example: frida_hook(pid, \"ntdll.dll\", \"NtQueryInformationProcess\") then run
    the target and read frida_events. The interceptor stays live until detach.
    """
    try:
        return render(frida_mcp.hook(pid, module, export, wait=wait, extra_javascript=extra_javascript))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def frida_modules(pid: int, filter: str | None = None) -> str:
    """Modules loaded in the target (name, base, size, path), optional name filter."""
    try:
        return render(frida_mcp.modules(pid, filter=filter))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def frida_exports(pid: int, module: str) -> str:
    """Exports (symbols) of one module - the hookable surface for frida_hook."""
    try:
        return render(frida_mcp.exports(pid, module))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def frida_memory_read(pid: int, address: str, size: int = 64) -> str:
    """Read bytes from the target's memory via the Frida session, as hex + ascii."""
    try:
        return render(frida_mcp.mem_read(pid, address, size))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def frida_memory_write(pid: int, address: str, hex_data: str) -> str:
    """Write bytes into the target's memory (code pages writable through the agent)."""
    try:
        return render(frida_mcp.mem_write(pid, address, hex_data))
    except Exception as exc:
        return fail(exc)