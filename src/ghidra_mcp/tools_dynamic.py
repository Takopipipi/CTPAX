"""MCP tools for dynamic analysis: debugger integration, hardware breakpoints,
anti-anti-debug, and kernel debug state.

Elevation and missing components are reported as actionable hints, never as raw errors:
a tool that needs cdb says where to install it, one that needs the TitanHide driver says
how to load it.
"""

from __future__ import annotations

from ghidra_mcp import dynamic
from ghidra_mcp.runtime import fail, mcp, render

_ADMIN_HINT = "most of these tools need an elevated session; start OpenCode (and Cursor) as Administrator when debugging"


@mcp.tool()
def debugger_environment() -> str:
    """One-shot capability report: elevation, SeDebugPrivilege, cdb, x64dbg, TitanHide.

    Call this first when a debugging task comes up: it says which of the dynamic tools
    will work right now and what is missing.
    """
    try:
        return render(dynamic.debugger_environment())
    except Exception as exc:
        return fail(exc, hint=_ADMIN_HINT)


@mcp.tool()
def debug_privilege_enable() -> str:
    """Enable SeDebugPrivilege in this process so it can open system processes."""
    try:
        return render(dynamic.enable_debug_privilege())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def dbg_run(
    target: str,
    commands: list[str],
    target_arguments: str = "",
    timeout: float = 30.0,
) -> str:
    """Run a target under cdb (WinDbg command-line): execute debugger commands, get the log.

    Classic batch debugging: commands like ``lm``, ``!peb``, ``bp ntdll!NtQueryInformationProcess``,
    ``sxe ld:payload.dll``, ``g`` run against the fresh process, then the log comes back as
    text. End the command list with ``q`` or the run ends in a timeout. Requires the
    Windows SDK Debugging Tools (cdb.exe).
    """
    try:
        return render(dynamic.cdb_run(target, commands, target_arguments=target_arguments, timeout=timeout))
    except Exception as exc:
        return fail(exc, hint="cdb.exe comes with 'Debugging Tools for Windows' in the Windows SDK; debugger_environment shows the search result")


@mcp.tool()
def dbg_attach(pid: int, commands: list[str], timeout: float = 30.0) -> str:
    """Attach cdb to a running process, run debugger commands, detach, return the log.

    Non-invasive inspection of a live process: ``!peb``, ``!heap``, ``~*k`` stack walks,
    ``!handle``. Detaches with qd when done. Protected processes refuse attach.
    """
    try:
        return render(dynamic.cdb_attach(pid, commands, timeout=timeout))
    except Exception as exc:
        return fail(exc, hint=_ADMIN_HINT)


@mcp.tool()
def x64dbg_script(kind: str, breakpoint: str | None = None, hwbp_address: str | None = None, commands: list[str] | None = None) -> str:
    """Generate an x64dbg script file (bp/bphws/erun) ready for the Script tab.

    ``kind``: ``run_to_bp`` (software breakpoint at a symbol or address), ``run_to_hwbp``
    (hardware breakpoint), ``script`` (raw command list). Returns the file path and the
    ``x64dbg -a`` launch command for automation builds.
    """
    try:
        return render(dynamic.x64dbg_script(kind, breakpoint=breakpoint, hwbp_address=hwbp_address, commands=commands))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def x64dbg_launch(target: str, script: str | None = None) -> str:
    """Start x64dbg on a target (detached); drive the session in its own window."""
    try:
        return render(dynamic.x64dbg_launch(target, script=script))
    except Exception as exc:
        return fail(exc, hint="set X64DBG_DIR if x64dbg is unpacked somewhere unusual")


@mcp.tool()
def hwbp_set(pid: int, address: str, kind: str = "execute", slot: int = 0) -> str:
    """Set a hardware breakpoint (DR0-DR3) on every thread of a process.

    Works through debug registers via SetThreadContext: no code patching, invisible to
    CRC checks. ``address`` accepts hex like ``0x7FF600001000``; ``kind`` is ``execute``
    (1 byte, classic), ``write`` or ``readwrite`` (4 bytes); ``slot`` is 0-3.

    Elevation notes: your OWN processes (started by proc_start from this same session)
    work without elevation; other users' or elevated targets need the server running as
    administrator. If the target hooks NtSetContextThread, TitanHide (titanhide_hide)
    restores access; otherwise a SetThreadContext failure is the target's anti-debug.
    """
    try:
        return render(dynamic.hwbp_set(pid, int(address, 0), kind=kind, slot=slot))
    except ValueError:
        return fail(ValueError(f"could not parse address {address!r}; use 0x-prefixed hex"))
    except Exception as exc:
        return fail(exc, hint=_ADMIN_HINT)


@mcp.tool()
def hwbp_clear(pid: int, slot: int | None = None) -> str:
    """Clear one hardware-breakpoint slot (0-3), or all four, on every thread of a process."""
    try:
        return render(dynamic.hwbp_clear(pid, slot))
    except Exception as exc:
        return fail(exc, hint=_ADMIN_HINT)


@mcp.tool()
def hwbp_list(pid: int) -> str:
    """Read DR0-DR7 from every thread: which hardware breakpoints are armed right now.

    Also reveals breakpoints set by someone else - a malware's own DR usage or an
    anti-debug check that counts hardware breakpoints.
    """
    try:
        return render(dynamic.hwbp_list(pid))
    except Exception as exc:
        return fail(exc, hint=_ADMIN_HINT)


@mcp.tool()
def titanhide_status() -> str:
    """Is the TitanHide kernel driver loaded and its device object reachable?

    TitanHide is the standard anti-anti-debug driver: it hides a PID from
    NtQueryInformationProcess, NtSetContextThread and friends at kernel level. This tool
    checks the device and the service; the hint names the install steps when missing.
    """
    try:
        return render(dynamic.titanhide_status())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def titanhide_hide(target_pid: int, options: list[str] | None = None, system_pid: int = 4) -> str:
    """Hide a PID behind TitanHide's kernel-level anti-anti-debug shields.

    ``options`` defaults to all nine shields (HideNtQueryInformationProcess,
    HideNtSetContextThread, HideNtGetContextThread, ...). Pass the debugger's PID as
    ``system_pid`` (default 4 = System, hides from every process). Needs an elevated
    session and the driver loaded.
    """
    try:
        return render(dynamic.titanhide_hide(target_pid, options, system_pid=system_pid))
    except Exception as exc:
        return fail(exc, hint=_ADMIN_HINT + "; the TitanHide driver must be started")


@mcp.tool()
def titanhide_unhide(target_pid: int, system_pid: int = 4) -> str:
    """Remove every TitanHide shield from a PID."""
    try:
        return render(dynamic.titanhide_unhide(target_pid, system_pid=system_pid))
    except Exception as exc:
        return fail(exc, hint=_ADMIN_HINT)


@mcp.tool()
def stealth_hide_threads(pid: int) -> str:
    """Hide every thread of a process from future debuggers (usermode TitanHide-lite).

    Sets ThreadHideFromDebugger via NtSetInformationThread on all threads - the same
    trick TitanHide does in kernel, but purely from usermode: no driver, no Secure
    Boot changes, no reboot. One-way flag (cannot be cleared; restart the process to
    undo). Use when the target checks for debuggers at startup and you are about to
    let it run free; existing debugger sessions are not affected.
    """
    try:
        return render(dynamic.stealth_hide_threads(pid))
    except Exception as exc:
        return fail(exc, hint=_ADMIN_HINT)


@mcp.tool()
def kernel_debug_info() -> str:
    """Boot debug state: bcdedit /dbgsettings, kernel debug and test-signing flags, TitanHide service.

    The pre-flight check before kernel work: is this boot debug-enabled, is test signing
    on (needed for self-signed drivers), is the anti-anti-debug driver present.
    """
    try:
        return render(dynamic.kernel_debug_info())
    except Exception as exc:
        return fail(exc, hint=_ADMIN_HINT)


@mcp.tool()
def drivers_list(filter: str | None = None) -> str:
    """List loaded kernel drivers via driverquery, optionally filtered by module name."""
    try:
        return render(dynamic.drivers_list(filter))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def x64dbg_plugin_install() -> str:
    """Download and install the x64dbg-automate plugin into the debugger at runtime.

    Self-healing for the xdbg_* tools: when xdbg_start reports the plugin missing,
    call this once and retry - no reinstall, no manual download.
    """
    try:
        return render(dynamic.install_x64dbg_plugin())
    except Exception as exc:
        return fail(exc)
