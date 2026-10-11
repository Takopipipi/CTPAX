"""MCP tools wrapping the Cheat Engine integration: install/launch status, the
autorun Lua bridge, arbitrary Lua execution inside CE (the full-program
channel), and typed attach/read/write/assemble helpers."""

from __future__ import annotations

from ghidra_mcp import ce_mcp
from ghidra_mcp.runtime import fail, mcp, render


@mcp.tool()
def ce_status() -> str:
    """Cheat Engine availability: install dir, version, process, window, Lua bridge.

    One-time setup when the bridge is not ready: call ce_launch (it drops the
    bridge script into autorun\\ - Cheat Engine runs *.lua files there at
    startup), wait for the heartbeat reported here, then ce_lua executes any
    Cheat Engine Lua. The native mem_* tools cover scanning without CE.
    """
    try:
        return render(ce_mcp.status())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def ce_launch(target: str = "") -> str:
    """Start Cheat Engine (installing the Lua bridge), optionally with a target.

    `target` is a pid or a process name (e.g. 'game.exe'); it reaches CE through
    the environment and is attached with openProcess by the autorun script - the
    CEAutoAttach pattern. If CE is already running with a live bridge, the
    target is attached through the bridge instead.
    """
    try:
        return render(ce_mcp.launch(target.strip() or None))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def ce_bridge_install(force: bool = False) -> str:
    """Write the Lua mailbox bridge into Cheat Engine's autorun\\ folder.

    Idempotent: an unchanged script is left alone unless force=true. Takes
    effect at the next CE start (autorun scripts run only at startup), so
    follow with ce_launch or restart Cheat Engine.
    """
    try:
        return render(ce_mcp.bridge_install(force=force))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def ce_bridge_status() -> str:
    """Is the autorun script in place, is CE running, is the heartbeat fresh?"""
    try:
        return render(ce_mcp.bridge_status())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def ce_lua(script: str, timeout: float = 15.0) -> str:
    """Execute ANY Cheat Engine Lua chunk inside CE and return its first return value.

    This is the 100%-of-the-program channel: openProcess, readBytes/writeBytes,
    autoAssemble, createMemScan (the value scanner), debug_* breakpoints, the
    address list, forms, timers - the whole CE Lua API. `script` runs in CE's
    own Lua state; `return <value>` comes back as JSON. CE must be running with
    the bridge loaded (ce_status). Examples:
      return getAddress('kernel32.dll')
      openProcess('game.exe'); return getAddressList()[1].Value
    """
    try:
        return render(ce_mcp.lua(script, timeout=timeout))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def ce_attach(target: str) -> str:
    """Attach Cheat Engine to a process: pid or name (openProcess, e.g. 'game.exe')."""
    try:
        return render(ce_mcp.attach(target))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def ce_read(address: str, size: int = 8) -> str:
    """Read bytes from the attached process via CE (readBytes) - decimal list plus hex.

    `address` is a CE address string: 'game.exe+1234', '00400000', a symbol, or
    a plain number - parsed by Cheat Engine exactly like its own address field.
    """
    try:
        return render(ce_mcp.read(address, size))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def ce_write(address: str, data: str) -> str:
    """Write hex bytes into the attached process via CE (writeBytes).

    `data` is hex bytes: '90 90', '0x90,0x90' or '9090'. `address` follows
    CEAddressString rules (see ce_read).
    """
    try:
        return render(ce_mcp.write(address, data))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def ce_assemble(code: str) -> str:
    """Run a full Cheat Engine Auto Assembler script verbatim (autoAssemble).

    Pass the complete AA text - alloc/labels/[enable] blocks work exactly as in
    CE's assembler window. For raw bytes use ce_write instead.
    """
    try:
        return render(ce_mcp.assemble(code))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def ce_focus() -> str:
    """Bring the Cheat Engine window to the foreground (for manual follow-up)."""
    try:
        return render(ce_mcp.focus())
    except Exception as exc:
        return fail(exc)