"""MCP tools driving a live x64dbg session: the model operates the debugger itself.

The session holds one debuggee at a time. ``xdbg_start`` launches it under the debugger,
then breakpoints, stepping, memory, registers, and commands work against that session
until ``xdbg_stop``. Each tool's failure text says what to do next (start a session,
pause first, install the plugin).
"""

from __future__ import annotations

from ghidra_mcp.runtime import fail, mcp, render
from ghidra_mcp.x64dbg_client import SESSION

_NO_SESSION = "no x64dbg session; call xdbg_start first"
_NOT_STOPPED = "the debuggee is running; call xdbg_pause first (most inspections need it stopped)"
_PLUGIN_HINT = "the x64dbg-automate plugin is missing; re-run install.bat to fetch it into the plugins folder"


@mcp.tool()
def xdbg_start(target: str, cmdline: str = "", current_dir: str = "") -> str:
    """Launch a target under x64dbg and hold it at the initial system breakpoint.

    This is the entry point of a dynamic session: after it, xdbg_bp_set, xdbg_regs,
    xdbg_mem_read, xdbg_stepi and the rest operate on that debuggee. Starting a new
    session terminates the previous one. Requires the x64dbg-automate plugin.
    """
    try:
        return render(SESSION.start(target, cmdline, current_dir))
    except Exception as exc:
        return fail(exc, hint=_PLUGIN_HINT)


@mcp.tool()
def xdbg_attach(pid: int) -> str:
    """Attach the x64dbg session to a running process (terminates the previous session)."""
    try:
        return render(SESSION.attach(pid))
    except Exception as exc:
        return fail(exc, hint=_PLUGIN_HINT)


@mcp.tool()
def xdbg_stop(detach: bool = False) -> str:
    """Terminate the x64dbg session (killing the debuggee), or detach to let it live.

    ``detach=True`` frees the process instead of killing it - use when the analysis is
    done but the program should keep running.
    """
    try:
        return render(SESSION.stop(detach=detach))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def xdbg_status() -> str:
    """Session state: running, debuggee PID, bitness, stopped-or-running; plugin presence."""
    try:
        return render(SESSION.status())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def xdbg_cmd(command: str) -> str:
    """Run any x64dbg command in the session, returning success and the log tail.

    The escape hatch: every command the x64dbg command bar accepts works here -
    ``bp``, ``bphws``, ``SetBreakpointCommand``, ``log``, ``StepInto``. Use the typed
    tools first; drop to this one for anything they do not cover.
    """
    try:
        return render(SESSION.cmd(command))
    except Exception as exc:
        return fail(exc, hint=_NO_SESSION)


@mcp.tool()
def xdbg_eval(expression: str) -> str:
    """Evaluate an x64dbg expression: register names, ``mod.base``, ``mem.valid(...)``.

    Returns the resolved value, so addresses like ``kernel32.CreateFileW`` or
    ``rip + 0x10`` become numbers the other tools can use.
    """
    try:
        return render(SESSION.evaluate(expression))
    except Exception as exc:
        return fail(exc, hint=_NO_SESSION)


@mcp.tool()
def xdbg_go(wait_stop_timeout: float = 0.0) -> str:
    """Resume the debuggee; optionally wait up to N seconds for the next stop.

    ``wait_stop_timeout=5`` returns once a breakpoint or exception lands (with the stop
    reason context), which is how the model waits for a breakpoint it just set.
    """
    try:
        return render(SESSION.go(wait_stop_timeout=wait_stop_timeout))
    except Exception as exc:
        return fail(exc, hint=_NO_SESSION)


@mcp.tool()
def xdbg_wait_stopped(timeout: float = 10.0) -> str:
    """Block until the debuggee stops (breakpoint, exception, user pause), up to timeout."""
    try:
        return render(SESSION.wait_stopped(timeout))
    except Exception as exc:
        return fail(exc, hint=_NO_SESSION)


@mcp.tool()
def xdbg_pause() -> str:
    """Pause the running debuggee so registers and memory can be inspected."""
    try:
        return render(SESSION.pause())
    except Exception as exc:
        return fail(exc, hint=_NO_SESSION)


@mcp.tool()
def xdbg_stepi(count: int = 1) -> str:
    """Step into N instructions; returns the resulting register state."""
    try:
        return render(SESSION.step_into(count))
    except Exception as exc:
        return fail(exc, hint=_NOT_STOPPED)


@mcp.tool()
def xdbg_stepo(count: int = 1) -> str:
    """Step over N instructions (calls execute whole); returns the register state."""
    try:
        return render(SESSION.step_over(count))
    except Exception as exc:
        return fail(exc, hint=_NOT_STOPPED)


@mcp.tool()
def xdbg_skip(count: int = 1) -> str:
    """Skip N instructions: advance rip without executing them - anti-debug and junk-byte removal."""
    try:
        return render(SESSION.skip(count))
    except Exception as exc:
        return fail(exc, hint=_NOT_STOPPED)


@mcp.tool()
def xdbg_bp_set(address_or_symbol: str, hardware: bool = False, size: int = 1, access: str = "x") -> str:
    """Set a software or hardware breakpoint at a symbol or address.

    ``address_or_symbol`` accepts ``0x7FF6...``, ``kernel32.CreateFileW``, ``rip+0x20``.
    Hardware breakpoints: ``access`` is ``x`` (execute), ``w`` (write), ``r`` (read),
    ``rw``; ``size`` 1/2/4/8. Hardware ones survive code patching and self-CRC.
    """
    try:
        return render(SESSION.bp_set(address_or_symbol, hardware=hardware, size=size, access=access))
    except Exception as exc:
        return fail(exc, hint=_NO_SESSION)


@mcp.tool()
def xdbg_bp_clear(address_or_symbol: str, hardware: bool = False) -> str:
    """Remove a breakpoint."""
    try:
        return render(SESSION.bp_clear(address_or_symbol, hardware=hardware))
    except Exception as exc:
        return fail(exc, hint=_NO_SESSION)


@mcp.tool()
def xdbg_bp_list() -> str:
    """List all breakpoints in the session."""
    try:
        return render(SESSION.bp_list())
    except Exception as exc:
        return fail(exc, hint=_NO_SESSION)


@mcp.tool()
def xdbg_regs() -> str:
    """Full register dump (the debuggee must be stopped)."""
    try:
        return render(SESSION.regs())
    except Exception as exc:
        return fail(exc, hint=_NOT_STOPPED)


@mcp.tool()
def xdbg_set_reg(name: str, value: str) -> str:
    """Set one register (e.g. rip, rax) - patch execution state directly."""
    try:
        return render(SESSION.set_reg(name, int(value, 0)))
    except ValueError:
        return fail(ValueError(f"could not parse value {value!r}; use 0x-prefixed hex or decimal"))
    except Exception as exc:
        return fail(exc, hint=_NOT_STOPPED)


@mcp.tool()
def xdbg_mem_read(address: str, size: int = 64) -> str:
    """Read memory at an address; returns hex plus a hash for comparison."""
    try:
        return render(SESSION.mem_read(int(address, 0), size))
    except ValueError:
        return fail(ValueError(f"could not parse address {address!r}; use 0x-prefixed hex"))
    except Exception as exc:
        return fail(exc, hint=_NOT_STOPPED)


@mcp.tool()
def xdbg_mem_write(address: str, hex_data: str) -> str:
    """Write bytes (hex string) into the debuggee's memory - patching at runtime."""
    try:
        return render(SESSION.mem_write(int(address, 0), hex_data))
    except ValueError:
        return fail(ValueError("pass address as 0x-hex and data as a hex string like '9090c3'"))
    except Exception as exc:
        return fail(exc, hint=_NOT_STOPPED)


@mcp.tool()
def xdbg_disassemble(address: str) -> str:
    """Disassemble one instruction at an address (the debuggee must be stopped)."""
    try:
        return render(SESSION.disassemble(int(address, 0)))
    except ValueError:
        return fail(ValueError(f"could not parse address {address!r}; use 0x-prefixed hex"))
    except Exception as exc:
        return fail(exc, hint=_NOT_STOPPED)


@mcp.tool()
def xdbg_assemble(address: str, instruction: str) -> str:
    """Assemble one instruction at an address and write it - runtime patching."""
    try:
        return render(SESSION.assemble(int(address, 0), instruction))
    except ValueError:
        return fail(ValueError(f"could not parse address {address!r}; use 0x-prefixed hex"))
    except Exception as exc:
        return fail(exc, hint=_NOT_STOPPED)


@mcp.tool()
def xdbg_memmap() -> str:
    """List the debuggee's memory map: modules, heaps, stacks, protections."""
    try:
        return render(SESSION.memmap())
    except Exception as exc:
        return fail(exc, hint=_NOT_STOPPED)


@mcp.tool()
def xdbg_step_out() -> str:
    """Run until the current function returns (rtr) - the missing step_out."""
    try:
        return render(SESSION.cmd("rtr"))
    except Exception as exc:
        return fail(exc, hint=_NOT_STOPPED)


@mcp.tool()
def xdbg_bp_condition(address_or_symbol: str, condition: str) -> str:
    """Set a break condition on a breakpoint: break only when the expression is true.

    x64dbg conditions are expressions like ``eax==0``, ``[esp+4]==0x77``, ``eax>5``.
    The breakpoint must already exist (xdbg_bp_set); this attaches the condition.
    """
    try:
        ok = SESSION.cmd(f"SetBreakpointCondition {address_or_symbol}, \"{condition}\"")
        return render({"success": ok["success"], "address": address_or_symbol, "condition": condition})
    except Exception as exc:
        return fail(exc, hint=_NO_SESSION)


@mcp.tool()
def xdbg_mem_breakpoint(address_or_symbol: str, access: str = "w", size: int = 4) -> str:
    """Set a memory breakpoint (bpm): break on read/write access to an address range.

    ``access``: ``r`` (read), ``w`` (write), ``x`` (execute), ``rw``. This is the
    x64dbg-native watchpoint - survives reallocation differently from hardware
    breakpoints and has no 4-slot limit.
    """
    try:
        access_map = {"r": "r", "w": "w", "x": "x", "rw": "a"}
        if access not in access_map:
            return render({"error": f"access must be one of {sorted(access_map)}"})
        ok = SESSION.cmd(f"bpm {address_or_symbol}, 0, {access_map[access]}")
        return render({"success": ok["success"], "address": address_or_symbol, "access": access, "size": size})
    except Exception as exc:
        return fail(exc, hint=_NO_SESSION)


@mcp.tool()
def xdbg_mem_diff(address: str, previous_hex: str, size: int = 64) -> str:
    """Compare memory now against a previous read: which bytes changed since t1.

    Pass the hex you got from the earlier xdbg_mem_read as ``previous_hex``; the
    response lists every differing byte run with before/after values.
    """
    try:
        addr = int(address, 0)
        client = SESSION._require_client() if hasattr(SESSION, "_require_client") else None
        with SESSION._lock:
            client = SESSION.client
            if client is None:
                return render({"error": "no x64dbg session; xdbg_start first"})
            current = client.read_memory(addr, size)
        previous = bytes.fromhex(previous_hex.replace(" ", ""))
        if len(previous) != len(current):
            return render({"error": f"previous_hex is {len(previous)} bytes, current read is {len(current)}; same size required"})
        runs = []
        index = 0
        while index < len(current):
            if current[index] != previous[index]:
                start = index
                while index < len(current) and current[index] != previous[index]:
                    index += 1
                runs.append({
                    "offset": hex(addr + start),
                    "was": previous[start:index].hex(),
                    "now": current[start:index].hex(),
                    "length": index - start,
                })
            else:
                index += 1
        return render({"address": hex(addr), "changed_runs": len(runs), "runs": runs[:50], "unchanged": not runs})
    except ValueError as exc:
        return fail(ValueError(f"bad hex or address: {exc}"))
    except Exception as exc:
        return fail(exc, hint=_NOT_STOPPED)
