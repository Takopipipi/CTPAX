"""MCP tools for system-level inspection: processes, windows, memory scan/read/write,
registry, and network connections.

The memory tools are the Cheat Engine workflow (scan, narrow, patch) and work without a
debugger; the registry tools reach license checks; netstat maps connections to pids.
"""

from __future__ import annotations

from ghidra_mcp import system
from ghidra_mcp.runtime import fail, mcp, render

_ELEVATED = "most of these need an elevated session"


@mcp.tool()
def proc_list(filter: str | None = None) -> str:
    """Enumerate running processes: pid, parent, threads, image path.

    The starting point for every dynamic task: find the target's pid to feed into
    mem_scan, proc_modules, hwbp_set, xdbg_attach, or titanhide_hide.
    """
    try:
        return render(system.proc_list(filter=filter))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def proc_modules(pid: int) -> str:
    """List modules loaded into a process with base addresses and sizes.

    Base addresses are what you add offsets to for hardware breakpoints, memory patches,
    and x64dbg commands when ASLR moved everything.
    """
    try:
        return render(system.proc_modules(pid))
    except Exception as exc:
        return fail(exc, hint=_ELEVATED)


@mcp.tool()
def proc_start(path: str, arguments: str = "", capture: bool = True) -> str:
    """Start a process and return its pid; capture=True (default) keeps stdin/stdout pipes.

    With capture on, the process is fully interactive from MCP: ``proc_write`` feeds its
    stdin (prompts, license keys, menu choices) and ``proc_read`` returns what it
    printed. This is the workflow for console crackmes: proc_start -> proc_read (see
    the prompt) -> proc_write (the answer) -> proc_read. ``proc_alive`` /
    ``proc_wait_exit`` track the pid; ``proc_kill`` ends it. capture=False detaches and
    only tracks the pid.
    """
    try:
        return render(system.proc_start(path, arguments, capture=capture))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def proc_kill(pid: int) -> str:
    """Terminate a process by pid."""
    try:
        return render(system.proc_kill(pid))
    except Exception as exc:
        return fail(exc, hint=_ELEVATED)


@mcp.tool()
def window_list(filter: str | None = None, visible_only: bool = True) -> str:
    """Enumerate top-level windows with hwnd, title, class, and owning pid.

    The hwnd is the handle for window_send_text and window_close; the class name is the
    stable identifier when titles change.
    """
    try:
        return render(system.window_list(filter=filter, visible_only=visible_only))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def window_send_text(hwnd: str, text: str) -> str:
    """Type text into a window via WM_CHAR without stealing focus."""
    try:
        return render(system.window_send_text(int(hwnd, 0), text))
    except ValueError:
        return fail(ValueError(f"could not parse hwnd {hwnd!r}; use a value from window_list"))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def window_close(hwnd: str) -> str:
    """Post WM_CLOSE to a window - the polite termination an app can refuse."""
    try:
        return render(system.window_close(int(hwnd, 0)))
    except ValueError:
        return fail(ValueError(f"could not parse hwnd {hwnd!r}; use a value from window_list"))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def mem_scan(pid: int, value: str, type: str = "u32", filter: str | None = None, previous_file: str | None = None, limit: int = 200) -> str:
    """Scan a live process's memory for a value, Cheat Engine style.

    First call: ``mem_scan(pid, "9999", type="u32")`` returns hits and a ``state_file``.
    Change the value in the game/app, then rescan with the new value and
    ``previous_file=<state_file>`` - the surviving addresses are the variable. ``type``
    is u8..u64/i32/i64/f32/f64; ``filter`` adds comparisons (``>100``, ``!=7``) for
    narrowing by range. Final step: ``mem_write_proc`` the address.
    """
    try:
        return render(system.mem_scan(pid, value, type=type, filter=filter, previous_file=previous_file, limit=limit))
    except Exception as exc:
        return fail(exc, hint=_ELEVATED)


@mcp.tool()
def mem_read_proc(pid: int, address: str, size: int = 64) -> str:
    """Read memory from a live process at an address (no debugger attached)."""
    try:
        return render(system.mem_read_proc(pid, address, size))
    except Exception as exc:
        return fail(exc, hint=_ELEVATED)


@mcp.tool()
def mem_write_proc(pid: int, address: str, hex_data: str) -> str:
    """Write bytes into a live process's memory - patch values or code at runtime.

    Code pages are flipped writable for the duration, so patching instructions works
    the same as patching game state.
    """
    try:
        return render(system.mem_write_proc(pid, address, hex_data))
    except Exception as exc:
        return fail(exc, hint=_ELEVATED)


@mcp.tool()
def mem_strings_proc(pid: int, min_length: int = 6, limit: int = 100) -> str:
    """Dump readable strings (ascii + utf-16) from a live process's memory with addresses.

    The fast way to find license prompts, URLs, and player names inside a running
    process before hunting them in the file.
    """
    try:
        return render(system.mem_strings_proc(pid, min_length=min_length, limit=limit))
    except Exception as exc:
        return fail(exc, hint=_ELEVATED)


@mcp.tool()
def reg_read(key_path: str, value_name: str | None = None) -> str:
    """Read a registry value, or list every value of a key when value_name is null.

    Where trial periods, licenses, and MRU lists live. Pass HKLM\\... paths and read
    what the target checks at startup.
    """
    try:
        return render(system.reg_read(key_path, value_name))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def reg_write(key_path: str, value_name: str, data: str | int | list[str], kind: str = "auto") -> str:
    """Create or update a registry value (auto-detects str/dword/multi_sz; kind overrides).

    The write half of license research: flip a trial flag, set an install date, add a
    key the checker expects.
    """
    try:
        return render(system.reg_write(key_path, value_name, data, kind=kind))
    except Exception as exc:
        return fail(exc, hint=_ELEVATED)


@mcp.tool()
def reg_delete_value(key_path: str, value_name: str) -> str:
    """Delete a registry value - undoing license state is sometimes removal."""
    try:
        return render(system.reg_delete_value(key_path, value_name))
    except Exception as exc:
        return fail(exc, hint=_ELEVATED)


@mcp.tool()
def reg_enum_keys(key_path: str) -> str:
    """List the subkeys of a registry key."""
    try:
        return render(system.reg_enum_keys(key_path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def netstat(filter: str | None = None) -> str:
    """List TCP/UDP endpoints with owning pids; filter by port, ip, or state.

    Map what a process talks to: the server it phones home to, the port the game
    protocol uses - then replay it with http_request or tcp_send.
    """
    try:
        return render(system.netstat(filter=filter))
    except Exception as exc:
        return fail(exc)


# --------------------------------------------------------------------------
# process I/O and lifecycle
# --------------------------------------------------------------------------
@mcp.tool()
def proc_read(pid: int, timeout: float = 1.0) -> str:
    """Read what the process (from proc_start with capture=True) wrote to stdout so far.

    The question half of the interactive workflow: read the prompt before answering it
    with proc_write, or read the result after. Returns everything printed since the
    last read, plus whether the process is still alive.
    """
    try:
        return render(system.proc_read(pid, timeout=timeout))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def proc_write(pid: int, text: str, newline: bool = True) -> str:
    """Write to the process's stdin (from proc_start with capture=True).

    Feeds prompts, answers, and menu choices: the answer half of the interactive
    workflow. Pair with proc_read - write the response to the prompt, then read what
    the program did with it.
    """
    try:
        return render(system.proc_write(pid, text, newline=newline))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def proc_alive(pid: int) -> str:
    """Is a pid running right now, without proc_list and filtering."""
    try:
        return render(system.proc_alive(pid))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def proc_wait_exit(pid: int, timeout: float = 30.0) -> str:
    """Block until a pid exits (or timeout); returns the exit code when it does."""
    try:
        return render(system.proc_wait_exit(pid, timeout=timeout))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def proc_info(pid: int) -> str:
    """One call: name, path, real command line (PEB), parent, creation time, threads.

    Everything worth knowing about a process before touching it - and the command
    line comes from the PEB, so it survives GetCommandLineW lies.
    """
    try:
        return render(system.proc_info(int(pid)))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def proc_watch_start(pattern: str | None = None, name: str | None = None) -> str:
    """Watch process creation and exit tree-wide; log spawn/exit with cmdline.

    The master tool for loaders that spawn children: every new process lands in the
    log within ~1s with pid, ppid, name, and real command line. ``pattern`` filters
    spawns by name substring (e.g. "cmd.exe"). proc_watch_read tails, proc_watch_stop
    ends it. Fast children (<0.25s lifetime) can slip between snapshots.
    """
    try:
        return render(system.proc_watch_start(pattern, name=name))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def proc_watch_read(name: str, limit: int = 100) -> str:
    """Read the spawn/exit events a watcher has collected (newest last)."""
    try:
        return render(system.proc_watch_read(name, limit=limit))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def proc_watch_stop(name: str) -> str:
    """Stop a process watcher; its log stays on disk."""
    try:
        return render(system.proc_watch_stop(name))
    except Exception as exc:
        return fail(exc)
