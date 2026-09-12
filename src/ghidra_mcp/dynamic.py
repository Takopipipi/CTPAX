"""Dynamic-analysis layer: debuggers (cdb/WinDbg, x64dbg), anti-anti-debug (TitanHide),
hardware breakpoints via debug registers, and process/privilege helpers.

Nothing here silently attaches to anything. Each tool reports what is installed, runs a
short-lived command and returns its log, generates a script for the target debugger, or
pokes a process the caller explicitly names. Tools that need elevation or a kernel driver
(TitanHide) say so in their failure hints instead of failing cryptically.

Win32 note: every DLL is loaded once with ``use_last_error=True`` and signatures are
declared at import. Without declared signatures ctypes truncates HANDLEs to 32 bits on
x64 (breaking GetCurrentProcess's pseudo-handle), and without ``use_last_error`` the
error code is clobbered by ctypes' own calls before ``get_last_error`` reads it.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import time
from pathlib import Path
from typing import Any

_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)

_GENERIC_READ_WRITE = 0xC0000000
_OPEN_EXISTING = 3
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_THREAD_ALL = 0x1FFFFF
_PROCESS_ALL = 0x1FFFFF
_TH32CS_SNAPTHREAD = 0x4
_PRIVILEGE_SET = 0x00000002  # SE_PRIVILEGE_ENABLED


class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]


class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wt.DWORD),
        ("Luid", _LUID),
        ("Attributes", wt.DWORD),
    ]


class _THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ThreadID", wt.DWORD),
        ("th32OwnerProcessID", wt.DWORD),
        ("tpBasePri", wt.LONG),
        ("tpDeltaPri", wt.LONG),
        ("dwFlags", wt.DWORD),
    ]


class _M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_uint64), ("High", ctypes.c_int64)]


class _XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord", ctypes.c_uint16), ("StatusWord", ctypes.c_uint16),
        ("TagWord", ctypes.c_uint8), ("Reserved1", ctypes.c_uint8),
        ("ErrorOpcode", ctypes.c_uint16), ("ErrorOffset", ctypes.c_uint32),
        ("ErrorSelector", ctypes.c_uint16), ("Reserved2", ctypes.c_uint16),
        ("DataOffset", ctypes.c_uint32), ("DataSelector", ctypes.c_uint16),
        ("Reserved3", ctypes.c_uint16), ("MxCsr", ctypes.c_uint32),
        ("MxCsr_Mask", ctypes.c_uint32),
        ("FloatRegisters", _M128A * 8),
        ("XmmRegisters", _M128A * 16),
        ("Reserved4", ctypes.c_uint8 * 96),
    ]


class _CONTEXT64(ctypes.Structure):
    """The complete x64 CONTEXT (1232 bytes, 16-aligned).

    The kernel writes the whole structure with GetThreadContext, so a partial replica
    would be overwritten past its end. Debug registers sit at 0x48-0x78, so they come
    out readable here; the rest exists to make the buffer the right size and shape.
    """
    _fields_ = [
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64), ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64), ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        ("ContextFlags", wt.DWORD), ("MxCsr", wt.DWORD),
        ("SegCs", wt.WORD), ("SegDs", wt.WORD), ("SegEs", wt.WORD),
        ("SegFs", wt.WORD), ("SegGs", wt.WORD), ("SegSs", wt.WORD),
        ("EFlags", wt.DWORD),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64), ("Dr2", ctypes.c_uint64), ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64), ("Rdx", ctypes.c_uint64), ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64), ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64), ("R9", ctypes.c_uint64), ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64), ("R14", ctypes.c_uint64), ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("FltSave", _XMM_SAVE_AREA32),
        ("VectorRegister", _M128A * 26),
        ("VectorControl", ctypes.c_uint64),
        ("DebugControl", ctypes.c_uint64),
        ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64),
        ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64),
    ]


assert ctypes.sizeof(_CONTEXT64) == 1232, ctypes.sizeof(_CONTEXT64)

# CONTROL | INTEGER | SEGMENTS | FLOATING_POINT | DEBUG_REGISTERS
_CONTEXT_FLAGS = 0x0010001F


def _init_winapi() -> None:
    """Declare every Win32 signature once, at import, so callers cannot half-configure."""
    kernel32, advapi32 = _KERNEL32, _ADVAPI32
    handle_p = ctypes.POINTER(wt.HANDLE)

    kernel32.GetCurrentProcess.restype = wt.HANDLE
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.CloseHandle.restype = wt.BOOL

    advapi32.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, handle_p]
    advapi32.OpenProcessToken.restype = wt.BOOL
    advapi32.LookupPrivilegeValueW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ctypes.POINTER(_LUID)]
    advapi32.LookupPrivilegeValueW.restype = wt.BOOL
    advapi32.AdjustTokenPrivileges.argtypes = [
        wt.HANDLE, wt.BOOL, ctypes.POINTER(_TOKEN_PRIVILEGES), wt.DWORD, ctypes.c_void_p, ctypes.c_void_p,
    ]
    advapi32.AdjustTokenPrivileges.restype = wt.BOOL

    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.OpenThread.restype = wt.HANDLE
    kernel32.GetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
    kernel32.GetThreadContext.restype = wt.BOOL
    kernel32.SetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
    kernel32.SetThreadContext.restype = wt.BOOL
    kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    kernel32.Thread32First.argtypes = [wt.HANDLE, ctypes.POINTER(_THREADENTRY32)]
    kernel32.Thread32First.restype = wt.BOOL
    kernel32.Thread32Next.argtypes = [wt.HANDLE, ctypes.POINTER(_THREADENTRY32)]
    kernel32.Thread32Next.restype = wt.BOOL

    kernel32.CreateFileW.argtypes = [
        wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE,
    ]
    kernel32.CreateFileW.restype = wt.HANDLE
    kernel32.DeviceIoControl.argtypes = [
        wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD, ctypes.c_void_p, wt.DWORD,
        ctypes.POINTER(wt.DWORD), ctypes.c_void_p,
    ]
    kernel32.DeviceIoControl.restype = wt.BOOL


_init_winapi()


# --------------------------------------------------------------------------
# admin / privilege
# --------------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _adjust_token_privilege(name: str, *, enable: bool) -> tuple[bool, str]:
    """Toggle one token privilege, returning (success, message)."""
    token = wt.HANDLE()
    if not _ADVAPI32.OpenProcessToken(_KERNEL32.GetCurrentProcess(), 0x0028, ctypes.byref(token)):
        return False, f"OpenProcessToken failed (error {ctypes.get_last_error()})"
    try:
        luid = _LUID()
        if not _ADVAPI32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False, f"LookupPrivilegeValueW({name}) failed"
        attributes = _PRIVILEGE_SET if enable else 0
        privileges = _TOKEN_PRIVILEGES(1, luid, attributes)
        if not _ADVAPI32.AdjustTokenPrivileges(token, False, ctypes.byref(privileges), 0, None, None):
            return False, "AdjustTokenPrivileges failed"
        # AdjustTokenPrivileges reports success even when the privilege is absent from
        # the token; ERROR_NOT_ALL_ASSIGNED is the real verdict.
        if ctypes.get_last_error() == 1300:
            return False, f"the process token does not hold {name} (restart elevated)"
        return True, f"{name} {'enabled' if enable else 'disabled'}"
    finally:
        _KERNEL32.CloseHandle(token)


def enable_debug_privilege() -> dict[str, Any]:
    """Enable SeDebugPrivilege in this process so other tools can open system processes."""
    ok, message = _adjust_token_privilege("SeDebugPrivilege", enable=True)
    result = {"enabled": ok, "message": message, "elevated": is_admin()}
    if not ok:
        result["why"] = (
            "the MCP server process runs with a limited token"
            if "does not hold" in message
            else message
        )
        result["fix"] = [
            "close OpenCode (and Cursor) completely",
            "right-click the terminal/launcher -> 'Run as administrator', start them from there",
            "or: schtasks-style auto-elevation is not possible without a UAC prompt - "
            "the server cannot elevate itself silently (that is a Windows security boundary)",
        ]
        result["dynamic_tools_state"] = (
            "tools that open OTHER users'/elevated processes (hwbp, titanhide, cdb attach to "
            "elevated targets) will fail; same-user non-elevated targets keep working"
        )
    return result


# --------------------------------------------------------------------------
# tool discovery
# --------------------------------------------------------------------------
_CDB_CANDIDATES = [
    "C:/Program Files (x86)/Windows Kits/10/Debuggers/x64/cdb.exe",
    "C:/Program Files (x86)/Windows Kits/10/Debuggers/x86/cdb.exe",
    "C:/Program Files/Windows Kits/10/Debuggers/x64/cdb.exe",
    "C:/Program Files/Windows Kits/11/Debuggers/x64/cdb.exe",
]

_X64DBG_ROOTS = [
    "C:/x64dbg/release",
    "C:/Program Files/x64dbg/release",
    "C:/Program Files (x86)/x64dbg/release",
    "D:/x64dbg/release",
    "E:/x64dbg/release",
]


def find_cdb() -> dict[str, Any]:
    """Locate cdb.exe - WinDbg's batch-scriptable command-line debugger."""
    override = os.environ.get("WINDBG_DIR")
    candidates = ([str(Path(override) / "cdb.exe")] if override else []) + _CDB_CANDIDATES
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file():
            return {"found": True, "path": str(path), "bitness": "x64" if "x64" in str(path) else "x86"}
    winsdk = Path("C:/Program Files (x86)/Windows Kits")
    hint = (
        "install 'Debugging Tools for Windows' via the Windows SDK installer, or set WINDBG_DIR"
        if not winsdk.is_dir()
        else f"{winsdk}\\10\\Debuggers exists but no cdb.exe was found; set WINDBG_DIR"
    )
    return {"found": False, "hint": hint}


def find_x64dbg() -> dict[str, Any]:
    """Locate x64dbg from X64DBG_DIR or the usual unpack locations."""
    override = os.environ.get("X64DBG_DIR")
    roots = ([override] if override else []) + _X64DBG_ROOTS
    for root_text in roots:
        root = Path(root_text)
        if not root.is_dir():
            continue
        for name in ("x96dbg.exe", "x64dbg.exe", "x32dbg.exe"):
            candidate = root / name
            if candidate.is_file():
                return {"found": True, "launcher": str(candidate), "root": str(root)}
    return {
        "found": False,
        "hint": "unpack x64dbg (https://x64dbg.com) and set X64DBG_DIR to its release folder, or unpack it to C:\\x64dbg",
    }


def _open_device(device_path: str) -> tuple[int, int]:
    """Open a device object; returns (handle, win32_error)."""
    handle = _KERNEL32.CreateFileW(
        device_path, _GENERIC_READ_WRITE, 0, None, _OPEN_EXISTING, 0, None
    )
    if not handle or handle == _INVALID_HANDLE:
        return 0, ctypes.get_last_error()
    return handle, 0


def titanhide_status() -> dict[str, Any]:
    """Is the TitanHide kernel driver's device object reachable, and is the service loaded?"""
    handle, error = _open_device(r"\\.\TitanHide")
    service = _sc_query("TitanHide")
    if handle:
        _KERNEL32.CloseHandle(handle)
        return {"device": True, "service": service}
    return {
        "device": False,
        "win32_error": error,
        "meaning": {2: "device \\\\.\\TitanHide does not exist: the driver is not loaded", 5: "access denied: run elevated"}.get(error, "CreateFileW failed"),
        "service": service,
        "hint": "build/install TitanHide (github.com/mrexodia/TitanHide): sc create TitanHide binPath= TitanHide.sys type= kernel && sc start TitanHide",
    }


def debugger_environment() -> dict[str, Any]:
    """One-shot capability report: elevation, privilege, cdb, x64dbg, TitanHide."""
    return {
        "elevated": is_admin(),
        "debug_privilege": enable_debug_privilege(),
        "cdb": find_cdb(),
        "x64dbg": find_x64dbg(),
        "titanhide": titanhide_status(),
    }


# --------------------------------------------------------------------------
# cdb (WinDbg command line): batch runs
# --------------------------------------------------------------------------
def _symbol_path() -> str:
    """The configured WinDbg symbol path (config.json symbol_path / GHIDRA_MCP_SYMBOL_PATH)."""
    from ghidra_mcp.runtime import SETTINGS

    return SETTINGS.symbol_path


def cdb_run(
    target: str,
    commands: list[str],
    *,
    target_arguments: str = "",
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Start the target under cdb, run the commands, quit, and return the log.

    The last command should usually be a quit command (``q`` / ``qd``), otherwise the
    run ends in a timeout with whatever output was produced by then.
    """
    cdb = find_cdb()
    if not cdb.get("found"):
        raise FileNotFoundError(cdb["hint"])
    if not Path(target).is_file():
        raise FileNotFoundError(f"no such target: {target}")

    script = "; ".join(commands)
    command_line = [cdb["path"], "-y", _symbol_path(), "-c", script, target]
    if target_arguments:
        command_line += target_arguments.split()
    started = time.time()
    try:
        result = subprocess.run(command_line, capture_output=True, text=True, errors="replace", timeout=timeout, stdin=subprocess.DEVNULL)
        output = result.stdout or ""
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return {
            "timed_out": True,
            "elapsed": round(time.time() - started, 1),
            "output_tail": partial.splitlines()[-40:],
            "note": "the target probably kept running; add q/qd as the last command or raise timeout",
        }
    return {"timed_out": False, "elapsed": round(time.time() - started, 1), "output": output}


def cdb_attach(pid: int, commands: list[str], *, timeout: float = 30.0) -> dict[str, Any]:
    """Attach cdb to a running PID, run commands, detach (qd), return the log."""
    cdb = find_cdb()
    if not cdb.get("found"):
        raise FileNotFoundError(cdb["hint"])
    script = "; ".join([*commands, "qd"])
    started = time.time()
    try:
        result = subprocess.run(
            [cdb["path"], "-p", str(pid), "-c", script],
            capture_output=True, text=True, errors="replace", timeout=timeout, stdin=subprocess.DEVNULL,
        )
        output = result.stdout or ""
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return {
            "timed_out": True,
            "elapsed": round(time.time() - started, 1),
            "output_tail": partial.splitlines()[-40:],
            "note": "attach or the commands did not finish; the process may be protected",
        }
    return {"timed_out": False, "elapsed": round(time.time() - started, 1), "output": output}


# --------------------------------------------------------------------------
# x64dbg: scripts and launching
# --------------------------------------------------------------------------
def x64dbg_script(
    kind: str,
    *,
    breakpoint: str | None = None,
    hwbp_address: str | None = None,
    commands: list[str] | None = None,
) -> dict[str, Any]:
    """Generate an x64dbg script file the Script tab can run.

    ``kind``: ``run_to_bp`` (bp symbol, erun, log), ``run_to_hwbp`` (bphws address),
    ``script`` (a raw command list). Returns the file path plus the launch command for
    ``x64dbg -a <script>`` on builds that support it.
    """
    lines: list[str] = []
    if kind == "run_to_bp":
        if not breakpoint:
            return {"error": "kind=run_to_bp needs 'breakpoint', e.g. kernel32.CreateProcessW or 0x140001000"}
        lines += [f"bp {breakpoint}", "log \"software breakpoint set\""]
    elif kind == "run_to_hwbp":
        if not hwbp_address:
            return {"error": "kind=run_to_hwbp needs 'hwbp_address', e.g. 0x140001000"}
        lines += [f"bphws {hwbp_address}, x", "log \"hardware breakpoint set\""]
    elif kind == "script":
        if not commands:
            return {"error": "kind=script needs 'commands'"}
        lines += list(commands)
    else:
        return {"error": f"unknown kind {kind!r}; use run_to_bp, run_to_hwbp, or script"}
    lines += ["erun", "log \"first break reached\""]

    script_path = Path(os.environ.get("TEMP", ".")) / f"x64dbg_{int(time.time())}.txt"
    script_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result: dict[str, Any] = {
        "script_path": str(script_path),
        "commands": lines,
        "manual": "Script tab -> Load Script -> this file -> Run. Automation builds also accept: x64dbg.exe -a <script>",
    }
    x64 = find_x64dbg()
    if x64.get("found"):
        result["launch_command"] = f'"{x64["launcher"]}" -a "{script_path}"'
    return result


def x64dbg_launch(target: str, *, script: str | None = None) -> dict[str, Any]:
    """Start x64dbg on a target and return immediately; the session itself is interactive."""
    x64 = find_x64dbg()
    if not x64.get("found"):
        raise FileNotFoundError(x64["hint"])
    if not Path(target).is_file():
        raise FileNotFoundError(f"no such target: {target}")
    launcher = x64["launcher"]
    command_line = [launcher, target]
    if script:
        command_line += ["-a", script]
    subprocess.Popen(command_line, cwd=str(Path(launcher).parent), stdin=subprocess.DEVNULL)
    return {
        "launched": True,
        "launcher": launcher,
        "target": target,
        "script": script,
        "note": "x64dbg is starting detached; drive the session in its window",
    }


# --------------------------------------------------------------------------
# hardware breakpoints: debug registers DR0-DR7 via thread contexts
# --------------------------------------------------------------------------
# DR7 encodings, per slot i: RW bits at 16+4i (00 exec, 01 write, 11 read/write),
# LEN bits at 18+4i (00 = 1 byte, 01 = 2, 11 = 4; x64 also allows 10 = 8),
# local enable bit at 2*i.
_RW_EXECUTE, _RW_WRITE, _RW_READWRITE = 0, 1, 3
_LEN_1, _LEN_2, _LEN_4, _LEN_8 = 0, 1, 3, 2

_HWBP_KINDS = {
    "execute": (_RW_EXECUTE, _LEN_1),
    "write": (_RW_WRITE, _LEN_4),
    "readwrite": (_RW_READWRITE, _LEN_4),
}


def _dr7_slot_mask(slot: int) -> int:
    """The DR7 bits one slot owns: RW, LEN, and the local-enable flag."""
    return (0b11 << (16 + 4 * slot)) | (0b11 << (18 + 4 * slot)) | (1 << (2 * slot))


def _dr7_encode(slot: int, rw: int, length: int) -> int:
    return (rw << (16 + 4 * slot)) | (length << (18 + 4 * slot)) | (1 << (2 * slot))


def _process_threads(pid: int) -> list[int]:
    snapshot = _KERNEL32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
    if not snapshot or snapshot == _INVALID_HANDLE:
        raise OSError(f"CreateToolhelp32Snapshot failed (error {ctypes.get_last_error()})")
    entry = _THREADENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    tids: list[int] = []
    try:
        ok = _KERNEL32.Thread32First(snapshot, ctypes.byref(entry))
        while ok:
            if entry.th32OwnerProcessID == pid:
                tids.append(entry.th32ThreadID)
            ok = _KERNEL32.Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        _KERNEL32.CloseHandle(snapshot)
    return tids


def _open_process_threads(pid: int) -> tuple[int, list[tuple[int, int, str | None]]]:
    """Open the process and all its threads; returns (process, [(tid, handle, error)])."""
    process = _KERNEL32.OpenProcess(_PROCESS_ALL, False, pid)
    if not process:
        return 0, []
    threads = []
    for tid in _process_threads(pid):
        thread = _KERNEL32.OpenThread(_THREAD_ALL, False, tid)
        threads.append((tid, thread, None if thread else f"OpenThread failed (error {ctypes.get_last_error()})"))
    return process, threads


def hwbp_set(pid: int, address: int, *, kind: str = "execute", slot: int = 0) -> dict[str, Any]:
    """Set a hardware breakpoint (DR0-DR3) on every thread of a process via SetThreadContext.

    ``kind``: ``execute`` (1 byte, the classic HBP), ``write`` (4 bytes), ``readwrite``
    (4 bytes). ``slot``: 0-3. Requires SeDebugPrivilege for other users' processes and
    same-architecture access (this Python is 64-bit, so 64-bit targets).
    """
    if kind not in _HWBP_KINDS:
        return {"error": f"kind must be one of {sorted(_HWBP_KINDS)}"}
    if not 0 <= slot <= 3:
        return {"error": "slot must be 0..3"}
    if kind == "execute" and address & 0x3:
        return {"error": "execute breakpoints must be 4-byte aligned (address & 3 == 0)"}

    enable_debug_privilege()
    rw, length = _HWBP_KINDS[kind]
    process, threads = _open_process_threads(pid)
    if not process:
        return {"error": f"OpenProcess({pid}) failed with error {ctypes.get_last_error()} (run elevated?)"}
    try:
        if not threads:
            return {"error": f"no threads found for pid {pid}"}
        results = []
        for tid, thread, open_error in threads:
            if open_error:
                results.append({"tid": tid, "error": open_error})
                continue
            context = _CONTEXT64()
            context.ContextFlags = _CONTEXT_FLAGS
            if not _KERNEL32.GetThreadContext(thread, ctypes.byref(context)):
                results.append({"tid": tid, "error": f"GetThreadContext failed (error {ctypes.get_last_error()})"})
                continue
            setattr(context, f"Dr{slot}", address)
            context.Dr7 &= ~_dr7_slot_mask(slot) & 0xFFFFFFFFFFFFFFFF
            context.Dr7 |= _dr7_encode(slot, rw, length) & 0xFFFFFFFFFFFFFFFF
            if _KERNEL32.SetThreadContext(thread, ctypes.byref(context)):
                results.append({"tid": tid, "set": True, "dr": slot, "address": hex(address), "kind": kind})
            else:
                results.append({"tid": tid, "error": f"SetThreadContext failed (error {ctypes.get_last_error()}) - does the target hook NtSetContextThread?"})
        failed = [r for r in results if "error" in r]
        return {
            "pid": pid,
            "slot": slot,
            "address": hex(address),
            "kind": kind,
            "threads_total": len(threads),
            "threads_set": len(results) - len(failed),
            "failed": failed or None,
        }
    finally:
        for _, thread, _ in threads:
            if thread:
                _KERNEL32.CloseHandle(thread)
        _KERNEL32.CloseHandle(process)


def hwbp_clear(pid: int, slot: int | None = None) -> dict[str, Any]:
    """Clear one hardware-breakpoint slot, or all four, on every thread of the process."""
    if slot is not None and not 0 <= slot <= 3:
        return {"error": "slot must be 0..3 or null for all"}
    enable_debug_privilege()
    process, threads = _open_process_threads(pid)
    if not process:
        return {"error": f"OpenProcess({pid}) failed with error {ctypes.get_last_error()}"}
    try:
        slots = range(4) if slot is None else [slot]
        results = []
        for tid, thread, open_error in threads:
            if open_error:
                results.append({"tid": tid, "error": open_error})
                continue
            context = _CONTEXT64()
            context.ContextFlags = _CONTEXT_FLAGS
            if not _KERNEL32.GetThreadContext(thread, ctypes.byref(context)):
                results.append({"tid": tid, "error": "GetThreadContext failed"})
                continue
            for s in slots:
                setattr(context, f"Dr{s}", 0)
                context.Dr7 &= ~_dr7_slot_mask(s) & 0xFFFFFFFFFFFFFFFF
            if _KERNEL32.SetThreadContext(thread, ctypes.byref(context)):
                results.append({"tid": tid, "cleared": list(slots)})
            else:
                results.append({"tid": tid, "error": f"SetThreadContext failed (error {ctypes.get_last_error()})"})
        return {"pid": pid, "threads_total": len(threads), "results": results}
    finally:
        for _, thread, _ in threads:
            if thread:
                _KERNEL32.CloseHandle(thread)
        _KERNEL32.CloseHandle(process)


def hwbp_list(pid: int) -> dict[str, Any]:
    """Read DR0-DR7 from every thread of the process - who has which breakpoint armed."""
    enable_debug_privilege()
    process, threads = _open_process_threads(pid)
    if not process:
        return {"error": f"OpenProcess({pid}) failed with error {ctypes.get_last_error()}"}
    try:
        entries = []
        for tid, thread, _ in threads:
            if not thread:
                continue
            context = _CONTEXT64()
            context.ContextFlags = _CONTEXT_FLAGS
            if not _KERNEL32.GetThreadContext(thread, ctypes.byref(context)):
                continue
            entries.append({
                "tid": tid,
                "dr0": hex(context.Dr0), "dr1": hex(context.Dr1),
                "dr2": hex(context.Dr2), "dr3": hex(context.Dr3),
                "dr6": hex(context.Dr6), "dr7": hex(context.Dr7),
            })
        armed = any(int(entry[f"dr{i}"], 16) for entry in entries for i in range(4))
        return {"pid": pid, "threads": entries, "any_breakpoint_armed": armed}
    finally:
        for _, thread, _ in threads:
            if thread:
                _KERNEL32.CloseHandle(thread)
        _KERNEL32.CloseHandle(process)


# --------------------------------------------------------------------------
# TitanHide client (DeviceIoControl on \\.\\TitanHide)
# --------------------------------------------------------------------------
_TITANHIDE_IOCTL_HIDE = (0x22 << 16) | (0x800 << 2) | 3  # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
_TITANHIDE_IOCTL_UNHIDE = (0x22 << 16) | (0x801 << 2) | 3

_TITANHIDE_OPTIONS = {
    "HideSystemDebugger": 1,
    "HideNtQueryInformationProcess": 2,
    "HideNtSetInformationThread": 4,
    "HideNtQueryObject": 8,
    "HideNtQuerySystemInformation": 16,
    "HideNtYieldExecution": 32,
    "HideNtGetContextThread": 64,
    "HideNtSetContextThread": 128,
    "HideNtCreateThreadEx": 256,
}


class _TITANHIDE_REQUEST(ctypes.Structure):
    _fields_ = [
        ("SystemPid", ctypes.c_uint32),
        ("ProcessId", ctypes.c_uint32),
        ("HideOptions", ctypes.c_uint32),
    ]


def _titanhide_call(ioctl: int, system_pid: int, target_pid: int, options: int) -> dict[str, Any]:
    """Send one HIDE/UNHIDE request; DeviceIoControl errors are reported verbatim."""
    enable_debug_privilege()
    handle, error = _open_device(r"\\.\TitanHide")
    if not handle:
        return {
            "sent": False,
            "win32_error": error,
            "meaning": {2: "driver not loaded", 5: "access denied: run elevated"}.get(error, "CreateFileW failed"),
            "hint": "install/start the TitanHide kernel driver first (titanhide_status shows the service state)",
        }
    try:
        request = _TITANHIDE_REQUEST(system_pid, target_pid, options)
        bytes_returned = wt.DWORD(0)
        ok = _KERNEL32.DeviceIoControl(
            handle, ioctl,
            ctypes.byref(request), ctypes.sizeof(request),
            None, 0,
            ctypes.byref(bytes_returned), None,
        )
        return {
            "sent": bool(ok),
            "win32_error": None if ok else ctypes.get_last_error(),
            "system_pid": system_pid,
            "target_pid": target_pid,
            "options": options,
        }
    finally:
        _KERNEL32.CloseHandle(handle)


def titanhide_hide(target_pid: int, options: list[str] | None = None, *, system_pid: int = 4) -> dict[str, Any]:
    """Tell TitanHide to hide a PID behind the chosen anti-anti-debug shields.

    ``options``: any of HideSystemDebugger, HideNtQueryInformationProcess,
    HideNtSetInformationThread, HideNtQueryObject, HideNtQuerySystemInformation,
    HideNtYieldExecution, HideNtGetContextThread, HideNtSetContextThread,
    HideNtCreateThreadEx. Default: all of them. ``system_pid`` is the debugger's PID
    (System=4 hides from everything).
    """
    if options is None:
        chosen = sum(_TITANHIDE_OPTIONS.values())
        used = list(_TITANHIDE_OPTIONS)
    else:
        unknown = [o for o in options if o not in _TITANHIDE_OPTIONS]
        if unknown:
            return {"error": f"unknown options {unknown}; valid: {sorted(_TITANHIDE_OPTIONS)}"}
        chosen = sum(_TITANHIDE_OPTIONS[o] for o in options)
        used = options
    if not chosen:
        return {"error": "empty option set"}
    result = _titanhide_call(_TITANHIDE_IOCTL_HIDE, system_pid, target_pid, chosen)
    result["applied_options"] = used
    return result


def titanhide_unhide(target_pid: int, *, system_pid: int = 4) -> dict[str, Any]:
    """Remove every TitanHide shield from a PID."""
    return _titanhide_call(_TITANHIDE_IOCTL_UNHIDE, system_pid, target_pid, 0)


# --------------------------------------------------------------------------
# usermode thread hiding (TitanHide's main trick without a kernel driver)
# --------------------------------------------------------------------------
_THREAD_HIDE_FROM_DEBUGGER = 0x11  # ThreadHideFromDebugger
_NTDLL = ctypes.WinDLL("ntdll", use_last_error=True)
_NtSetInformationThread = _NTDLL.NtSetInformationThread
_NtSetInformationThread.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong]
_NtSetInformationThread.restype = ctypes.c_long


def _process_threads_direct(pid: int) -> list[int]:
    """Thread ids of a process, without needing an opened process handle first."""
    return _process_threads(pid)


def stealth_hide_threads(pid: int, *, unhide: bool = False) -> dict[str, Any]:
    """Hide every thread of a process from debuggers via ThreadHideFromDebugger.

    This is the usermode half of TitanHide: calling NtSetInformationThread with
    ThreadHideFromDebugger on a target's threads makes debug events from those threads
    invisible to any debugger that attaches later. Works from this process with
    SeDebugPrivilege; no driver, no Secure Boot, no reboot. The flag is one-way inside
    the kernel - it cannot be cleared afterwards, which is why ``unhide`` reports that
    instead of pretending.
    """
    enable_debug_privilege()
    process = _KERNEL32.OpenProcess(_PROCESS_ALL, False, pid)
    if not process:
        return {"error": f"OpenProcess({pid}) failed (error {ctypes.get_last_error()}); run elevated"}
    try:
        if unhide:
            return {
                "pid": pid,
                "note": "ThreadHideFromDebugger is one-way and cannot be cleared; restart the process instead",
            }
        tids = _process_threads(pid)
        results = []
        for tid in tids:
            thread = _KERNEL32.OpenThread(_THREAD_ALL, False, tid)
            if not thread:
                results.append({"tid": tid, "error": f"OpenThread failed ({ctypes.get_last_error()})"})
                continue
            try:
                status = _NtSetInformationThread(thread, _THREAD_HIDE_FROM_DEBUGGER, None, 0)
                results.append({"tid": tid, "hidden": status == 0, "ntstatus": hex(status & 0xFFFFFFFF)})
            finally:
                _KERNEL32.CloseHandle(thread)
        failed = [r for r in results if "error" in r]
        return {
            "pid": pid,
            "threads_total": len(tids),
            "threads_hidden": len(results) - len(failed),
            "results": results,
            "note": "ThreadHideFromDebugger set; existing debuggers keep their events, new ones see nothing from these threads",
        }
    finally:
        _KERNEL32.CloseHandle(process)


# --------------------------------------------------------------------------
# kernel / boot debug state, drivers
# --------------------------------------------------------------------------
def _sc_query(service: str) -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["sc", "query", service], capture_output=True, text=True, errors="replace", timeout=15, stdin=subprocess.DEVNULL
        )
        output = result.stdout or ""
        state = next((line.split(":", 1)[1].strip() for line in output.splitlines() if "STATE" in line.upper()), None)
        return {"queried": True, "exists": result.returncode == 0, "state": state}
    except Exception as exc:
        return {"queried": False, "error": str(exc)}


def kernel_debug_info() -> dict[str, Any]:
    """Boot-time debug state: bcdedit /dbgsettings, test signing, TitanHide service."""
    report: dict[str, Any] = {"elevated": is_admin(), "titanhide_service": _sc_query("TitanHide")}
    try:
        result = subprocess.run(["bcdedit", "/dbgsettings"], capture_output=True, text=True, errors="replace", timeout=15, stdin=subprocess.DEVNULL)
        report["dbgsettings"] = result.stdout.strip() if result.returncode == 0 else f"(bcdedit failed: run elevated) {result.stderr.strip()[:200]}"
    except FileNotFoundError:
        report["dbgsettings"] = "bcdedit.exe not on PATH"
    except Exception as exc:
        report["dbgsettings"] = f"error: {exc}"
    try:
        result = subprocess.run(
            ["bcdedit", "/enum", "{current}"], capture_output=True, text=True, errors="replace", timeout=15, stdin=subprocess.DEVNULL
        )
        text = result.stdout if result.returncode == 0 else ""
        report["kernel_debug_enabled"] = "debug yes" in text.lower() if text else None
        report["testsigning_enabled"] = "testsigning yes" in text.lower() if text else None
        if not text and result.returncode != 0:
            report["note"] = "bcdedit /enum needs elevation; kernel_debug/testsigning unknown"
    except Exception as exc:
        report["kernel_debug_enabled"] = None
        report["note"] = f"bcdedit error: {exc}"
    return report


def drivers_list(filter: str | None = None) -> dict[str, Any]:
    """List loaded kernel drivers via driverquery, optionally filtered by name/module."""
    try:
        result = subprocess.run(
            ["driverquery", "/fo", "csv", "/nh"], capture_output=True, text=True, errors="replace", timeout=60, stdin=subprocess.DEVNULL
        )
    except FileNotFoundError:
        return {"error": "driverquery.exe not on PATH"}
    if result.returncode != 0:
        return {"error": f"driverquery failed: {(result.stderr or result.stdout)[:200]}"}
    rows = []
    for line in (result.stdout or "").splitlines():
        if not line.strip():
            continue
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) < 3:
            continue
        rows.append({"module": parts[0], "type": parts[1] if len(parts) > 1 else "", "state": parts[-2] if len(parts) > 3 else parts[2]})
    if filter:
        needle = filter.lower()
        rows = [r for r in rows if needle in r["module"].lower() or needle in r.get("type", "").lower()]
    return {"count": len(rows), "drivers": rows}


# --------------------------------------------------------------------------
# x64dbg-automate plugin: install at runtime, so xdbg_start can heal itself
# --------------------------------------------------------------------------
_X64DBG_AUTOMATE_RELEASE = "https://github.com/dariushoule/x64dbg-automate/releases/download/v0.8.1-ghost_fungus"


def install_x64dbg_plugin() -> dict[str, Any]:
    """Download and drop x64dbg-automate.dp64/dp32 into the debugger's plugins folder.

    Runtime self-healing for the xdbg_* tools: when xdbg_start reports the plugin
    missing, call this once - no reinstall, no manual download.
    """
    import tempfile
    import urllib.request
    import zipfile

    from pathlib import Path as _Path

    override = os.environ.get("X64DBG_DIR")
    roots = ([override] if override else []) + [
        "C:/x64dbg/release", "C:/Program Files/x64dbg/release",
        "C:/Program Files (x86)/x64dbg/release", "D:/x64dbg/release", "E:/x64dbg/release",
    ]
    root = next((_Path(r) for r in roots if _Path(r).is_dir()), None)
    if root is None:
        return {"installed": False, "error": "x64dbg not found; set X64DBG_DIR"}

    archive = Path(tempfile.gettempdir()) / "x64dbg_automate_plugin.zip"
    installed = []
    for asset, plugin_files, plugin_dir in (
        ("release64-0.8.1-ghost_fungus.zip", ("x64dbg-automate.dp64", "libzmq-mt-4_3_5.dll"), root / "x64" / "plugins"),
        ("release32-0.8.1-ghost_fungus.zip", ("x64dbg-automate.dp32", "libzmq-mt-4_3_5.dll"), root / "x32" / "plugins"),
    ):
        marker = plugin_dir / plugin_files[0]
        if marker.is_file():
            installed.append(str(marker))
            continue
        try:
            urllib.request.urlretrieve(f"{_X64DBG_AUTOMATE_RELEASE}/{asset}", archive)
            plugin_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(archive) as bundle:
                for name in bundle.namelist():
                    if _Path(name).name in plugin_files:
                        (plugin_dir / _Path(name).name).write_bytes(bundle.read(name))
                        installed.append(str(plugin_dir / _Path(name).name))
            archive.unlink(missing_ok=True)
        except Exception as exc:
            return {"installed": False, "error": f"download failed: {exc}",
                    "manual": f"copy {plugin_files[0]} into {plugin_dir} from {_X64DBG_AUTOMATE_RELEASE}"}
    return {"installed": True, "files": installed,
            "note": "restart x64dbg if it is running, then retry xdbg_start"}
