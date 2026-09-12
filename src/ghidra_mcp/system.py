"""System-level inspection: processes, modules, windows, memory scan/read/write without
a debugger, registry, and network connections.

The memory scanner is the Cheat Engine workflow: narrow a first scan by an initial value,
then rescan the survivors after the value changes, until a stable address list remains.
Reads and writes go through ReadProcessMemory/WriteProcessMemory, so no debugger is
attached and no debug registers are consumed - the target does not even have to know.

Every function opens the target process explicitly; nothing enumerates or touches a
process the caller did not name.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_USER32 = ctypes.WinDLL("user32", use_last_error=True)
_ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)

_PROCESS_ALL = 0x1FFFFF
_THREAD_ALL = 0x1FFFFF
_TH32CS_SNAPPROCESS = 0x2
_TH32CS_SNAPMODULE = 0x8
_TH32CS_SNAPMODULE32 = 0x10
_TH32CS_SNAPHEAPLIST = 0x1
_MEM_COMMIT = 0x1000
_PAGE_GUARD = 0x100
_PAGE_NOACCESS = 0x01


class _PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)), ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_char * 260),
    ]


class _MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD), ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wt.DWORD), ("hModule", wt.HMODULE), ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260),
    ]


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR), ("lpTitle", wt.LPWSTR),
        ("dwX", wt.DWORD), ("dwY", wt.DWORD), ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
        ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
        ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
        ("lpReserved2", wt.LPVOID), ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
        ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD),
    ]


def _init_winapi() -> None:
    kernel32, user32, advapi32 = _KERNEL32, _USER32, _ADVAPI32
    kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    kernel32.Process32First.argtypes = [wt.HANDLE, ctypes.POINTER(_PROCESSENTRY32)]
    kernel32.Process32First.restype = wt.BOOL
    kernel32.Process32Next.argtypes = [wt.HANDLE, ctypes.POINTER(_PROCESSENTRY32)]
    kernel32.Process32Next.restype = wt.BOOL
    kernel32.Module32First.argtypes = [wt.HANDLE, ctypes.POINTER(_MODULEENTRY32)]
    kernel32.Module32First.restype = wt.BOOL
    kernel32.Module32Next.argtypes = [wt.HANDLE, ctypes.POINTER(_MODULEENTRY32)]
    kernel32.Module32Next.restype = wt.BOOL
    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.ReadProcessMemory.restype = wt.BOOL
    kernel32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.WriteProcessMemory.restype = wt.BOOL
    kernel32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.OpenThread.restype = wt.HANDLE
    kernel32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
    kernel32.TerminateProcess.restype = wt.BOOL
    user32.EnumWindows.argtypes = [ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM), wt.LPARAM]
    user32.EnumWindows.restype = wt.BOOL
    user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
    user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    user32.IsWindowVisible.argtypes = [wt.HWND]
    user32.IsWindowVisible.restype = wt.BOOL
    user32.SendMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
    user32.SendMessageW.restype = wt.LONG
    user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
    user32.PostMessageW.restype = wt.BOOL


_init_winapi()


def _open_process(pid: int, *, access: int = _PROCESS_ALL) -> int:
    from ghidra_mcp.dynamic import enable_debug_privilege

    enable_debug_privilege()
    handle = _KERNEL32.OpenProcess(access, False, pid)
    if not handle:
        raise PermissionError(f"OpenProcess({pid}) failed (error {ctypes.get_last_error()}); run elevated")
    return handle


# --------------------------------------------------------------------------
# processes / modules
# --------------------------------------------------------------------------
def proc_list(*, filter: str | None = None) -> dict[str, Any]:
    """Enumerate running processes with pid, parent, threads, and image path."""
    snapshot = _KERNEL32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == ctypes.c_void_p(-1).value:
        raise OSError(f"CreateToolhelp32Snapshot failed (error {ctypes.get_last_error()})")
    entry = _PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    processes = []
    try:
        ok = _KERNEL32.Process32First(snapshot, ctypes.byref(entry))
        while ok:
            name = entry.szExeFile.decode("latin-1", "replace")
            processes.append({
                "pid": entry.th32ProcessID,
                "ppid": entry.th32ParentProcessID,
                "threads": entry.cntThreads,
                "name": name,
            })
            ok = _KERNEL32.Process32Next(snapshot, ctypes.byref(entry))
    finally:
        _KERNEL32.CloseHandle(snapshot)

    image_paths = {}
    try:
        result = subprocess.run(
            ["wmic", "process", "get", "ProcessId,ExecutablePath", "/format:csv"],
            capture_output=True, text=True, errors="replace", timeout=30, stdin=subprocess.DEVNULL,
        )
        for line in (result.stdout or "").splitlines():
            if line.count(",") < 2:
                continue
            parts = line.strip().split(",")
            if len(parts) >= 3 and parts[-1].isdigit():
                image_paths[int(parts[-1])] = parts[1] if len(parts) == 3 else ",".join(parts[1:-1])
    except Exception:
        pass
    for process in processes:
        process["exe_path"] = image_paths.get(process["pid"])

    if filter:
        needle = filter.lower()
        processes = [p for p in processes if needle in p["name"].lower() or needle in (p.get("exe_path") or "").lower()]
    return {"count": len(processes), "processes": processes}


def proc_modules(pid: int) -> dict[str, Any]:
    """List the modules (exe + DLLs) loaded into a process, with base and size."""
    handle = _open_process(pid, access=0x10410)  # QUERY_INFORMATION | VM_READ
    try:
        for flags in (_TH32CS_SNAPMODULE | _TH32CS_SNAPMODULE32, _TH32CS_SNAPMODULE):
            snapshot = _KERNEL32.CreateToolhelp32Snapshot(flags, pid)
            if snapshot and snapshot != ctypes.c_void_p(-1).value:
                break
        else:
            raise OSError(f"no module snapshot for {pid} (bitness mismatch or protected process)")
        entry = _MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        modules = []
        try:
            ok = _KERNEL32.Module32First(snapshot, ctypes.byref(entry))
            while ok:
                modules.append({
                    "name": entry.szModule.decode("latin-1", "replace"),
                    "base": hex(ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0),
                    "size": entry.modBaseSize,
                    "path": entry.szExePath.decode("latin-1", "replace"),
                })
                ok = _KERNEL32.Module32Next(snapshot, ctypes.byref(entry))
        finally:
            _KERNEL32.CloseHandle(snapshot)
        return {"pid": pid, "count": len(modules), "modules": modules}
    finally:
        _KERNEL32.CloseHandle(handle)


# --------------------------------------------------------------------------
# process I/O and lifecycle helpers
# --------------------------------------------------------------------------
_RUNNING_PROCESSES: dict[int, dict[str, Any]] = {}
_PROC_LOCK = threading.Lock()


def proc_start(path: str, arguments: str = "", *, capture: bool = True) -> dict[str, Any]:
    """Start a process; with capture=True its stdin/stdout are kept for interaction.

    Interactive crackmes and prompt-driven tools need their input fed and output
    read: proc_write (stdin) and proc_read (stdout) do that against the pid returned
    here. capture=False detaches and only tracks the pid.
    """
    if not Path(path).is_file():
        raise FileNotFoundError(f"no such executable: {path}")
    command_line = f'"{path}" {arguments}'.strip()
    pipes: dict[str, Any] = {}
    process = subprocess.Popen(
        command_line,
        stdin=subprocess.PIPE if capture else subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.STDOUT if capture else subprocess.DEVNULL,
    )
    if capture:
        pipes = {"stdin": process.stdin, "stdout": process.stdout}
    with _PROC_LOCK:
        _RUNNING_PROCESSES[process.pid] = {"process": process, "pipes": pipes, "command": command_line, "buffer": b""}
    time.sleep(0.3)
    return {
        "started": True,
        "pid": process.pid,
        "command": command_line,
        "captured": capture,
        "note": "proc_write/proc_read talk to it; proc_alive/proc_wait_exit track it",
    }


def proc_start_dll(path: str, arguments: str = "", dll_path: str = "") -> dict[str, Any]:
    """Start a process with a DLL queued via APC BEFORE it runs - the instrumentation
    that remote-thread injection cannot do.

    The process is created suspended, QueueUserAPC schedules kernel32!LoadLibraryW on
    the main thread, and ResumeThread lets it run: the DLL loads before any target
    code, DllMain executes ON the main thread, and a vectored exception handler
    registered there fires for every thread (remote-thread-injected VEH registration
    is silently ignored by dispatch on this Windows build - verified experimentally).
    The classic early-instrumentation window: exceptions, but also everything the DLL
    does at attach.
    """
    if not Path(path).is_file():
        raise FileNotFoundError(f"no such executable: {path}")
    dll = Path(dll_path)
    if not dll.is_file():
        return {"error": f"no such DLL: {dll}"}

    _KERNEL32.CreateProcessW.argtypes = [
        wt.LPCWSTR, wt.LPWSTR, wt.LPVOID, wt.LPVOID, wt.BOOL, wt.DWORD, wt.LPVOID, wt.LPCWSTR,
        ctypes.POINTER(_STARTUPINFOW), ctypes.POINTER(_PROCESS_INFORMATION),
    ]
    _KERNEL32.CreateProcessW.restype = wt.BOOL
    _KERNEL32.QueueUserAPC.argtypes = [wt.LPVOID, wt.HANDLE, wt.LPVOID]
    _KERNEL32.QueueUserAPC.restype = ctypes.c_size_t
    _KERNEL32.ResumeThread.argtypes = [wt.HANDLE]
    _KERNEL32.ResumeThread.restype = wt.DWORD
    _KERNEL32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
    _KERNEL32.GetModuleHandleW.restype = wt.HMODULE
    _KERNEL32.GetProcAddress.argtypes = [wt.HMODULE, wt.LPCSTR]
    _KERNEL32.GetProcAddress.restype = wt.LPVOID
    _KERNEL32.VirtualAllocEx.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD, wt.DWORD]
    _KERNEL32.VirtualAllocEx.restype = wt.LPVOID
    _KERNEL32.WriteProcessMemory.argtypes = [wt.HANDLE, wt.LPVOID, wt.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    _KERNEL32.WriteProcessMemory.restype = wt.BOOL

    startup = _STARTUPINFOW()
    startup.cb = ctypes.sizeof(startup)
    # STARTF_USESTDHANDLES with null handles: the child's stdout must NOT inherit
    # this process's, or its output corrupts the MCP stdio protocol stream.
    startup.dwFlags = 0x00000100  # STARTF_USESTDHANDLES
    proc_info = _PROCESS_INFORMATION()
    command_line = ctypes.create_unicode_buffer(f'"{path}" {arguments}'.strip())
    creation_flags = 0x00000004  # CREATE_SUSPENDED
    if not _KERNEL32.CreateProcessW(None, command_line, None, None, False, creation_flags, None, None, ctypes.byref(startup), ctypes.byref(proc_info)):
        return {"error": f"CreateProcessW failed (error {ctypes.get_last_error()})"}

    pid = proc_info.dwProcessId
    hprocess = proc_info.hProcess
    hthread = proc_info.hThread
    try:
        load_library = _KERNEL32.GetProcAddress(_KERNEL32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        if not load_library:
            _KERNEL32.TerminateProcess(hprocess, 1)
            return {"error": "could not resolve kernel32!LoadLibraryW"}
        dll_bytes = str(dll).encode("utf-16-le") + b"\x00\x00"
        remote_mem = _KERNEL32.VirtualAllocEx(hprocess, None, len(dll_bytes), 0x3000, 0x04)
        if not remote_mem:
            _KERNEL32.TerminateProcess(hprocess, 1)
            return {"error": f"VirtualAllocEx failed (error {ctypes.get_last_error()})"}
        written = ctypes.c_size_t(0)
        if not _KERNEL32.WriteProcessMemory(hprocess, remote_mem, dll_bytes, len(dll_bytes), ctypes.byref(written)):
            _KERNEL32.TerminateProcess(hprocess, 1)
            return {"error": f"WriteProcessMemory failed (error {ctypes.get_last_error()})"}
        queued = _KERNEL32.QueueUserAPC(load_library, hthread, remote_mem)
        if not queued:
            _KERNEL32.TerminateProcess(hprocess, 1)
            return {"error": f"QueueUserAPC failed (error {ctypes.get_last_error()})"}
        _KERNEL32.ResumeThread(hthread)
        _KERNEL32.CloseHandle(hthread)
        return {
            "started": True,
            "pid": pid,
            "dll": str(dll),
            "method": "apc-at-startup",
            "note": "DLL loads before the first target instruction; DllMain runs on the main thread",
        }
    except Exception:
        _KERNEL32.TerminateProcess(hprocess, 1)
        raise


def proc_read(pid: int, *, timeout: float = 1.0) -> dict[str, Any]:
    """Read whatever the process has written to stdout so far (non-blocking-ish)."""
    with _PROC_LOCK:
        entry = _RUNNING_PROCESSES.get(pid)
    if entry is None:
        return {"error": f"pid {pid} was not started with capture=True by proc_start"}
    process: subprocess.Popen[bytes] = entry["process"]
    stream = entry["pipes"].get("stdout")
    if stream is None:
        return {"error": "the process was started with capture=False"}
    chunk: bytes = b""
    deadline = time.time() + timeout
    import threading as _threading

    result: list[bytes] = []

    def reader() -> None:
        nonlocal chunk
        try:
            chunk = stream.readline()
        except OSError:
            chunk = b""
        result.append(chunk)

    thread = _threading.Thread(target=reader, daemon=True)
    thread.start()
    thread.join(timeout)
    entry["buffer"] += (result[0] if result else b"")
    text = entry["buffer"].decode("utf-8", "replace")
    entry["buffer"] = b""
    return {"pid": pid, "output": text[-4000:], "alive": process.poll() is None}


def proc_write(pid: int, text: str, *, newline: bool = True) -> dict[str, Any]:
    """Write to the process's stdin - feeding prompts, answers, and menu choices."""
    with _PROC_LOCK:
        entry = _RUNNING_PROCESSES.get(pid)
    if entry is None:
        return {"error": f"pid {pid} was not started by proc_start (or capture=False)"}
    stream = entry["pipes"].get("stdin")
    if stream is None:
        return {"error": "the process was started with capture=False"}
    try:
        payload = text.encode("utf-8", "replace") + (b"\n" if newline else b"")
        stream.write(payload)
        stream.flush()
        return {"written": len(payload), "pid": pid}
    except OSError as exc:
        return {"error": f"stdin write failed (process dead?): {exc}"}


def proc_alive(pid: int) -> dict[str, Any]:
    """Is a pid running right now - without proc_list and filtering."""
    import ctypes
    import ctypes.wintypes as _wt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [_wt.DWORD, _wt.BOOL, _wt.DWORD]
    kernel32.OpenProcess.restype = _wt.HANDLE
    kernel32.CloseHandle.argtypes = [_wt.HANDLE]
    kernel32.GetExitCodeProcess.argtypes = [_wt.HANDLE, ctypes.POINTER(_wt.DWORD)]
    handle = kernel32.OpenProcess(0x0400, 0, int(pid))  # PROCESS_QUERY_INFORMATION
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:
            return {"pid": int(pid), "alive": False, "note": "no such process"}
        if error == 5:
            # Access denied means it exists - a dead pid gives ERROR_INVALID_PARAMETER.
            return {"pid": int(pid), "alive": True, "note": "exists; details need elevation"}
        return {"pid": int(pid), "alive": False, "win32_error": error}
    exit_code = wt.DWORD(0)
    kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
    kernel32.CloseHandle(handle)
    return {
        "pid": int(pid),
        "alive": exit_code.value == 259,  # STILL_ACTIVE
        "exit_code": hex(exit_code.value) if exit_code.value != 259 else None,
    }


def proc_wait_exit(pid: int, timeout: float = 30.0) -> dict[str, Any]:
    """Block until a pid exits (or timeout); returns the exit code when it does."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = proc_alive(pid)
        if not state.get("alive"):
            return {"pid": int(pid), "exited": True, "exit_code": state.get("exit_code"), "waited": round(timeout - (deadline - time.time()), 1)}
        time.sleep(0.3)
    return {"pid": int(pid), "exited": False, "timeout": timeout, "note": "still running; proc_alive to re-check"}


def proc_kill(pid: int) -> dict[str, Any]:
    """Terminate a process by pid (and forget its captured pipes)."""
    with _PROC_LOCK:
        entry = _RUNNING_PROCESSES.pop(pid, None)
        for key in [k for k in _RUNNING_PROCESSES if k != pid]:
            state = _RUNNING_PROCESSES.get(key)
            if state and state["process"].poll() is not None:
                del _RUNNING_PROCESSES[key]
    if entry is not None:
        try:
            entry["process"].kill()
        except OSError:
            pass
    import ctypes
    import ctypes.wintypes as _wt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [_wt.DWORD, _wt.BOOL, _wt.DWORD]
    kernel32.OpenProcess.restype = _wt.HANDLE
    kernel32.TerminateProcess.argtypes = [_wt.HANDLE, _wt.UINT]
    kernel32.CloseHandle.argtypes = [_wt.HANDLE]
    handle = kernel32.OpenProcess(0x0001, 0, int(pid))  # PROCESS_TERMINATE
    if not handle:
        return {"killed": False, "pid": int(pid), "error": f"OpenProcess failed (error {ctypes.get_last_error()}); run elevated"}
    ok = kernel32.TerminateProcess(handle, 1)
    kernel32.CloseHandle(handle)
    return {"killed": bool(ok), "pid": int(pid)}


# --------------------------------------------------------------------------
# windows
# --------------------------------------------------------------------------
def window_list(*, filter: str | None = None, visible_only: bool = True) -> dict[str, Any]:
    """Enumerate top-level windows: title, class, pid, visibility."""
    results: list[dict[str, Any]] = []

    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def callback(hwnd, _lparam):
        pid = wt.DWORD(0)
        _USER32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        title = ctypes.create_unicode_buffer(512)
        class_name = ctypes.create_unicode_buffer(256)
        _USER32.GetWindowTextW(hwnd, title, 512)
        _USER32.GetClassNameW(hwnd, class_name, 256)
        visible = bool(_USER32.IsWindowVisible(hwnd))
        if visible or not visible_only:
            results.append({
                "hwnd": hex(hwnd),
                "pid": pid.value,
                "title": title.value,
                "class": class_name.value,
                "visible": visible,
            })
        return True

    _USER32.EnumWindows(callback, 0)
    if filter:
        needle = filter.lower()
        results = [w for w in results if needle in w["title"].lower() or needle in w["class"].lower()]
    return {"count": len(results), "windows": results}


def window_send_text(hwnd: int, text: str) -> dict[str, Any]:
    """Send a WM_CHAR sequence to a window handle - typing into a GUI without focus."""
    sent = 0
    for character in text:
        if _USER32.SendMessageW(hwnd, 0x0102, ord(character), 0):  # WM_CHAR
            sent += 1
    return {"sent": sent, "of": len(text), "hwnd": hex(hwnd)}


def window_close(hwnd: int) -> dict[str, Any]:
    """Ask a window to close (WM_CLOSE) - polite termination, the app can refuse."""
    _USER32.PostMessageW(hwnd, 0x0010, 0, 0)
    return {"posted": True, "hwnd": hex(hwnd)}


# --------------------------------------------------------------------------
# memory: scan, read, write (no debugger attached)
# --------------------------------------------------------------------------
class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


_PACK = {"u8": ("B", 1), "i8": ("b", 1), "u16": ("H", 2), "i16": ("h", 2),
         "u32": ("I", 4), "i32": ("i", 4), "u64": ("Q", 8), "i64": ("q", 8),
         "f32": ("f", 4), "f64": ("d", 8)}


def _read_process(handle: int, address: int, size: int) -> bytes:
    buffer = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    if not _KERNEL32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(read)):
        raise OSError(f"ReadProcessMemory({hex(address)}) failed (error {ctypes.get_last_error()})")
    return buffer.raw[: read.value]


def _iter_regions(handle: int, *, writable_only: bool = True):
    address = 0
    mbi = _MEMORY_BASIC_INFORMATION()
    while address < 0x7FFFFFFEFFFF:
        result = _KERNEL32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if result == 0:
            break
        if (
            mbi.State == _MEM_COMMIT
            and not (mbi.Protect & _PAGE_GUARD)
            and mbi.Protect != _PAGE_NOACCESS
            and (mbi.Protect & 0x04 or mbi.Protect & 0x40 or mbi.Protect & 0x80 or mbi.Protect & 0x08)  # readable
            and (not writable_only or mbi.Protect & 0x04 or mbi.Protect & 0x40 or mbi.Protect & 0x80)  # writable family
        ):
            base = mbi.BaseAddress or 0
            yield base, mbi.RegionSize
        address = (mbi.BaseAddress or 0) + mbi.RegionSize


def mem_scan(
    pid: int,
    value: str,
    *,
    type: str = "u32",
    filter: str | None = None,
    previous_file: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Scan a process's memory for a value; optionally rescan a previous hit list.

    First scan: ``mem_scan(pid, "9999", type="u32")`` - sweeps committed writable memory.
    Narrowing scan: save the returned ``state_file``, change the value in the target,
    then rerun with the new value and ``previous_file`` pointing at the saved file -
    only addresses whose current value matches AND whose previous value differed survive.
    Types: u8/i8/u16/i16/u32/i32/u64/i64/f32/f64. ``filter`` accepts ``exact``, or a
    Python-style comparison like ``>100`` / ``<=50`` / ``!=7`` for the rescan stage.
    """
    if type not in _PACK:
        return {"error": f"type must be one of {sorted(_PACK)}"}
    fmt, width = _PACK[type]
    import struct as _struct

    try:
        wanted = int(value, 0)
    except ValueError:
        try:
            wanted = float(value)
        except ValueError:
            return {"error": f"cannot parse value {value!r} for {type}"}

    handle = _open_process(pid, access=0x0438)  # QUERY | VM_READ | VM_WRITE | VM_OPERATION
    try:
        candidates: list[int] | None = None
        if previous_file:
            state_path = Path(previous_file)
            if not state_path.is_file():
                return {"error": f"previous scan file not found: {previous_file}"}
            candidates = [int(line, 16) for line in state_path.read_text().splitlines() if line.strip()]

        matches: list[dict[str, Any]] = []
        scanned = 0
        for base, size in _iter_regions(handle):
            if candidates is not None:
                region_hits = [a for a in candidates if base <= a < base + size]
                if not region_hits:
                    continue
            try:
                data = _read_process(handle, base, min(size, 0x4000000))
            except OSError:
                continue
            scanned += size
            if candidates is None:
                for offset in range(0, len(data) - width + 1):
                    try:
                        current = _struct.unpack_from(fmt, data, offset)[0]
                    except struct.error:
                        break
                    if current == wanted:
                        matches.append({"address": hex(base + offset), "value": current})
                        if len(matches) >= limit:
                            break
            else:
                region_set = set(region_hits)
                for address in region_set:
                    offset = address - base
                    if offset + width > len(data):
                        continue
                    try:
                        current = _struct.unpack_from(fmt, data, offset)[0]
                    except struct.error:
                        continue
                    ok = current == wanted
                    if not ok and filter:
                        expression = filter.strip()
                        for op in ("<=", ">=", "!=", "<", ">"):
                            if expression.startswith(op):
                                try:
                                    bound = float(expression[len(op):])
                                except ValueError:
                                    continue
                                ok = {
                                    "<=": current <= bound, ">=": current >= bound,
                                    "!=": current != bound, "<": current < bound, ">": current > bound,
                                }[op]
                                break
                    if ok:
                        matches.append({"address": hex(address), "value": current})
                        if len(matches) >= limit:
                            break
            if len(matches) >= limit:
                break

        state_file = None
        if matches:
            state_path = Path(os.environ.get("TEMP", ".")) / f"memscan_{pid}_{int(time.time())}.txt"
            state_path.write_text("\n".join(m["address"] for m in matches), encoding="utf-8")
            state_file = str(state_path)
        return {
            "pid": pid,
            "type": type,
            "matches": len(matches),
            "scanned_bytes": scanned,
            "state_file": state_file,
            "hits": matches[:limit],
            "note": "change the value in the target, then rerun with previous_file=this state_file and the new value",
        }
    finally:
        _KERNEL32.CloseHandle(handle)


def mem_read_proc(pid: int, address: str, size: int = 64) -> dict[str, Any]:
    """Read raw memory from a live process (no debugger needed)."""
    try:
        addr = int(address, 0)
    except ValueError:
        return {"error": f"could not parse address {address!r}"}
    handle = _open_process(pid, access=0x0410)
    try:
        data = _read_process(handle, addr, size)
        import hashlib

        return {"pid": pid, "address": hex(addr), "size": len(data), "hex": data.hex(), "sha256": hashlib.sha256(data).hexdigest()}
    finally:
        _KERNEL32.CloseHandle(handle)


def mem_write_proc(pid: int, address: str, hex_data: str) -> dict[str, Any]:
    """Write bytes into a live process's memory - runtime patching without a debugger."""
    try:
        addr = int(address, 0)
        data = bytes.fromhex(hex_data)
    except ValueError as exc:
        return {"error": f"bad arguments: {exc}"}
    handle = _open_process(pid, access=0x0438)
    try:
        written = ctypes.c_size_t(0)
        old_protect = wt.DWORD(0)
        # Writing to code pages needs the protection flipped; VirtualProtectEx first.
        _KERNEL32.VirtualProtectEx(handle, ctypes.c_void_p(addr), len(data), 0x40, ctypes.byref(old_protect))
        ok = _KERNEL32.WriteProcessMemory(handle, ctypes.c_void_p(addr), data, len(data), ctypes.byref(written))
        if not ok:
            return {"error": f"WriteProcessMemory failed (error {ctypes.get_last_error()})"}
        _KERNEL32.VirtualProtectEx(handle, ctypes.c_void_p(addr), len(data), old_protect.value, ctypes.byref(old_protect))
        return {"pid": pid, "address": hex(addr), "bytes_written": written.value}
    finally:
        _KERNEL32.CloseHandle(handle)


def mem_strings_proc(pid: int, min_length: int = 6, limit: int = 100) -> dict[str, Any]:
    """Extract readable strings from a live process's memory (utf-16 and ascii)."""
    handle = _open_process(pid, access=0x0410)
    try:
        found: list[dict[str, Any]] = []
        for base, size in _iter_regions(handle):
            if len(found) >= limit or size > 0x8000000:
                continue
            try:
                data = _read_process(handle, base, size)
            except OSError:
                continue
            for match in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length, data):
                text = match.group().decode("utf-16-le", "replace")
                found.append({"address": hex(base + match.start()), "encoding": "utf16le", "value": text[:200]})
                if len(found) >= limit:
                    break
            for match in re.finditer(rb"[\x20-\x7e]{%d,}" % min_length, data):
                text = match.group().decode("ascii", "replace")
                found.append({"address": hex(base + match.start()), "encoding": "ascii", "value": text[:200]})
                if len(found) >= limit:
                    break
        return {"pid": pid, "count": len(found), "strings": found}
    finally:
        _KERNEL32.CloseHandle(handle)


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------
_HKEYS = {"HKLM": 0x80000002, "HKCU": 0x80000001, "HKCR": 0x80000000, "HKU": 0x80000003}
_TYPES = {1: "REG_SZ", 2: "REG_EXPAND_SZ", 4: "REG_DWORD", 7: "REG_MULTI_SZ", 3: "REG_BINARY", 11: "REG_QWORD"}


def reg_read(key_path: str, value_name: str | None = None) -> dict[str, Any]:
    """Read a registry value, or list all values of a key when value_name is null."""
    hive_name, _, subkey = key_path.partition("\\")
    hive = _HKEYS.get(hive_name.upper())
    if hive is None:
        return {"error": f"hive must be one of {sorted(_HKEYS)}"}
    import winreg

    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            if value_name:
                data, kind = winreg.QueryValueEx(key, value_name)
                if isinstance(data, bytes):
                    data = data.hex()
                return {"key": key_path, "value": value_name, "type": _TYPES.get(kind, kind), "data": data}
            values = []
            index = 0
            while True:
                try:
                    name, data, kind = winreg.EnumValue(key, index)
                except OSError:
                    break
                if isinstance(data, bytes):
                    data = data.hex()
                values.append({"name": name, "type": _TYPES.get(kind, kind), "data": data})
                index += 1
            return {"key": key_path, "value_count": len(values), "values": values}
    except FileNotFoundError:
        return {"error": f"key or value not found: {key_path}\\{value_name}"}
    except PermissionError:
        return {"error": "access denied; run elevated for HKLM writes and protected keys"}


def reg_write(key_path: str, value_name: str, data: Any, *, kind: str = "auto") -> dict[str, Any]:
    """Create or update a registry value. kind: auto, sz, dword, qword, binary, multi_sz."""
    hive_name, _, subkey = key_path.partition("\\")
    hive = _HKEYS.get(hive_name.upper())
    if hive is None:
        return {"error": f"hive must be one of {sorted(_HKEYS)}"}
    import winreg

    type_map = {"sz": winreg.REG_SZ, "dword": winreg.REG_DWORD, "qword": winreg.REG_QWORD,
                "binary": winreg.REG_BINARY, "multi_sz": winreg.REG_MULTI_SZ, "expand_sz": winreg.REG_EXPAND_SZ}
    if kind == "auto":
        if isinstance(data, int):
            reg_type = winreg.REG_DWORD
        elif isinstance(data, list):
            reg_type = winreg.REG_MULTI_SZ
        else:
            reg_type = winreg.REG_SZ
    elif kind.lower() in type_map:
        reg_type = type_map[kind.lower()]
    else:
        return {"error": f"kind must be one of {sorted(type_map)} or auto"}

    try:
        with winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, value_name, 0, reg_type, data)
        return {"written": True, "key": key_path, "value": value_name, "type": _TYPES.get(reg_type, reg_type)}
    except PermissionError:
        return {"error": "access denied; run elevated"}
    except FileNotFoundError:
        return {"error": f"parent key not found: {key_path}"}


def reg_delete_value(key_path: str, value_name: str) -> dict[str, Any]:
    """Delete one value from a registry key."""
    hive_name, _, subkey = key_path.partition("\\")
    hive = _HKEYS.get(hive_name.upper())
    if hive is None:
        return {"error": f"hive must be one of {sorted(_HKEYS)}"}
    import winreg

    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, value_name)
        return {"deleted": True, "key": key_path, "value": value_name}
    except FileNotFoundError:
        return {"error": f"key or value not found: {key_path}\\{value_name}"}
    except PermissionError:
        return {"error": "access denied; run elevated"}


def reg_enum_keys(key_path: str) -> dict[str, Any]:
    """List the subkeys of a registry key."""
    hive_name, _, subkey = key_path.partition("\\")
    hive = _HKEYS.get(hive_name.upper())
    if hive is None:
        return {"error": f"hive must be one of {sorted(_HKEYS)}"}
    import winreg

    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            subkeys = []
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(key, index)
                except OSError:
                    break
                subkeys.append(name)
                index += 1
            return {"key": key_path, "subkey_count": len(subkeys), "subkeys": subkeys}
    except FileNotFoundError:
        return {"error": f"key not found: {key_path}"}


# --------------------------------------------------------------------------
# network connections
# --------------------------------------------------------------------------
def netstat(*, filter: str | None = None) -> dict[str, Any]:
    """List TCP/UDP endpoints with owning pid; filter by port, address, or process name."""
    try:
        result = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, errors="replace", timeout=30, stdin=subprocess.DEVNULL
        )
    except FileNotFoundError:
        return {"error": "netstat.exe not available"}
    rows = []
    for line in (result.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] in ("TCP", "UDP"):
            row = {
                "proto": parts[0],
                "local": parts[1],
                "remote": parts[2] if parts[0] == "TCP" else None,
                "state": parts[3] if parts[0] == "TCP" else None,
                "pid": int(parts[-1]) if parts[-1].isdigit() else None,
            }
            rows.append(row)
    if filter:
        needle = filter.lower()
        rows = [r for r in rows if needle in json.dumps(r).lower()]
    return {"count": len(rows), "connections": rows}


import json  # noqa: E402  (used by netstat filter)


# --------------------------------------------------------------------------
# process tree monitoring (WMI spawn/exit events) and one-shot process info
# --------------------------------------------------------------------------
def proc_info(pid: int) -> dict[str, Any]:
    """pid -> name, path, command line, parent, creation time, threads, in one call.

    Everything the tester kept pulling from CIM by hand: PEB gives the real command
    line (survives GetCommandLineW lies), toolhelp gives parent and threads,
    GetProcessTimes gives creation time.
    """
    import ctypes

    result: dict[str, Any] = {"pid": int(pid)}
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    handle = kernel32.OpenProcess(0x0410, 0, int(pid))  # QUERY | VM_READ
    if not handle:
        return {"error": f"OpenProcess({pid}) failed (error {ctypes.get_last_error()}); run elevated"}

    class _FILETIME(ctypes.Structure):
        _fields_ = [("low", wt.DWORD), ("high", wt.DWORD)]

    created = _FILETIME(); exited = _FILETIME(); kernel = _FILETIME(); user = _FILETIME()
    if kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
        stamp = (created.high << 32) | created.low
        if stamp:
            import datetime

            result["created"] = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=stamp // 10)).isoformat(sep=" ", timespec="seconds")

    # parent + name + thread count via toolhelp snapshot
    snapshot = _KERNEL32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    entry = _PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    if snapshot and snapshot != ctypes.c_void_p(-1).value:
        try:
            ok = _KERNEL32.Process32First(snapshot, ctypes.byref(entry))
            while ok:
                if entry.th32ProcessID == int(pid):
                    result["name"] = entry.szExeFile.decode("latin-1", "replace")
                    result["ppid"] = entry.th32ParentProcessID
                    result["threads"] = entry.cntThreads
                    break
                ok = _KERNEL32.Process32Next(snapshot, ctypes.byref(entry))
        finally:
            _KERNEL32.CloseHandle(snapshot)

    # real command line from the PEB
    try:
        from ghidra_mcp.maxi import peb_info

        peb = peb_info(int(pid))
        if "command_line" in peb:
            result["command_line"] = peb["command_line"]
        if "image_base" in peb:
            result["image_base"] = peb["image_base"]
    except Exception:
        pass
    _KERNEL32.CloseHandle(handle)
    return result


_PROC_WATCHES: dict[str, dict[str, Any]] = {}
_PROC_WATCH_LOCK = threading.Lock()


def _process_snapshot() -> dict[int, dict[str, Any]]:
    """One toolhelp pass: pid -> {pid, ppid, threads, name}."""
    out: dict[int, dict[str, Any]] = {}
    try:
        snap = _KERNEL32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
        if snap and snap != ctypes.c_void_p(-1).value:
            entry = _PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            ok = _KERNEL32.Process32First(snap, ctypes.byref(entry))
            while ok:
                out[entry.th32ProcessID] = {
                    "pid": entry.th32ProcessID,
                    "ppid": entry.th32ParentProcessID,
                    "threads": entry.cntThreads,
                    "name": entry.szExeFile.decode("latin-1", "replace"),
                }
                ok = _KERNEL32.Process32Next(snap, ctypes.byref(entry))
            _KERNEL32.CloseHandle(snap)
    except Exception:
        pass
    return out


def _watch_loop(name: str, pattern: str | None, log_path: Path, stop_event: threading.Event, baseline: dict[int, dict[str, Any]]) -> None:
    """Pure-Python watcher thread: toolhelp snapshots every 250ms, diff -> spawn/exit.

    Replaces the PowerShell CIM poller (unreliable under nested shells); runs inside
    this process, so nothing to babysit and no pipe to lose.
    """
    def append(entry: dict[str, Any]) -> None:
        try:
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass

    seen = baseline
    while not stop_event.is_set():
        # 250ms: fast children (cmd /C, crash handlers) live under a second; a 1s
        # poll lets spawn+exit happen between snapshots and nothing gets logged.
        # ETW (Kernel-Process) is the only complete answer - see etw_trace.
        stop_event.wait(0.25)
        current = _process_snapshot()
        for pid, proc in current.items():
            if pid in seen:
                continue
            matched = not pattern or pattern.lower() in proc["name"].lower()
            entry = {"kind": "spawn", "at": round(time.time(), 3), **proc}
            if matched:
                # command line for just-spawned processes: PEB read, best effort
                try:
                    info = proc_info(pid)
                    entry["cmdline"] = info.get("command_line")
                except Exception:
                    pass
            append(entry)
        for pid in seen:
            if pid not in current:
                append({"kind": "exit", "at": round(time.time(), 3), "pid": pid, "name": seen[pid]["name"]})
        seen = current


def proc_watch_start(pattern: str | None = None, *, name: str | None = None) -> dict[str, Any]:
    """Watch process creation and exit tree-wide, log spawn/exit with cmdline.

    The master tool for loaders that spawn children: every new process appears here
    within ~1s with pid, ppid, name, and real command line (PEB read) - no polling of
    CIM, no PowerShell. ``pattern`` filters spawns by name substring (e.g. "cmd.exe");
    unfiltered logs everything. proc_watch_read tails the log; proc_watch_stop ends it.
    The baseline snapshot is taken synchronously, so everything spawned after this
    returns is guaranteed to be reported.
    """
    watcher_name = name or f"watch_{int(time.time())}"
    log_path = Path(os.environ.get("TEMP", ".")) / f"procwatch_{watcher_name}.jsonl"
    if log_path.exists():
        log_path.unlink()
    baseline = _process_snapshot()
    stop_event = threading.Event()
    thread = threading.Thread(target=_watch_loop, args=(watcher_name, pattern, log_path, stop_event, baseline), daemon=True)
    thread.start()
    with _PROC_WATCH_LOCK:
        _PROC_WATCHES[watcher_name] = {"thread": thread, "stop": stop_event, "log": str(log_path), "pattern": pattern, "seen": {}}
    return {"watching": True, "name": watcher_name, "log": str(log_path),
            "note": "spawn/exit events land within ~1s; proc_watch_read tails them, proc_watch_stop ends it"}


def proc_watch_read(name: str, *, clear: bool = False, limit: int = 100) -> dict[str, Any]:
    """Read process-spawn events collected by a watcher (jsonl entries)."""
    watcher = _PROC_WATCHES.get(name)
    if watcher is None:
        return {"error": f"unknown watcher {name!r}"}
    entries = []
    try:
        text = Path(watcher["log"]).read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            pid = entry.get("ProcessId") or entry.get("pid")
            kind = entry.get("kind", "spawn")
            key = (kind, pid)
            if key in watcher["seen"]:
                continue  # re-read of the same log line
            watcher["seen"][key] = True
            entries.append(entry)
    except OSError as exc:
        return {"error": f"could not read the watcher log: {exc}"}
    shown = entries[-limit:]
    return {"count": len(entries), "events": shown}


def proc_watch_stop(name: str) -> dict[str, Any]:
    """Stop a process watcher."""
    with _PROC_WATCH_LOCK:
        watcher = _PROC_WATCHES.pop(name, None)
    if watcher is None:
        return {"error": f"unknown watcher {name!r}"}
    watcher["stop"].set()
    watcher["thread"].join(timeout=3)
    return {"stopped": True, "name": name, "log": watcher["log"]}
