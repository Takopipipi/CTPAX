"""Maximum-power additions: anti-debug/anti-VM static scanner, live PEB inspection,
DLL injection and ejection, registry snapshots with diffing, clipboard, file watching,
and the one-shot triage workflow.

The scanner is the map of what you are up against before a single breakpoint is set:
known check names, import fingerprints, and the strings each protection family leaves.
The registry diff closes the license-research loop: snapshot before, activate the app,
snapshot after, read exactly which keys the target touched.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from ghidra_mcp.dynamic import _ADVAPI32, _KERNEL32
from ghidra_mcp.pe_tools import load_pe
from ghidra_mcp.static_analysis import read_file

# --------------------------------------------------------------------------
# anti-debug / anti-VM static scanner
# --------------------------------------------------------------------------
_ANTIDEBUG_CHECKS = {
    "IsDebuggerPresent": "PEB->BeingDebugged",
    "CheckRemoteDebuggerPresent": "remote debugger via NtQueryInformationProcess",
    "NtQueryInformationProcess": "ProcessDebugPort / ProcessDebugFlags / ProcessDebugObjectHandle",
    "NtSetInformationThread": "ThreadHideFromDebugger",
    "NtQueryObject": "debug-object handle counting",
    "NtQuerySystemInformation": "SystemKernelDebuggerInformation / process listing",
    "NtCreateDebugObject": "kernel debugger detection",
    "DbgUiRemoteBreakin": "anti-attach (terminates the breakin thread)",
    "DbgUiConnectToDbg": "debug-object probes",
    "OutputDebugStringW": "exception-based check (last error differs under a debugger)",
    "NtYieldExecution": "shared-user-data DebugFlag check",
    "NtSetDebugFilterState": "debug-filter probe",
    "NtClose": "invalid-handle exception check",
    "RtlAdjustPrivilege": "SeDebugPrivilege probes",
    "IsProcessorFeaturePresent": "hidden hardware checks",
}

_ANTIVM_CHECKS = {
    "VmToolsd": "VMware tools process",
    "vmware": "VMware string",
    "VBoxService": "VirtualBox service process",
    "VBox": "VirtualBox string",
    "qemu": "QEMU string",
    "KVM": "KVM string",
    "Xen": "Xen string",
    "Hyper-V": "Hyper-V string",
    "cpuid": "hypervisor bit leaf 0x1",
    "inout": "VMware backdoor port vx",
}

_VM_MARKER_STRINGS = ["vmware", "virtualbox", "vbox", "qemu", "kvm", "xen", "hyper-v", "vmci", "vmmouse", "prl_", "paragon"]
_ANTI_DEBUG_STRINGS = ["debugger", "debugged", "ollydbg", "x64dbg", "x32dbg", "windbg", "ida", "idaq", "ida64",
                       "ghidra", "cheatengine", "cheat engine", "scylla", "titanhide", "httpdebugger", "fiddler",
                       "wireshark", "procmon", "process monitor", "process hacker", "processhacker",
                       "dnspy", "de4dot", "charles", "burp", "mitmproxy", "dumpcap"]

_PACKER_MARKERS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX!": "UPX",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".themida": "Themida", "winlice": "WinLicense",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".nsp0": "NsPack", ".nsp1": "NsPack", ".nsp2": "NsPack",
    ".petite": "Petite", ".pec1": "PECompact", ".pec2": "PECompact", "PECompact2": "PECompact",
    ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
    ".enigma1": "Enigma Protector", ".enigma2": "Enigma Protector",
    ".xy": "Obfuscator/SmartAssembly", ".dyamar": "Dyamar",
    "FSG!": "FSG", ".y0da": "Yoda", ".sedLL": "SedLL",
}


def antidebug_scan(path: str | Path) -> dict[str, Any]:
    """Static scan for anti-debug, anti-VM, and packer fingerprints - the pre-flight map.

    Run this before touching a target with a debugger: it tells you which checks to
    expect (IsDebuggerPresent vs NtQueryInformationProcess vs hidden strings), whether
    ScyllaHide's profile should be VMProtect/Themida, and whether the string list
    already suggests it hunts analyst tooling by name.
    """
    file_path = Path(path)
    if not file_path.is_file():
        return {"error": f"no such file: {file_path}"}
    data = read_file(file_path, length=0x2000000)  # 32 MB is plenty for marker sweeps
    lowered = data.lower()

    findings: dict[str, Any] = {"imports": [], "strings": [], "packers": [], "anti_vm": []}

    try:
        pe = load_pe(file_path)
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("latin-1", "replace")
                for imp in entry.imports:
                    name = imp.name.decode("latin-1", "replace") if imp.name else ""
                    if name in _ANTIDEBUG_CHECKS:
                        findings["imports"].append({"dll": dll, "function": name, "why": _ANTIDEBUG_CHECKS[name]})
        except AttributeError:
            pass
    except ValueError:
        pass  # packed or not a PE; the string sweep still works

    for marker, family in _PACKER_MARKERS.items():
        if marker.encode() in data:
            findings["packers"].append({"marker": marker, "family": family})

    for needle in _ANTI_DEBUG_STRINGS:
        count = lowered.count(needle.encode())
        if count:
            findings["strings"].append({"string": needle, "count": count, "kind": "analyst_tool"})

    for needle in _VM_MARKER_STRINGS:
        count = lowered.count(needle.encode())
        if count:
            findings["anti_vm"].append({"string": needle, "count": count})

    # Heavier checks referenced indirectly: hash of the import-name absence pattern
    checks_expected = sorted({f["function"] for f in findings["imports"]})
    severity = "high" if len(checks_expected) >= 5 else "medium" if checks_expected else "low"
    return {
        "file": str(file_path),
        "severity": severity,
        "anti_debug_imports": findings["imports"],
        "anti_debug_strings": findings["strings"],
        "anti_vm_strings": findings["anti_vm"],
        "packers": findings["packers"],
        "scyllahide_profile_hint": (
            "VMProtect x86/x64" if any(p["family"] in ("VMProtect", "Themida", "WinLicense") for p in findings["packers"])
            else "Normal" if not findings["imports"] else "Normal (hook NtQueryInformationProcess)"
        ),
        "note": "imports are ground truth; strings can be false positives (documentation, help files)",
    }


# --------------------------------------------------------------------------
# live PEB inspection (BeingDebugged, NtGlobalFlag, command line, image path)
# --------------------------------------------------------------------------
class _PEB_PARTIAL(ctypes.Structure):
    """Offsets through the PEB's first 0x100 bytes; enough for the classic checks.

    The kernel fills a full PEB layout when queried with ProcessBasicInformation, so
    we only model the fields we read and index the rest by offset arithmetic.
    """
    _fields_ = [
        ("InheritedAddressSpace", ctypes.c_byte),
        ("ReadImageFileExecOptions", ctypes.c_byte),
        ("BeingDebugged", ctypes.c_byte),
        ("BitField", ctypes.c_byte),
        ("Mutant", ctypes.c_void_p),
        ("ImageBaseAddress", ctypes.c_void_p),
        ("Ldr", ctypes.c_void_p),
        ("ProcessParameters", ctypes.c_void_p),
        ("SubSystemData", ctypes.c_void_p),
        ("ProcessHeap", ctypes.c_void_p),
        ("FastPebLock", ctypes.c_void_p),
        ("AtlThunkSListPtr", ctypes.c_void_p),
        ("IFEOKey", ctypes.c_void_p),
        ("CrossProcessFlags", ctypes.c_uint32),
        ("KernelCallbackTable", ctypes.c_void_p),
        ("ReadOnlySharedMemoryBase", ctypes.c_void_p),
        ("ReadOnlySharedMemoryHeap", ctypes.c_void_p),
        ("ReadOnlyStaticServerData", ctypes.c_void_p),
        ("AnsiCodePageData", ctypes.c_void_p),
        ("OemCodePageData", ctypes.c_void_p),
        ("UnicodeCaseTableData", ctypes.c_void_p),
        ("NumberOfProcessors", ctypes.c_uint32),
        ("NtGlobalFlag", ctypes.c_uint32),
    ]


class _PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_void_p),
        ("BasePriority", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
    ]


_NTDLL = ctypes.WinDLL("ntdll", use_last_error=True)
_NtQueryInformationProcess = _NTDLL.NtQueryInformationProcess
_NtQueryInformationProcess.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
_NtQueryInformationProcess.restype = ctypes.c_long


def _read_remote(handle: int, address: int, size: int) -> bytes:
    buffer = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    if not _KERNEL32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(read)):
        raise OSError(f"ReadProcessMemory({hex(address)}) failed (error {ctypes.get_last_error()})")
    return buffer.raw[: read.value]


def peb_info(pid: int) -> dict[str, Any]:
    """Read a live process's PEB: BeingDebugged, NtGlobalFlag, heap flags, command line.

    The anti-debug triad (BeingDebugged / NtGlobalFlag / heap Flags+ForceFlags) is what
    IsDebuggerPresent and friends actually read - this shows their current values, so
    you can verify a ScyllaHide-style patch took hold. Also returns the real command
    line and image path, which processes lie about through GetCommandLineW.
    """
    from ghidra_mcp.dynamic import enable_debug_privilege

    enable_debug_privilege()
    process = _KERNEL32.OpenProcess(0x0438, False, pid)  # QUERY | VM_READ | VM_OPERATION
    if not process:
        return {"error": f"OpenProcess({pid}) failed (error {ctypes.get_last_error()}); run elevated"}
    try:
        pbi = _PROCESS_BASIC_INFORMATION()
        ret_len = ctypes.c_ulong(0)
        status = _NtQueryInformationProcess(process, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len))
        if status != 0:
            return {"error": f"NtQueryInformationProcess failed: ntstatus {hex(status & 0xFFFFFFFF)}"}
        peb_address = pbi.PebBaseAddress
        if not peb_address:
            return {"error": "PebBaseAddress is null (protected process?)"}
        peb = _PEB_PARTIAL.from_buffer_copy(_read_remote(process, peb_address, ctypes.sizeof(_PEB_PARTIAL)))

        result: dict[str, Any] = {
            "pid": pid,
            "peb": hex(peb_address),
            "image_base": hex(peb.ImageBaseAddress or 0),
            "process_heap": hex(peb.ProcessHeap or 0),
            "being_debugged": bool(peb.BeingDebugged),
            "nt_global_flag": hex(peb.NtGlobalFlag),
            "nt_global_flag_debugged": bool(peb.NtGlobalFlag & 0x70),  # FLG_HEAP_* markers
            "number_of_processors": peb.NumberOfProcessors,
        }

        # Heap Flags/ForceFlags sit at heap+0x70/0x74 on x64 (x86: 0x0C/0x10).
        if peb.ProcessHeap:
            is_x64 = ctypes.sizeof(ctypes.c_void_p) == 8
            try:
                heap_bytes = _read_remote(process, peb.ProcessHeap, 0x80)
                offset = 0x70 if is_x64 else 0x0C
                flags = int.from_bytes(heap_bytes[offset:offset + (8 if is_x64 else 4)], "little")
                force_offset = 0x74 if is_x64 else 0x10
                force_flags = int.from_bytes(heap_bytes[force_offset:force_offset + (4)], "little") if is_x64 else force_flags
                result["heap_flags"] = hex(flags)
                result["heap_force_flags"] = hex(force_flags)
                result["heap_flags_debugged"] = bool(flags & 0x40000000 | force_flags & 0x40000000)  # HEAP_GROWABLE inverse marker
            except OSError:
                result["heap_flags"] = None

        # RTL_USER_PROCESS_PARAMETERS: CommandLine (UNICODE_STRING at 0x70 on x64)
        if peb.ProcessParameters:
            is_x64 = ctypes.sizeof(ctypes.c_void_p) == 8
            cmd_offset = 0x70 if is_x64 else 0x40
            params_bytes = _read_remote(process, peb.ProcessParameters, cmd_offset + 16)
            length = int.from_bytes(params_bytes[cmd_offset:cmd_offset + 2], "little")
            buffer_ptr = int.from_bytes(params_bytes[cmd_offset + 8:cmd_offset + 16], "little")
            if length and buffer_ptr:
                raw = _read_remote(process, buffer_ptr, length)
                result["command_line"] = raw.decode("utf-16-le", "replace")
        return result
    finally:
        _KERNEL32.CloseHandle(process)


# --------------------------------------------------------------------------
# DLL injection and ejection
# --------------------------------------------------------------------------
def dll_inject(pid: int, dll_path: str) -> dict[str, Any]:
    """Load a DLL into a target via the classic LoadLibraryW remote-thread trick.

    Your DLL's DllMain runs inside the target. Detection is trivial (a remote thread
    at LoadLibraryW is the oldest signature in the book), which is fine for research
    and instrumentation, not for stealth. Path must be absolute.
    """
    from ghidra_mcp.dynamic import enable_debug_privilege

    dll = Path(dll_path)
    if not dll.is_file():
        return {"error": f"no such DLL: {dll}"}
    if not dll.is_absolute():
        return {"error": "pass an absolute path"}
    enable_debug_privilege()
    # Without restype=LPVOID the 64-bit allocation address comes back as a negative
    # c_int and every downstream use fails with error 87/998 - set full signatures.
    _KERNEL32.VirtualAllocEx.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD, wt.DWORD]
    _KERNEL32.VirtualAllocEx.restype = wt.LPVOID
    _KERNEL32.WriteProcessMemory.argtypes = [wt.HANDLE, wt.LPVOID, wt.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    _KERNEL32.WriteProcessMemory.restype = wt.BOOL
    _KERNEL32.CreateRemoteThread.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.LPVOID, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD)]
    _KERNEL32.CreateRemoteThread.restype = wt.HANDLE
    _KERNEL32.VirtualFreeEx.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD]
    _KERNEL32.VirtualFreeEx.restype = wt.BOOL
    # GetProcAddress without restype=LPVOID truncates the 64-bit function pointer the
    # same way VirtualAllocEx did - resolve it after the signatures are set.
    _KERNEL32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
    _KERNEL32.GetModuleHandleW.restype = wt.HMODULE
    _KERNEL32.GetProcAddress.argtypes = [wt.HMODULE, wt.LPCSTR]
    _KERNEL32.GetProcAddress.restype = wt.LPVOID
    process = _KERNEL32.OpenProcess(0x1FFFFF, False, pid)  # PROCESS_ALL_ACCESS
    if not process:
        return {"error": f"OpenProcess({pid}) failed (error {ctypes.get_last_error()}); run elevated"}
    try:
        path_bytes = str(dll).encode("utf-16-le") + b"\x00\x00"
        remote_mem = _KERNEL32.VirtualAllocEx(process, None, len(path_bytes), 0x3000, 0x04)
        if not remote_mem:
            return {"error": f"VirtualAllocEx failed (error {ctypes.get_last_error()})"}
        try:
            written = ctypes.c_size_t(0)
            if not _KERNEL32.WriteProcessMemory(process, remote_mem, path_bytes, len(path_bytes), ctypes.byref(written)):
                return {"error": f"WriteProcessMemory failed (error {ctypes.get_last_error()})"}
            load_library = _KERNEL32.GetProcAddress(_KERNEL32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
            if not load_library:
                return {"error": "could not resolve kernel32!LoadLibraryW"}
            thread_id = wt.DWORD(0)
            remote_thread = _KERNEL32.CreateRemoteThread(
                process, None, 0, load_library, remote_mem, 0, ctypes.byref(thread_id)
            )
            if not remote_thread:
                return {"error": f"CreateRemoteThread failed (error {ctypes.get_last_error()}) - protected process, or a security product blocked it"}
            _KERNEL32.WaitForSingleObject(remote_thread, 10000)
            exit_code = wt.DWORD(0)
            _KERNEL32.GetExitCodeThread(remote_thread, ctypes.byref(exit_code))
            _KERNEL32.CloseHandle(remote_thread)
            return {
                "injected": True,
                "pid": pid,
                "dll": str(dll),
                "thread_exit_code": hex(exit_code.value),
                "note": "exit code is the remote LoadLibraryW return (module base) or 0 on failure; verify with proc_modules",
            }
        finally:
            _KERNEL32.VirtualFreeEx(process, ctypes.c_void_p(remote_mem), 0, 0x8000)
    finally:
        _KERNEL32.CloseHandle(process)


def dll_eject(pid: int, module_name: str) -> dict[str, Any]:
    """Eject a DLL from a target by FreeLibrary on a remote thread."""
    from ghidra_mcp.system import proc_modules

    try:
        modules = proc_modules(pid)["modules"]
    except Exception as exc:
        return {"error": f"could not list modules: {exc}"}
    target = next((m for m in modules if m["name"].lower() == module_name.lower()), None)
    if target is None:
        return {"error": f"module {module_name!r} not loaded in {pid}; proc_modules lists what is"}
    base = int(target["base"], 16)
    from ghidra_mcp.dynamic import enable_debug_privilege

    enable_debug_privilege()
    process = _KERNEL32.OpenProcess(0x1FFFFF, False, pid)
    if not process:
        return {"error": f"OpenProcess({pid}) failed (error {ctypes.get_last_error()})"}
    try:
        free_library = _KERNEL32.GetProcAddress(_KERNEL32.GetModuleHandleW("kernel32.dll"), "FreeLibrary")
        thread_id = wt.DWORD(0)
        remote_thread = _KERNEL32.CreateRemoteThread(
            process, None, 0, ctypes.c_void_p(free_library), ctypes.c_void_p(base), 0, ctypes.byref(thread_id)
        )
        if not remote_thread:
            return {"error": f"CreateRemoteThread failed (error {ctypes.get_last_error()})"}
        _KERNEL32.WaitForSingleObject(remote_thread, 10000)
        _KERNEL32.CloseHandle(remote_thread)
        return {"ejected": True, "pid": pid, "module": module_name, "base": target["base"]}
    finally:
        _KERNEL32.CloseHandle(process)


# --------------------------------------------------------------------------
# registry snapshots with diff
# --------------------------------------------------------------------------
_REG_SNAPSHOTS: dict[str, dict[str, Any]] = {}


def _flatten_key(key_path: str, values_out: dict[str, Any], subkeys_out: set[str]) -> None:
    from ghidra_mcp.system import reg_enum_keys, reg_read

    listing = reg_enum_keys(key_path)
    for subkey in listing.get("subkeys", []):
        child = f"{key_path}\\{subkey}"
        subkeys_out.add(child.lower())
        _flatten_key(child, values_out, subkeys_out)
    values = reg_read(key_path)
    for value in values.get("values", []):
        values_out[f"{key_path}\\{value['name']}".lower()] = {
            "type": value["type"], "data": str(value["data"])[:512],
        }


def reg_snapshot(key_path: str, name: str | None = None) -> dict[str, Any]:
    """Snapshot a registry subtree (keys + values) under a name for later diffing.

    The license-research workhorse: snapshot HKCU\\Software\\Vendor before activating,
    run the app, diff - the answer is exactly which keys/values the check wrote.
    """
    snapshot_name = name or f"snap_{int(time.time())}"
    values: dict[str, Any] = {}
    subkeys: set[str] = set()
    _flatten_key(key_path, values, subkeys)
    _REG_SNAPSHOTS[snapshot_name] = {"root": key_path, "values": values, "subkeys": subkeys, "at": time.time()}
    return {
        "snapshot": snapshot_name,
        "root": key_path,
        "value_count": len(values),
        "subkey_count": len(subkeys),
        "note": "rerun the target, then reg_snapshot_diff against this name",
    }


def reg_snapshot_diff(name_before: str, name_after: str) -> dict[str, Any]:
    """Diff two registry snapshots: added, removed, and changed values.

    This is the answer to 'where does it store the license' - activate the trial,
    diff, and the changed keys are the state to patch or replay. The response includes
    a human-readable delta and a guess at which values are license state, by name and
    value shape (trial/activated flags, dates, GUID-shaped tokens, encoded blobs).
    """
    before = _REG_SNAPSHOTS.get(name_before)
    after = _REG_SNAPSHOTS.get(name_after)
    if before is None or after is None:
        return {"error": f"unknown snapshot(s): {name_before!r}, {name_after!r}; reg_snapshot first"}
    added = {k: after["values"][k] for k in after["values"] if k not in before["values"]}
    removed = {k: before["values"][k] for k in before["values"] if k not in after["values"]}
    changed = {}
    for key in before["values"]:
        if key in after["values"] and before["values"][key] != after["values"][key]:
            changed[key] = {"was": before["values"][key], "now": after["values"][key]}
    added_keys = sorted(after["subkeys"] - before["subkeys"])
    removed_keys = sorted(before["subkeys"] - after["subkeys"])

    # Human-readable delta: one line per change, value before -> value after.
    lines = []
    for key, record in sorted(changed.items()):
        lines.append(f"~ {key}: {record['was']['data']!r} -> {record['now']['data']!r}")
    for key, record in sorted(added.items()):
        lines.append(f"+ {key} = {record['data']!r} ({record['type']})")
    for key, record in sorted(removed.items()):
        lines.append(f"- {key} (was {record['data']!r})")
    for key in added_keys:
        lines.append(f"+ [key] {key}")
    for key in removed_keys:
        lines.append(f"- [key] {key}")

    # License-candidate heuristic: names and value shapes that look like state.
    license_hints = []
    interesting_names = ("license", "licence", "trial", "activated", "activation", "serial", "key", "expire",
                         "expiry", "expires", "install", "first_run", "lastrun", "reg", "register", "regcode",
                         "premium", "pro", "paid", "unlock", " days", "count", "runs", "hwid", "machine")
    for key in set(list(changed) + list(added)):
        lowered = key.lower()
        record = changed.get(key, {}).get("now") or added.get(key, {})
        data_text = str(record.get("data", ""))
        looks_like_state = (
            any(hint in lowered for hint in interesting_names)
            or re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", data_text)
            or re.fullmatch(r"[A-Z0-9]{4}(-[A-Z0-9]{4}){2,5}", data_text)
            or (data_text.lower() in ("true", "false", "0", "1"))
        )
        if looks_like_state:
            license_hints.append({
                "value": key,
                "current": record.get("data"),
                "type": record.get("type"),
                "why": "name suggests state" if any(hint in lowered for hint in interesting_names) else "value shape (GUID/serial/flag)",
            })

    return {
        "before": name_before, "after": name_after,
        "delta_readable": lines if lines else ["(no registry changes)"],
        "license_candidates": license_hints,
        "values_added": added, "values_removed": removed, "values_changed": changed,
        "keys_added": added_keys, "keys_removed": removed_keys,
        "summary": f"{len(added)} added, {len(removed)} removed, {len(changed)} changed values; {len(added_keys)} new keys",
        "next_step": "reg_write the candidate values to fake an activated state, or replay them after a reinstall",
    }


# --------------------------------------------------------------------------
# clipboard
# --------------------------------------------------------------------------
_CF_UNICODETEXT = 13


def _clipboard_api() -> Any:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Explicit signatures: without restype the HGLOBAL from GlobalAlloc is truncated
    # to 32 bits on x64 and GlobalLock then returns null.
    user32.OpenClipboard.argtypes = [wt.HWND]
    user32.OpenClipboard.restype = wt.BOOL
    user32.CloseClipboard.restype = wt.BOOL
    user32.EmptyClipboard.restype = wt.BOOL
    user32.GetClipboardData.argtypes = [wt.UINT]
    user32.GetClipboardData.restype = wt.HANDLE
    user32.SetClipboardData.argtypes = [wt.UINT, wt.HANDLE]
    user32.SetClipboardData.restype = wt.HANDLE
    kernel32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wt.HGLOBAL
    kernel32.GlobalLock.argtypes = [wt.HGLOBAL]
    kernel32.GlobalLock.restype = wt.LPVOID
    kernel32.GlobalUnlock.argtypes = [wt.HGLOBAL]
    kernel32.GlobalUnlock.restype = wt.BOOL
    kernel32.GlobalFree.argtypes = [wt.HGLOBAL]
    kernel32.GlobalFree.restype = wt.HGLOBAL
    return user32, kernel32


def clipboard_get() -> dict[str, Any]:
    """Read the clipboard text - what the app copies is often the license state."""
    user32, kernel32 = _clipboard_api()
    if not user32.OpenClipboard(None):
        return {"error": "could not open the clipboard (another window holds it)"}
    try:
        handle = user32.GetClipboardData(_CF_UNICODETEXT)
        if not handle:
            return {"text": None, "note": "clipboard holds no text"}
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            return {"error": "GlobalLock failed"}
        try:
            text = ctypes.wstring_at(pointer)
        finally:
            kernel32.GlobalUnlock(handle)
        return {"text": text[:5000], "length": len(text)}
    finally:
        user32.CloseClipboard()


def clipboard_set(text: str) -> dict[str, Any]:
    """Write text to the clipboard - preload it before pasting into a target dialog."""
    user32, kernel32 = _clipboard_api()
    if not user32.OpenClipboard(None):
        return {"error": "could not open the clipboard"}
    try:
        user32.EmptyClipboard()
        data = text.encode("utf-16-le") + b"\x00\x00"
        handle = kernel32.GlobalAlloc(0x0002, len(data))  # GMEM_MOVEABLE
        if not handle:
            return {"error": f"GlobalAlloc failed (error {ctypes.get_last_error()})"}
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            return {"error": "GlobalLock failed"}
        ctypes.memmove(pointer, data, len(data))
        kernel32.GlobalUnlock(handle)
        if not user32.SetClipboardData(_CF_UNICODETEXT, handle):
            kernel32.GlobalFree(handle)
            return {"error": f"SetClipboardData failed (error {ctypes.get_last_error()})"}
        return {"set": True, "length": len(text)}
    finally:
        user32.CloseClipboard()


# --------------------------------------------------------------------------
# file watcher
# --------------------------------------------------------------------------
_WATCHERS: dict[str, dict[str, Any]] = {}


def file_watch_start(path: str, *, recursive: bool = True, name: str | None = None) -> dict[str, Any]:
    """Watch a directory tree for changes (creates, writes, deletes, renames).

    The answer to 'where does it write its state': start the watcher, run the target,
    read what appeared. Runs as a background thread inside the server.
    """
    directory = Path(path)
    if not directory.is_dir():
        return {"error": f"not a directory: {directory}"}
    watcher_name = name or f"watch_{int(time.time())}"
    events: list[dict[str, Any]] = []

    command = [
        "powershell", "-NoProfile", "-Command",
        "$fsw = New-Object IO.FileSystemWatcher",
        f"-Path '{directory}'",
        f"-IncludeSubfolders: {'$true' if recursive else '$false'}",
        "-NotifyFilter FileName, LastWrite",
        "register-objectevent $fsw Changed -action {} | out-null",
        "register-objectevent $fsw Created -action {} | out-null",
        "register-objectevent $fsw Deleted -action {} | out-null",
        "register-objectevent $fsw Renamed -action {} | out-null",
        "while ($true) { start-sleep -milliseconds 500 }",
    ]
    # A simpler, dependency-free approach: poll the tree and diff listings.
    def snapshot_tree() -> dict[str, tuple[float, int]]:
        result = {}
        pattern = "**/*" if recursive else "*"
        for item in directory.glob(pattern):
            try:
                if item.is_file():
                    stat = item.stat()
                    result[str(item)] = (stat.st_mtime, stat.st_size)
            except OSError:
                continue
        return result

    previous = snapshot_tree()
    stop_event = threading.Event()

    def poll() -> None:
        while not stop_event.is_set():
            time.sleep(0.4)
            current = snapshot_tree()
            for path_value, (mtime, size) in current.items():
                if path_value not in previous:
                    events.append({"at": round(time.time(), 3), "kind": "created", "path": path_value, "size": size})
                elif previous[path_value] != (mtime, size):
                    events.append({"at": round(time.time(), 3), "kind": "modified", "path": path_value, "size": size})
            for path_value in previous:
                if path_value not in current:
                    events.append({"at": round(time.time(), 3), "kind": "deleted", "path": path_value})
            del events[:-1000]
            previous.clear()
            previous.update(current)

    thread = threading.Thread(target=poll, daemon=True)
    thread.start()
    _WATCHERS[watcher_name] = {"stop": stop_event, "events": events, "root": str(directory)}
    return {"watching": True, "name": watcher_name, "root": str(directory), "recursive": recursive,
            "note": "run the target, then file_watch_read to see what it touched"}


def file_watch_read(name: str, *, clear: bool = False, limit: int = 100) -> dict[str, Any]:
    """Read (and optionally clear) what a watcher saw: created / modified / deleted paths."""
    watcher = _WATCHERS.get(name)
    if watcher is None:
        return {"error": f"unknown watcher {name!r}"}
    events = watcher["events"][-limit:]
    if clear:
        watcher["events"].clear()
    return {"count": len(watcher["events"]), "events": events}


def file_watch_stop(name: str) -> dict[str, Any]:
    """Stop a file watcher."""
    watcher = _WATCHERS.pop(name, None)
    if watcher is None:
        return {"error": f"unknown watcher {name!r}"}
    watcher["stop"].set()
    return {"stopped": True, "name": name, "events_seen": len(watcher["events"])}


# --------------------------------------------------------------------------
# one-shot triage
# --------------------------------------------------------------------------
def triage(path: str) -> dict[str, Any]:
    """One command, full static picture: identity, packing, anti-debug, PE traits, verdict.

    The opening move for any unknown binary - everything static the toolkit knows,
    without running a single tool by hand.
    """
    from ghidra_mcp.static_analysis import analyze_binary, detect_packing
    from ghidra_mcp.pe_tools import pe_heuristics

    report: dict[str, Any] = {}
    try:
        report["identity"] = analyze_binary(path, section_entropy=True)
    except Exception as exc:
        report["identity"] = {"error": str(exc)}
    try:
        report["packing"] = detect_packing(path)
    except Exception as exc:
        report["packing"] = {"error": str(exc)}
    report["antidebug"] = antidebug_scan(path)
    report["pe_heuristics"] = pe_heuristics(path)

    score = 0
    notes = []
    if report["packing"].get("packed"):
        score += 3
        notes.append(f"packed: {report['packing'].get('packer')}")
    heur = report["pe_heuristics"]
    if isinstance(heur, dict) and heur.get("verdict") == "likely_packed_or_protected":
        score += 2
    if report["antidebug"]["severity"] == "high":
        score += 2
        notes.append("heavy anti-debug import surface")
    elif report["antidebug"]["severity"] == "medium":
        score += 1
    if report["antidebug"]["packers"]:
        score += 1
    report["triage_score"] = score
    report["triage_verdict"] = "clean" if score <= 1 else "interesting" if score <= 4 else "hostile"
    report["notes"] = notes
    report["next_steps"] = [
        "open_binary in Ghidra for decompilation" if score < 4 else "unpack first (check packers above), then open_binary",
        "ScyllaHide profile: " + str(report["antidebug"].get("scyllahide_profile_hint")),
        "mem_strings_proc / proc_list once it runs, xdbg_start for the session",
    ]
    return report
