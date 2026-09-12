"""Dump forensics: take minidumps from outside the target, and analyse any .dmp for
anti-forensic fakery.

The threat this answers: a target hooks WER or its own crash path and writes a dump
full of decoy threads (422 of them, garbage TEBs, phantom modules). Taking the dump
ourselves via MiniDumpWriteDump bypasses every in-process hook; dump_analyze then
scores the file's structure for the classic fake-dump tells - absurd thread counts,
stack/context RVAs outside the file, zeroed TEBs, module paths that do not exist on
disk, exception addresses outside every module range.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import time
from pathlib import Path
from typing import Any

from ghidra_mcp.dynamic import enable_debug_privilege

# MINIDUMP stream types
_THREAD_LIST = 3
_MODULE_LIST = 4
_MEMORY_LIST = 5
_EXCEPTION = 6
_SYSTEM_INFO = 7
_MEMORY64_LIST = 9
_UNLOADED_MODULES = 15


def proc_mindump(pid: int, out_path: str) -> dict[str, Any]:
    """Write a real minidump of a live process via dbghelp!MiniDumpWriteDump.

    Taken from OUTSIDE the process, so in-process WER/MiniDump hooks never run and
    cannot forge the file. Includes thread+context and handle data - enough for
    dump_analyze and for offline inspection in WinDbg.
    """
    from ghidra_mcp.dynamic import _KERNEL32

    enable_debug_privilege()
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    process = _KERNEL32.OpenProcess(0x1F0FFF, False, int(pid))  # PROCESS_ALL_ACCESS minus a few
    if not process:
        error = ctypes.get_last_error()
        return {"error": f"OpenProcess({pid}) failed (error {error}); run elevated for other users' processes"}

    dump_type = 0x100 | 0x4 | 0x20 | 0x1 | 0x40  # WithProcessThreadData|WithHandleData|WithUnloadedModules|WithDataSegs|WithIndirectlyReferencedMemory
    try:
        dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
        dbghelp.MiniDumpWriteDump.argtypes = [wt.HANDLE, wt.DWORD, wt.HANDLE, wt.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        dbghelp.MiniDumpWriteDump.restype = wt.BOOL
        file_handle = _KERNEL32.CreateFileW(str(out), 0x40000000, 0, None, 2, 0x80, None)  # GENERIC_WRITE, CREATE_ALWAYS
        if file_handle in (0, ctypes.c_void_p(-1).value):
            return {"error": f"CreateFileW({out}) failed (error {ctypes.get_last_error()})"}
        try:
            ok = dbghelp.MiniDumpWriteDump(process, int(pid), file_handle, dump_type, None, None, None)
            if not ok:
                return {"error": f"MiniDumpWriteDump failed (error {ctypes.get_last_error()}) - protected process or a security product blocked it"}
        finally:
            _KERNEL32.CloseHandle(file_handle)
        return {
            "dumped": True,
            "pid": int(pid),
            "path": str(out),
            "size": out.stat().st_size,
            "dump_flags": hex(dump_type),
            "note": "the dump bypasses in-process WER hooks; dump_analyze it next",
        }
    finally:
        _KERNEL32.CloseHandle(process)


def _read_struct(data: bytes, offset: int, fmt: str) -> tuple:
    size = struct.calcsize(fmt)
    return struct.unpack_from(fmt, data, offset)


def _minidump_string(data: bytes, rva: int) -> str:
    if rva <= 0 or rva + 4 > len(data):
        return ""
    length = struct.unpack_from("<I", data, rva)[0]
    if length == 0 or rva + 4 + length > len(data):
        return ""
    return data[rva + 4 : rva + 4 + length].decode("utf-16-le", "replace")


def dump_analyze(path: str, *, live_pid: int | None = None) -> dict[str, Any]:
    """Parse a minidump and score it for anti-forensic fakery.

    Parses the stream directory and the streams that matter (ThreadList, ModuleList,
    Exception, SystemInfo, Memory64List), then runs plausibility checks - the ones a
    forged dump fails: thread counts absurd for a user app, stack or context RVAs past
    the end of the file, zeroed or misaligned TEBs, thread context sizes that do not
    match the architecture's CONTEXT (1232 bytes on x64), module paths that do not
    exist on disk, and exception addresses outside every module range. Optionally
    cross-checks modules against a live process when ``live_pid`` is given.
    """
    dump = Path(path)
    if not dump.is_file():
        return {"error": f"no such file: {dump}"}
    data = dump.read_bytes()
    if len(data) < 32 or data[:4] != b"MDMP":
        return {"error": "not a minidump (missing MDMP magic)"}

    (_version, number_of_streams, directory_rva, _checksum, _timestamp, flags) = _read_struct(data, 4, "<IIIIIQ")
    findings: list[dict[str, Any]] = []

    def flag(severity: str, trait: str, detail: str) -> None:
        findings.append({"severity": severity, "trait": trait, "detail": detail})

    streams: dict[int, tuple[int, int]] = {}
    for index in range(number_of_streams):
        base = directory_rva + index * 12
        if base + 12 > len(data):
            flag("high", "directory_truncated", f"stream directory entry {index} past EOF")
            break
        stream_type, stream_size, stream_rva = _read_struct(data, base, "<III")
        streams[stream_type] = (stream_rva, stream_size)

    is_x64 = True
    processors = None
    threads: list[dict[str, Any]] = []
    modules: list[dict[str, Any]] = []
    exception: dict[str, Any] | None = None

    if _SYSTEM_INFO in streams:
        rva, _size = streams[_SYSTEM_INFO]
        try:
            arch = struct.unpack_from("<H", data, rva)[0]
            processors = data[rva + 20]  # NumberOfProcessors byte
            is_x64 = arch in (9, 12)  # PROCESSOR_ARCHITECTURE_AMD64 / ARM64
        except struct.error:
            flag("medium", "systeminfo_truncated", "SystemInfoStream present but truncated")
    else:
        flag("medium", "missing_systeminfo", "no SystemInfoStream - real WER dumps always have one")

    if _THREAD_LIST in streams:
        rva, size = streams[_THREAD_LIST]
        if rva + 4 > len(data):
            flag("high", "threadlist_truncated", "thread count past EOF")
        else:
            count = struct.unpack_from("<I", data, rva)[0]
            # Classic CONTEXT is 1232 bytes on x64 / 716 on x86, but modern dumps carry
            # the XSAVE-extended context (~1663 bytes); anything far outside both is fake.
            plausible_context = (400, 2500)
            for i in range(min(count, 10000)):
                base = rva + 4 + i * 48
                if base + 48 > len(data):
                    flag("high", "thread_table_truncated", f"thread {i} entry past EOF")
                    break
                (tid, suspend, _prio_class, _prio, teb, stack_start, stack_size, stack_rva, ctx_size, ctx_rva) = _read_struct(data, base, "<IIIIQ QII II")
                threads.append({
                    "tid": tid, "teb": teb, "stack_rva": stack_rva, "stack_size": stack_size,
                    "context_rva": ctx_rva, "context_size": ctx_size,
                })
            if count > 1000:
                flag("high", "thread_count_absurd", f"{count} threads in one user process - classic decoy flood (the tester's 422)")
            elif count == 0:
                flag("high", "thread_count_zero", "a dump with no threads cannot come from a live process")

            bad_stack = sum(1 for t in threads if t["stack_rva"] + t["stack_size"] > len(data) or (t["stack_size"] == 0 and t["stack_rva"] != 0))
            if bad_stack:
                flag("high", "stacks_outside_file", f"{bad_stack}/{len(threads)} stack RVAs point past the end of the dump")
            bad_ctx_size = sum(1 for t in threads if t["context_size"] != 0 and not plausible_context[0] <= t["context_size"] <= plausible_context[1])
            if bad_ctx_size:
                flag("high", "context_size_wrong", f"{bad_ctx_size}/{len(threads)} context sizes outside {plausible_context} ({'x64' if is_x64 else 'x86'})")
            bad_ctx_rva = sum(1 for t in threads if t["context_rva"] and t["context_rva"] + t["context_size"] > len(data))
            if bad_ctx_rva:
                flag("high", "contexts_outside_file", f"{bad_ctx_rva}/{len(threads)} context RVAs point past EOF")
            teb_zero = sum(1 for t in threads if t["teb"] == 0)
            if teb_zero and threads:
                flag("medium", "tebs_zeroed", f"{teb_zero}/{len(threads)} TEBs are zero")
            teb_misaligned = sum(1 for t in threads if t["teb"] and t["teb"] % 0x1000 != 0)
            if teb_misaligned:
                flag("medium", "tebs_misaligned", f"{teb_misaligned}/{len(threads)} TEBs are not page-aligned")
            tebs = [t["teb"] for t in threads if t["teb"]]
            if len(tebs) != len(set(tebs)):
                flag("high", "duplicate_tebs", "several threads claim the same TEB address")
    else:
        flag("high", "missing_threadlist", "no ThreadListStream - a dump without threads is not a crash dump")

    if _MODULE_LIST in streams:
        rva, _size = streams[_MODULE_LIST]
        if rva + 4 > len(data):
            flag("high", "modulelist_truncated", "module count past EOF")
        else:
            count = struct.unpack_from("<I", data, rva)[0]
            for i in range(min(count, 4000)):
                base = rva + 4 + i * 108
                if base + 108 > len(data):
                    flag("high", "module_table_truncated", f"module {i} entry past EOF")
                    break
                (base_image, size_image, _checksum, _timestamp, name_rva) = _read_struct(data, base, "<QIIII")
                name = _minidump_string(data, name_rva)
                modules.append({"base": base_image, "size": size_image, "name": name})
            missing_on_disk = [m["name"] for m in modules if m["name"] and not Path(m["name"]).exists()]
            if missing_on_disk:
                flag("medium", "modules_not_on_disk", f"{len(missing_on_disk)} dumped modules have no backing file: {missing_on_disk[:4]}")
            unnamed = sum(1 for m in modules if not m["name"])
            if unnamed:
                flag("high", "modules_unnamed", f"{unnamed}/{len(modules)} modules have no name string")
            bases = [m["base"] for m in modules if m["base"]]
            if len(bases) != len(set(bases)):
                flag("high", "duplicate_module_bases", "several modules claim the same image base")
    else:
        flag("high", "missing_modulelist", "no ModuleListStream - a dump without modules is not a crash dump")

    if _EXCEPTION in streams:
        rva, _size = streams[_EXCEPTION]
        try:
            thread_id = struct.unpack_from("<I", data, rva)[0]
            code = struct.unpack_from("<I", data, rva + 8)[0]
            address = struct.unpack_from("<Q", data, rva + 24)[0]
            exception = {"thread_id": thread_id, "code": hex(code), "address": hex(address)}
            thread_ids = {t["tid"] for t in threads}
            if thread_id not in thread_ids:
                flag("high", "exception_thread_missing", f"exception references thread {thread_id} which the ThreadList does not contain")
            if modules and address:
                in_module = any(m["base"] <= address < m["base"] + m["size"] for m in modules)
                if not in_module:
                    flag("medium", "exception_outside_modules", f"exception address {hex(address)} lies in no module range (heap/JIT is fine; garbage is not)")
        except struct.error:
            flag("high", "exception_truncated", "ExceptionStream present but truncated")
    else:
        flag("low", "missing_exception", "no ExceptionStream (some dumps legitimately omit it)")

    if live_pid:
        try:
            from ghidra_mcp.system import proc_modules

            live = {m["name"].lower() for m in proc_modules(live_pid)["modules"]}
            dumped = {m["name"].lower() for m in modules if m["name"]}
            phantom = sorted(dumped - live - {"", "memory\\listedmodules"})
            if phantom:
                # Info, not high: the process legitimately unloaded modules between the
                # dump and the live check, and WER paths differ. Only worth a look.
                findings.append({
                    "severity": "info",
                    "trait": "modules_not_loaded_now",
                    "detail": f"{len(phantom)} dumped modules are not in the live module list now: {phantom[:5]} (race or genuinely unloaded)",
                })
        except Exception as exc:
            findings.append({"severity": "info", "trait": "live_check_failed", "detail": str(exc)})

    weights = {"high": 3, "medium": 2, "low": 0, "info": 0}
    score = sum(weights.get(f["severity"], 0) for f in findings)
    verdict = ("authentic" if not findings else "plausible") if score == 0 else "suspicious" if score <= 5 else "likely_forged"
    return {
        "file": str(dump),
        "size": len(data),
        "streams": {name_of(t): (s[1]) for t, s in sorted(streams.items())},
        "threads": len(threads),
        "modules": len(modules),
        "processors": processors,
        "exception": exception,
        "sample_threads": threads[:5],
        "sample_modules": modules[:8],
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "note": "likely_forged dumps pair decoy thread floods with RVAs past EOF and phantom modules; authentic dumps fail none of the structural checks",
    }


def name_of(stream_type: int) -> str:
    names = {3: "ThreadList", 4: "ModuleList", 5: "MemoryList", 6: "Exception", 7: "SystemInfo", 9: "Memory64List", 15: "UnloadedModules"}
    return names.get(stream_type, f"stream_{stream_type}")
