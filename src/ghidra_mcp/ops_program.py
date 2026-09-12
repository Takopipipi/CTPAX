"""Program-level operations: import, analyze, metadata, project management.

Everything here runs inside the worker process with a live JVM.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Callable

from ghidra_mcp.ghidra_ops import (
    OpError,
    Session,
    clamp,
    function_summary,
    op,
    sha256_file,
)


def _program_details(session: Session, entry: Any) -> dict[str, Any]:
    program = entry.program
    memory = program.getMemory()
    blocks = []
    for block in memory.getBlocks():
        blocks.append(
            {
                "name": str(block.getName()),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": int(block.getSize()),
                "r": bool(block.isRead()),
                "w": bool(block.isWrite()),
                "x": bool(block.isExecute()),
                "initialized": bool(block.isInitialized()),
                "overlay": bool(block.isOverlay()),
            }
        )
    language = program.getLanguage()
    info = program.getOptions("Program Information")
    program_info = {}
    for name in info.getOptionNames():
        try:
            program_info[str(name)] = str(info.getValueAsString(name))
        except Exception:
            continue
    from ghidra.program.util import GhidraProgramUtilities  # type: ignore

    return {
        "program": entry.key,
        "name": str(program.getName()),
        "executable_path": str(program.getExecutablePath() or ""),
        "format": str(program.getExecutableFormat() or ""),
        "md5": str(program.getExecutableMD5() or ""),
        "sha256": str(program.getExecutableSHA256() or ""),
        "language": str(program.getLanguageID()),
        "processor": str(language.getProcessor()),
        "endian": "big" if language.isBigEndian() else "little",
        "bits": int(language.getLanguageDescription().getSize()),
        "compiler_spec": str(program.getCompilerSpec().getCompilerSpecID().getIdAsString()),
        "pointer_size": int(program.getDefaultPointerSize()),
        "image_base": str(program.getImageBase()),
        "min_address": str(program.getMinAddress()),
        "max_address": str(program.getMaxAddress()),
        "function_count": int(program.getFunctionManager().getFunctionCount()),
        "symbol_count": int(program.getSymbolTable().getNumSymbols()),
        "analyzed": not bool(GhidraProgramUtilities.shouldAskToAnalyze(program)),
        "changed": bool(program.isChanged()),
        "blocks": blocks,
        "program_info": program_info,
    }


@op("status")
def status(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Worker health plus what is currently open."""
    from java.lang import Runtime  # type: ignore

    runtime = Runtime.getRuntime()
    return {
        "ghidra_version": session.ghidra_version(),
        "project": {"name": session.project_name, "location": str(session.project_dir)},
        "open_programs": [
            {
                "program": entry.key,
                "name": str(entry.program.getName()),
                "opened_seconds_ago": round(time.time() - entry.opened_at, 1),
                "changed": bool(entry.program.isChanged()),
            }
            for entry in session.programs.values()
        ],
        "active_program": session.active_key,
        "jvm": {
            "max_heap_mb": int(runtime.maxMemory() / (1024 * 1024)),
            "used_heap_mb": int((runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024)),
        },
        "pid": os.getpid(),
    }


@op("project_list")
def project_list(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Every program stored in the Ghidra project, analysed or not."""
    project = session.ensure_project()
    data = project.getProjectData()
    out = []
    for path in session.list_project_files():
        file = data.getFile(path)
        if file is None:
            continue
        out.append(
            {
                "program": path,
                "content_type": str(file.getContentType()),
                "read_only": bool(file.isReadOnly()),
                "open": path in session.programs,
                "size_bytes": int(file.length()) if hasattr(file, "length") else None,
            }
        )
    return {"project": session.project_name, "location": str(session.project_dir), "programs": out}


@op("open")
def open_binary(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Import a file (or reuse a previous import) and open it.

    ``analyze`` defaults to True. Re-opening a file that was analysed in an earlier
    session is nearly instant, because the analysis lives in the project.
    """
    raw_path = params.get("path")
    reopen_key = params.get("program")
    analyze = params.get("analyze", True)
    reimport = bool(params.get("reimport"))

    if raw_path:
        file_path = Path(str(raw_path)).expanduser()
        if not file_path.exists():
            raise OpError(f"file not found: {file_path}")
        if not file_path.is_file():
            raise OpError(f"not a file: {file_path}")
        size = file_path.stat().st_size
        if size == 0:
            raise OpError(f"file is empty: {file_path}")
        started = time.time()
        key, imported = session.import_binary(
            file_path,
            language=params.get("language"),
            compiler=params.get("compiler"),
            loader=params.get("loader"),
            program_name=params.get("name"),
            reimport=reimport,
            progress=progress,
        )
        import_seconds = round(time.time() - started, 2)
    elif reopen_key:
        key = str(reopen_key)
        candidates = session.list_project_files()
        if key not in candidates:
            matches = [c for c in candidates if key.lower() in c.lower()]
            if len(matches) != 1:
                raise OpError(f"'{key}' is not in the project. Known: {', '.join(candidates) or '(none)'}")
            key = matches[0]
        imported = False
        import_seconds = 0.0
        size = None
    else:
        raise OpError("pass 'path' to import a file, or 'program' to reopen one already in the project")

    entry = session.open_program(key)
    if raw_path:
        entry.path = str(Path(str(raw_path)).expanduser())

    result: dict[str, Any] = {
        "imported": imported,
        "import_seconds": import_seconds,
        "file_size": size,
    }
    if raw_path:
        result["sha256"] = sha256_file(Path(str(raw_path)).expanduser())

    from ghidra.program.util import GhidraProgramUtilities  # type: ignore

    needs_analysis = bool(GhidraProgramUtilities.shouldAskToAnalyze(entry.program))
    if analyze and needs_analysis:
        progress(stage="analyze", note="auto-analysis running, this is the slow part")
        started = time.time()
        with session.transaction(entry, "MCP auto-analysis"):
            log = session.pyghidra.analyze(entry.program, session.monitor())
        session.check_cancel()
        session.save(entry)
        result["analysis_seconds"] = round(time.time() - started, 2)
        result["analysis_log_tail"] = str(log or "")[-1500:]
    else:
        result["analysis_seconds"] = 0.0
        result["already_analyzed"] = not needs_analysis

    result.update(_program_details(session, entry))
    return result


@op("analyze")
def analyze(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Re-run auto-analysis, optionally after changing analyser options."""
    entry = session.resolve(params)
    options = params.get("options") or {}
    changed_options: dict[str, Any] = {}
    if options:
        analysis_options = session.pyghidra.analysis_properties(entry.program)
        with session.transaction(entry, "MCP analysis options"):
            for name, value in options.items():
                try:
                    analysis_options.setBoolean(str(name), bool(value)) if isinstance(value, bool) else None
                    if isinstance(value, int) and not isinstance(value, bool):
                        analysis_options.setInt(str(name), int(value))
                    elif isinstance(value, str):
                        analysis_options.setString(str(name), value)
                    changed_options[str(name)] = value
                except Exception as exc:
                    changed_options[str(name)] = f"failed: {exc}"

    before = int(entry.program.getFunctionManager().getFunctionCount())
    started = time.time()
    progress(stage="analyze", functions_before=before)
    with session.transaction(entry, "MCP re-analysis"):
        log = session.pyghidra.analyze(entry.program, session.monitor())
    session.check_cancel()
    session.save(entry)
    after = int(entry.program.getFunctionManager().getFunctionCount())
    return {
        "program": entry.key,
        "seconds": round(time.time() - started, 2),
        "functions_before": before,
        "functions_after": after,
        "options_applied": changed_options,
        "log_tail": str(log or "")[-4000:],
    }


@op("analysis_options")
def analysis_options(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """List the analyser options and their current values."""
    entry = session.resolve(params)
    options = session.pyghidra.analysis_properties(entry.program)
    out = []
    for name in options.getOptionNames():
        try:
            out.append(
                {
                    "name": str(name),
                    "value": str(options.getValueAsString(name)),
                    "description": str(options.getDescription(name) or ""),
                }
            )
        except Exception:
            continue
    return {"program": entry.key, "count": len(out), "options": out}


@op("info")
def info(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Everything Ghidra knows about the program at a glance."""
    entry = session.resolve(params)
    return _program_details(session, entry)


@op("close")
def close(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Close a program, saving analysis and edits by default."""
    entry = session.resolve(params)
    key = entry.key
    save = params.get("save", True)
    closed = session.close_program(key, save=bool(save))
    return {"program": key, "closed": closed, "saved": bool(save)}


@op("save")
def save(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Flush pending changes to the project on disk."""
    entry = session.resolve(params)
    changed = bool(entry.program.isChanged())
    session.save(entry)
    return {"program": entry.key, "had_changes": changed}


@op("delete_program")
def delete_program(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Remove a program from the project, discarding its analysis."""
    target = params.get("program")
    if not target:
        raise OpError("'program' is required, this one does not fall back to the active program")
    candidates = session.list_project_files()
    key = str(target)
    if key not in candidates:
        matches = [c for c in candidates if key.lower() in c.lower()]
        if len(matches) != 1:
            raise OpError(f"'{key}' is not in the project. Known: {', '.join(candidates) or '(none)'}")
        key = matches[0]
    session.close_program(key, save=False)
    file = session.ensure_project().getProjectData().getFile(key)
    if file is None:
        raise OpError(f"'{key}' vanished from the project")
    file.delete()
    return {"program": key, "deleted": True}


@op("memory_blocks")
def memory_blocks(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Section/segment layout as Ghidra sees it, with file offsets where known."""
    entry = session.resolve(params)
    out = []
    for block in entry.program.getMemory().getBlocks():
        record: dict[str, Any] = {
            "name": str(block.getName()),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": int(block.getSize()),
            "permissions": f"{'r' if block.isRead() else '-'}{'w' if block.isWrite() else '-'}{'x' if block.isExecute() else '-'}",
            "initialized": bool(block.isInitialized()),
            "type": str(block.getType()),
            "comment": str(block.getComment() or ""),
        }
        try:
            infos = block.getSourceInfos()
            if infos:
                offset = infos[0].getFileBytesOffset(block.getStart())
                if offset is not None and int(offset) >= 0:
                    record["file_offset"] = int(offset)
        except Exception:
            pass
        out.append(record)
    return {"program": entry.key, "count": len(out), "blocks": out}


@op("entry_points")
def entry_points(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Declared entry points, which is where reading a new binary usually starts."""
    entry = session.resolve(params)
    program = entry.program
    manager = program.getFunctionManager()
    out = []
    for address in program.getSymbolTable().getExternalEntryPointIterator():
        function = manager.getFunctionAt(address) or manager.getFunctionContaining(address)
        record: dict[str, Any] = {"address": str(address)}
        if function is not None:
            record["function"] = function_summary(function)
        symbol = program.getSymbolTable().getPrimarySymbol(address)
        if symbol is not None:
            record["symbol"] = str(symbol.getName())
        out.append(record)
    return {"program": entry.key, "count": len(out), "entry_points": out}


@op("imports")
def imports(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Imported (external) symbols grouped by library."""
    entry = session.resolve(params)
    limit = clamp(params.get("limit"), 1, 5000, 500)
    name_filter = (params.get("filter") or "").lower()
    grouped: dict[str, list[dict[str, Any]]] = {}
    total = 0
    for symbol in entry.program.getSymbolTable().getExternalSymbols():
        name = str(symbol.getName())
        if name_filter and name_filter not in name.lower():
            continue
        total += 1
        if total > limit:
            continue
        library = str(symbol.getParentNamespace().getName())
        grouped.setdefault(library, []).append(
            {
                "name": name,
                "address": str(symbol.getAddress()),
                "type": str(symbol.getSymbolType()),
            }
        )
    return {
        "program": entry.key,
        "total": total,
        "truncated": total > limit,
        "libraries": {k: v for k, v in sorted(grouped.items())},
    }


@op("exports")
def exports(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Exported symbols, i.e. what other modules can call."""
    entry = session.resolve(params)
    limit = clamp(params.get("limit"), 1, 5000, 500)
    table = entry.program.getSymbolTable()
    out = []
    total = 0
    for symbol in table.getAllSymbols(True):
        try:
            if not symbol.isExternalEntryPoint():
                continue
        except Exception:
            continue
        total += 1
        if total > limit:
            continue
        out.append(
            {
                "name": str(symbol.getName()),
                "address": str(symbol.getAddress()),
                "type": str(symbol.getSymbolType()),
                "namespace": str(symbol.getParentNamespace().getName()),
            }
        )
    return {"program": entry.key, "total": total, "truncated": total > limit, "exports": out}


@op("relocations")
def relocations(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Relocation entries; a stripped or packed binary often has surprisingly few."""
    entry = session.resolve(params)
    limit = clamp(params.get("limit"), 1, 5000, 200)
    table = entry.program.getRelocationTable()
    out = []
    total = 0
    for relocation in table.getRelocations():
        total += 1
        if total > limit:
            continue
        out.append(
            {
                "address": str(relocation.getAddress()),
                "type": int(relocation.getType()),
                "symbol": str(relocation.getSymbolName() or ""),
                "status": str(relocation.getStatus()),
            }
        )
    return {"program": entry.key, "total": total, "truncated": total > limit, "relocations": out}
