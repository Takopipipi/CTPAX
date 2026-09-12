"""Code-level operations: functions, decompilation, disassembly, references, call graph."""

from __future__ import annotations

import re
import time
from typing import Any, Callable

from ghidra_mcp.ghidra_ops import (
    OpError,
    Session,
    clamp,
    function_summary,
    op,
    parse_address,
    resolve_function,
)


def _decompile(session: Session, entry: Any, function: Any, timeout: int) -> tuple[str, Any]:
    """Decompile one function, returning ``(c_source, decompile_results)``."""
    interface = session.decompiler(entry)
    results = interface.decompileFunction(function, timeout, session.monitor())
    if not results.decompileCompleted():
        raise OpError(
            f"decompilation of {function.getName()} failed: {results.getErrorMessage() or 'unknown error'}"
        )
    decompiled = results.getDecompiledFunction()
    return (str(decompiled.getC()) if decompiled is not None else ""), results


@op("functions")
def functions(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """List functions, newest-analysis order, with filtering worth using on a big binary.

    ``filter`` matches the name as a substring; ``regex`` matches it as a pattern;
    ``named_only`` drops Ghidra's auto-generated ``FUN_*`` so you see what the binary
    actually told us about itself; ``section`` keeps only functions whose entry point
    lives in the named memory block (``.text``, ``.rdata``...).
    """
    entry = session.resolve(params)
    limit = clamp(params.get("limit"), 1, 5000, 200)
    offset = clamp(params.get("offset"), 0, 10**7, 0)
    name_filter = (params.get("filter") or "").lower()
    pattern = re.compile(params.get("regex")) if params.get("regex") else None
    named_only = bool(params.get("named_only"))
    min_size = clamp(params.get("min_size"), 0, 10**9, 0)
    include_external = bool(params.get("include_external", False))
    include_thunks = bool(params.get("include_thunks", True))
    sort = str(params.get("sort") or "address").lower()
    section_filter = (str(params.get("section")).lower().lstrip(".")) if params.get("section") else None
    memory = entry.program.getMemory()

    collected: list[Any] = []
    manager = entry.program.getFunctionManager()
    for function in manager.getFunctions(True):
        name = str(function.getName())
        if named_only and (name.startswith("FUN_") or name.startswith("SUB_")):
            continue
        if not include_external and function.isExternal():
            continue
        if not include_thunks and function.isThunk():
            continue
        if name_filter and name_filter not in name.lower():
            continue
        if pattern is not None and not pattern.search(name):
            continue
        if min_size and int(function.getBody().getNumAddresses()) < min_size:
            continue
        if section_filter:
            block = memory.getBlock(function.getEntryPoint())
            if block is None or str(block.getName()).lower().lstrip(".") != section_filter:
                continue
        collected.append(function)

    if sort == "size":
        collected.sort(key=lambda f: int(f.getBody().getNumAddresses()), reverse=True)
    elif sort == "name":
        collected.sort(key=lambda f: str(f.getName()).lower())

    total = len(collected)
    page = collected[offset : offset + limit]
    return {
        "program": entry.key,
        "total": total,
        "offset": offset,
        "returned": len(page),
        "next_offset": (offset + len(page)) if offset + len(page) < total else None,
        "functions": [function_summary(f) for f in page],
    }


@op("function")
def function_detail(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Full detail for one function: signature, variables, callers, callees."""
    entry = session.resolve(params)
    function = resolve_function(entry.program, params.get("function") or params.get("name") or params.get("address"))
    summary = function_summary(function)
    summary["return_type"] = str(function.getReturnType().getName())
    summary["stack_frame_size"] = int(function.getStackFrame().getFrameSize())
    summary["no_return"] = bool(function.hasNoReturn())
    summary["varargs"] = bool(function.hasVarArgs())
    summary["parameters"] = [
        {
            "name": str(p.getName()),
            "type": str(p.getDataType().getName()),
            "storage": str(p.getVariableStorage()),
        }
        for p in function.getParameters()
    ]
    summary["local_variables"] = [
        {
            "name": str(v.getName()),
            "type": str(v.getDataType().getName()),
            "storage": str(v.getVariableStorage()),
        }
        for v in function.getLocalVariables()
    ]
    summary["calls"] = sorted({str(f.getName()) for f in function.getCalledFunctions(session.monitor())})
    summary["called_by"] = sorted({str(f.getName()) for f in function.getCallingFunctions(session.monitor())})
    summary["tags"] = [str(t.getName()) for t in function.getTags()]
    comment = function.getComment()
    if comment:
        summary["comment"] = str(comment)
    summary["program"] = entry.key
    return summary


@op("decompile")
def decompile(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Decompile a function to C.

    This is the single most useful operation in the server, and the most expensive.
    Prefer naming one function over decompiling everything. When the target is an
    address with no function (stripped binaries), a function is created at that
    address automatically so the decompiler has something to chew - the creation is
    reported in the response rather than silently persisting.
    """
    entry = session.resolve(params)
    timeout = clamp(params.get("timeout"), 5, 600, 90)
    target = params.get("function") or params.get("name") or params.get("address")
    created_here = False
    try:
        function = resolve_function(entry.program, target)
    except OpError:
        # Stripped binaries: an address with no function is the normal case, and the
        # decompiler can still produce meaningful C from code at that address.
        if params.get("address"):
            from ghidra.app.cmd.function import CreateFunctionCmd  # type: ignore

            address = parse_address(entry.program, params["address"])
            command = CreateFunctionCmd(address)
            if command.applyTo(entry.program, session.monitor()):
                created_here = True
                function = resolve_function(entry.program, target)
            else:
                raise OpError(
                    f"cannot decompile {target}: no function there and auto-create failed "
                    f"({command.getStatusMsg()}); disassemble the address first"
                )
        else:
            raise
    started = time.time()
    source, results = _decompile(session, entry, function, timeout)

    result: dict[str, Any] = {
        "program": entry.key,
        "function": str(function.getName()),
        "entry": str(function.getEntryPoint()),
        "signature": str(function.getSignature().getPrototypeString()),
        "seconds": round(time.time() - started, 2),
        "c": source,
    }
    if created_here:
        result["note"] = (
            f"a function was created at {target} to decompile it; it persists in the analysis - "
            "disassemble it by hand if the guess was wrong"
        )
    if params.get("include_line_addresses"):
        # Map decompiled line numbers to addresses, which is how you connect a line of
        # C back to the instruction that produced it.
        markup = results.getCCodeMarkup()
        mapping: dict[int, list[str]] = {}
        if markup is not None:
            stack = [markup]
            while stack:
                node = stack.pop()
                try:
                    line = node.getLineParent()
                    address = node.getMinAddress()
                    if line is not None and address is not None:
                        mapping.setdefault(int(line.getLineNumber()), []).append(str(address))
                except Exception:
                    pass
                try:
                    for index in range(node.numChildren()):
                        stack.append(node.Child(index))
                except Exception:
                    pass
        result["line_addresses"] = {str(k): sorted(set(v)) for k, v in sorted(mapping.items())}
    return result


@op("decompile_many")
def decompile_many(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Decompile several functions in one round trip.

    Intended for a small named set (a call chain, a cluster of handlers), not for
    dumping a whole binary: the output cap will truncate that anyway.
    """
    entry = session.resolve(params)
    targets = params.get("functions") or []
    if isinstance(targets, str):
        targets = [targets]
    if not targets:
        raise OpError("'functions' must be a non-empty list of names or addresses")
    limit = clamp(params.get("limit"), 1, 40, 12)
    timeout = clamp(params.get("timeout"), 5, 600, 60)
    out = []
    for index, target in enumerate(targets[:limit]):
        session.check_cancel()
        progress(stage="decompile", index=index, target=str(target))
        try:
            function = resolve_function(entry.program, target)
            source, _ = _decompile(session, entry, function, timeout)
            out.append(
                {
                    "function": str(function.getName()),
                    "entry": str(function.getEntryPoint()),
                    "c": source,
                }
            )
        except Exception as exc:
            out.append({"target": str(target), "error": f"{type(exc).__name__}: {exc}"})
    return {"program": entry.key, "requested": len(targets), "returned": len(out), "results": out}


@op("disassemble")
def disassemble(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Listing-level disassembly for a function or an address range."""
    entry = session.resolve(params)
    program = entry.program
    listing = program.getListing()
    limit = clamp(params.get("limit"), 1, 20000, 400)

    target = params.get("function") or params.get("name")
    if target:
        function = resolve_function(program, target)
        iterator = listing.getInstructions(function.getBody(), True)
        scope = {"function": str(function.getName()), "entry": str(function.getEntryPoint())}
    else:
        address = parse_address(program, params.get("address"))
        iterator = listing.getInstructions(address, True)
        scope = {"start": str(address)}

    instructions = []
    for index, instruction in enumerate(iterator):
        if index >= limit:
            break
        record: dict[str, Any] = {
            "address": str(instruction.getAddress()),
            "bytes": bytes((int(b) & 0xFF) for b in instruction.getBytes()).hex(),
            "mnemonic": str(instruction.getMnemonicString()),
            "text": str(instruction),
        }
        if params.get("include_comments"):
            from ghidra.program.model.listing import CodeUnit  # type: ignore

            for label, kind in (("eol", "EOL"), ("pre", "PRE"), ("post", "POST")):
                try:
                    comment = instruction.getComment(session.comment_type(kind))
                except Exception:
                    comment = None
                if comment:
                    record[f"comment_{label}"] = str(comment)
        flows = [str(a) for a in instruction.getFlows()]
        if flows:
            record["flows"] = flows
        instructions.append(record)

    result = {"program": entry.key, "count": len(instructions), "instructions": instructions}
    result.update(scope)
    return result


@op("xrefs")
def xrefs(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """References to and from addresses, functions, or symbols - one or many targets.

    ``direction`` is ``to`` (who reaches this), ``from`` (what this reaches) or
    ``both``. ``targets`` accepts a list (names or addresses) for call-graph work in
    one round trip; a single ``address``/``function`` also works.
    """
    entry = session.resolve(params)
    program = entry.program
    manager = program.getReferenceManager()
    function_manager = program.getFunctionManager()
    limit = clamp(params.get("limit"), 1, 5000, 200)
    direction = str(params.get("direction") or "to").lower()

    targets: list[str] = []
    if params.get("targets"):
        raw = params["targets"]
        targets = [str(t) for t in raw] if isinstance(raw, list) else [str(raw)]
    elif params.get("address") or params.get("function") or params.get("name"):
        targets = [str(params.get("address") or params.get("function") or params.get("name"))]
    if not targets:
        raise OpError("pass 'targets' (list) or 'address'/'function'")

    def describe(reference: Any, which: str) -> dict[str, Any]:
        from_address = reference.getFromAddress()
        to_address = reference.getToAddress()
        record = {
            "direction": which,
            "from": str(from_address),
            "to": str(to_address),
            "type": str(reference.getReferenceType()),
            "operand": int(reference.getOperandIndex()),
            "primary": bool(reference.isPrimary()),
        }
        holder = function_manager.getFunctionContaining(from_address)
        if holder is not None:
            record["from_function"] = str(holder.getName())
        target_function = function_manager.getFunctionAt(to_address)
        if target_function is not None:
            record["to_function"] = str(target_function.getName())
        symbol = program.getSymbolTable().getPrimarySymbol(to_address)
        if symbol is not None:
            record["to_symbol"] = str(symbol.getName())
        return record

    results: dict[str, Any] = {"program": entry.key, "direction": direction, "targets": {}, "count": 0}
    truncated = False
    for target in targets:
        try:
            address = parse_address(program, target)
        except OpError:
            address = resolve_function(program, target).getEntryPoint()
        out: list[dict[str, Any]] = []
        if direction in ("to", "both"):
            for reference in manager.getReferencesTo(address):
                if len(out) >= limit:
                    truncated = True
                    break
                out.append(describe(reference, "to"))
        if direction in ("from", "both"):
            for reference in manager.getReferencesFrom(address):
                if len(out) >= limit:
                    truncated = True
                    break
                out.append(describe(reference, "from"))
        results["targets"][target] = {"address": str(address), "count": len(out), "references": out}
        results["count"] += len(out)

    results["truncated"] = truncated
    return results


@op("callgraph")
def callgraph(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Walk callers or callees breadth-first from one function.

    Use this to answer "how is this reached" without decompiling the whole path.
    """
    entry = session.resolve(params)
    program = entry.program
    function = resolve_function(program, params.get("function") or params.get("name") or params.get("address"))
    depth = clamp(params.get("depth"), 1, 6, 2)
    direction = str(params.get("direction") or "callees").lower()
    max_nodes = clamp(params.get("max_nodes"), 1, 4000, 300)
    monitor = session.monitor()

    seen = {str(function.getEntryPoint())}
    nodes = [{"name": str(function.getName()), "entry": str(function.getEntryPoint()), "depth": 0}]
    edges: list[dict[str, str]] = []
    frontier = [function]

    for level in range(1, depth + 1):
        next_frontier = []
        for current in frontier:
            session.check_cancel()
            if direction == "callers":
                neighbours = current.getCallingFunctions(monitor)
            else:
                neighbours = current.getCalledFunctions(monitor)
            for neighbour in neighbours:
                key = str(neighbour.getEntryPoint())
                if direction == "callers":
                    edges.append({"from": str(neighbour.getName()), "to": str(current.getName())})
                else:
                    edges.append({"from": str(current.getName()), "to": str(neighbour.getName())})
                if key in seen:
                    continue
                seen.add(key)
                nodes.append(
                    {
                        "name": str(neighbour.getName()),
                        "entry": key,
                        "depth": level,
                        "external": bool(neighbour.isExternal()),
                    }
                )
                if len(nodes) >= max_nodes:
                    break
                next_frontier.append(neighbour)
            if len(nodes) >= max_nodes:
                break
        if len(nodes) >= max_nodes:
            break
        frontier = next_frontier
        if not frontier:
            break

    # De-duplicate edges while preserving order.
    unique_edges = []
    seen_edges = set()
    for edge in edges:
        signature = (edge["from"], edge["to"])
        if signature in seen_edges:
            continue
        seen_edges.add(signature)
        unique_edges.append(edge)

    return {
        "program": entry.key,
        "root": str(function.getName()),
        "direction": direction,
        "depth": depth,
        "truncated": len(nodes) >= max_nodes,
        "node_count": len(nodes),
        "nodes": nodes,
        "edges": unique_edges,
    }


@op("decompile_grep")
def decompile_grep(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Search decompiled C across functions.

    This is how you find behaviour rather than names: grepping for ``VirtualAlloc``,
    ``0x1000``, or ``^ *while`` across the decompilation finds the code that does a
    thing even when every symbol is stripped. It decompiles as it goes, so bound it
    with ``max_functions``, ``filter`` or ``min_size``.
    """
    entry = session.resolve(params)
    query = params.get("query")
    if not query:
        raise OpError("'query' is required")
    is_regex = bool(params.get("regex"))
    case_sensitive = bool(params.get("case_sensitive", False))
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(str(query) if is_regex else re.escape(str(query)), flags)

    max_functions = clamp(params.get("max_functions"), 1, 6000, 400)
    max_hits = clamp(params.get("max_hits"), 1, 500, 60)
    context = clamp(params.get("context_lines"), 0, 10, 2)
    timeout = clamp(params.get("timeout"), 5, 300, 45)
    name_filter = (params.get("filter") or "").lower()
    min_size = clamp(params.get("min_size"), 0, 10**9, 0)

    candidates = []
    for function in entry.program.getFunctionManager().getFunctions(True):
        if function.isExternal() or function.isThunk():
            continue
        name = str(function.getName())
        if name_filter and name_filter not in name.lower():
            continue
        if min_size and int(function.getBody().getNumAddresses()) < min_size:
            continue
        candidates.append(function)
        if len(candidates) >= max_functions:
            break

    hits: list[dict[str, Any]] = []
    scanned = 0
    failed = 0
    started = time.time()
    for function in candidates:
        session.check_cancel()
        scanned += 1
        if scanned % 25 == 0:
            progress(stage="grep", scanned=scanned, of=len(candidates), hits=len(hits))
        try:
            source, _ = _decompile(session, entry, function, timeout)
        except Exception:
            failed += 1
            continue
        lines = source.splitlines()
        for number, line in enumerate(lines):
            if not pattern.search(line):
                continue
            low = max(0, number - context)
            high = min(len(lines), number + context + 1)
            hits.append(
                {
                    "function": str(function.getName()),
                    "entry": str(function.getEntryPoint()),
                    "line": number + 1,
                    "text": line.strip(),
                    "context": "\n".join(lines[low:high]),
                }
            )
            break  # one hit per function keeps the result readable
        if len(hits) >= max_hits:
            break

    return {
        "program": entry.key,
        "query": str(query),
        "regex": is_regex,
        "functions_scanned": scanned,
        "functions_considered": len(candidates),
        "decompile_failures": failed,
        "seconds": round(time.time() - started, 1),
        "hit_count": len(hits),
        "truncated": len(hits) >= max_hits,
        "hits": hits,
    }


@op("pcode")
def pcode(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """P-code for a function: the IR Ghidra reasons over, useful when C output lies."""
    entry = session.resolve(params)
    function = resolve_function(entry.program, params.get("function") or params.get("address"))
    limit = clamp(params.get("limit"), 1, 20000, 500)
    timeout = clamp(params.get("timeout"), 5, 300, 60)
    high_level = bool(params.get("high", True))

    if high_level:
        interface = session.decompiler(entry)
        results = interface.decompileFunction(function, timeout, session.monitor())
        high_function = results.getHighFunction()
        if high_function is None:
            raise OpError(f"no high-level p-code for {function.getName()}: {results.getErrorMessage()}")
        out = []
        for index, operation in enumerate(high_function.getPcodeOps()):
            if index >= limit:
                break
            out.append(
                {
                    "seq": str(operation.getSeqnum()),
                    "op": str(operation.getMnemonic()),
                    "output": str(operation.getOutput()) if operation.getOutput() is not None else None,
                    "inputs": [str(operation.getInput(i)) for i in range(operation.getNumInputs())],
                }
            )
        return {
            "program": entry.key,
            "function": str(function.getName()),
            "level": "high",
            "count": len(out),
            "pcode": out,
        }

    listing = entry.program.getListing()
    out = []
    for instruction in listing.getInstructions(function.getBody(), True):
        for operation in instruction.getPcode():
            if len(out) >= limit:
                break
            out.append({"address": str(instruction.getAddress()), "raw": str(operation)})
        if len(out) >= limit:
            break
    return {
        "program": entry.key,
        "function": str(function.getName()),
        "level": "raw",
        "count": len(out),
        "pcode": out,
    }


@op("symbols")
def symbols(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Search the symbol table by name, type, or namespace."""
    entry = session.resolve(params)
    limit = clamp(params.get("limit"), 1, 5000, 200)
    offset = clamp(params.get("offset"), 0, 10**7, 0)
    name_filter = (params.get("filter") or "").lower()
    pattern = re.compile(params.get("regex")) if params.get("regex") else None
    wanted_type = (params.get("type") or "").upper()

    table = entry.program.getSymbolTable()
    collected = []
    for symbol in table.getAllSymbols(bool(params.get("include_dynamic", False))):
        name = str(symbol.getName())
        if name_filter and name_filter not in name.lower():
            continue
        if pattern is not None and not pattern.search(name):
            continue
        symbol_type = str(symbol.getSymbolType()).upper()
        if wanted_type and wanted_type not in symbol_type:
            continue
        collected.append(
            {
                "name": name,
                "address": str(symbol.getAddress()),
                "type": str(symbol.getSymbolType()),
                "namespace": str(symbol.getParentNamespace().getName()),
                "source": str(symbol.getSource()),
                "primary": bool(symbol.isPrimary()),
                "external": bool(symbol.isExternal()),
            }
        )

    total = len(collected)
    page = collected[offset : offset + limit]
    return {
        "program": entry.key,
        "total": total,
        "offset": offset,
        "returned": len(page),
        "next_offset": (offset + len(page)) if offset + len(page) < total else None,
        "symbols": page,
    }
