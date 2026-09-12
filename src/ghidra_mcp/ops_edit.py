"""Mutating operations: renaming, retyping, commenting, patching, marking up code.

Every operation here changes the program database, so each one runs inside a Ghidra
transaction and saves afterwards. The point of persisting them is that reverse
engineering is cumulative: names and types recovered in one session must still be
there in the next.

``GHIDRA_MCP_READONLY=1`` in the worker's environment turns all of these into errors.
"""

from __future__ import annotations

import os
import re
from typing import Any, Callable

from ghidra_mcp.ghidra_ops import (
    OpError,
    Session,
    clamp,
    from_jbytes,
    function_summary,
    op,
    parse_address,
    resolve_function,
    to_jbytes,
)


def _require_write() -> None:
    if os.environ.get("GHIDRA_MCP_READONLY") == "1":
        raise OpError("this server is running read-only (GHIDRA_MCP_READONLY=1); mutating operations are disabled")


def _source_type(name: str | None = None) -> Any:
    from ghidra.program.model.symbol import SourceType  # type: ignore

    return getattr(SourceType, (name or "USER_DEFINED").upper(), SourceType.USER_DEFINED)


@op("rename")
def rename(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Rename a function, label, or data symbol; create a label if none exists.

    ``target`` may be a function name, an address, or a symbol name. Naming things as
    you understand them is what turns a pile of ``FUN_140001010`` into a readable
    program, and because it is saved, the next session inherits the work.
    """
    _require_write()
    entry = session.resolve(params)
    program = entry.program
    new_name = params.get("new_name") or params.get("name")
    if not new_name:
        raise OpError("'new_name' is required")
    new_name = str(new_name)
    target = params.get("target") or params.get("function") or params.get("address")
    if not target:
        raise OpError("'target' (function name, symbol, or address) is required")

    source = _source_type(params.get("source_type"))
    result: dict[str, Any] = {"program": entry.key, "new_name": new_name}

    with session.transaction(entry, f"MCP rename -> {new_name}"):
        function = None
        try:
            function = resolve_function(program, target)
        except OpError:
            function = None

        if function is not None and not params.get("label_only"):
            result["kind"] = "function"
            result["old_name"] = str(function.getName())
            result["entry"] = str(function.getEntryPoint())
            function.setName(new_name, source)
        else:
            address = parse_address(program, target)
            table = program.getSymbolTable()
            symbol = table.getPrimarySymbol(address)
            if symbol is not None:
                result["kind"] = "symbol"
                result["old_name"] = str(symbol.getName())
                symbol.setName(new_name, source)
            else:
                table.createLabel(address, new_name, source)
                result["kind"] = "new_label"
                result["old_name"] = None
            result["address"] = str(address)

    session.save(entry)
    return result


@op("set_comment")
def set_comment(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Attach a comment at an address.

    Comment types: ``EOL`` (end of line), ``PRE``, ``POST``, ``PLATE`` (a banner above
    a function) and ``REPEATABLE``. Write findings down here rather than only in chat:
    the comment survives into the next session and into the Ghidra GUI.
    """
    _require_write()
    entry = session.resolve(params)
    program = entry.program
    address = parse_address(program, params.get("address") or params.get("target"))
    comment_type = session.comment_type(str(params.get("type") or "EOL"))
    text = params.get("comment")
    if text is None:
        text = params.get("text")
    append = bool(params.get("append"))

    listing = program.getListing()
    with session.transaction(entry, "MCP comment"):
        existing = listing.getComment(comment_type, address)
        if text is None or text == "":
            listing.setComment(address, comment_type, None)
            new_value = None
        elif append and existing:
            new_value = f"{existing}\n{text}"
            listing.setComment(address, comment_type, new_value)
        else:
            new_value = str(text)
            listing.setComment(address, comment_type, new_value)

    session.save(entry)
    return {
        "program": entry.key,
        "address": str(address),
        "type": str(params.get("type") or "EOL").upper(),
        "previous": str(existing) if existing else None,
        "comment": new_value,
    }


@op("set_function_comment")
def set_function_comment(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Set the function-level comment shown in the decompiler header."""
    _require_write()
    entry = session.resolve(params)
    function = resolve_function(entry.program, params.get("function") or params.get("target"))
    text = params.get("comment") or params.get("text") or ""
    with session.transaction(entry, "MCP function comment"):
        previous = function.getComment()
        function.setComment(str(text) if text else None)
    session.save(entry)
    return {
        "program": entry.key,
        "function": str(function.getName()),
        "previous": str(previous) if previous else None,
        "comment": str(text) if text else None,
    }


@op("set_signature")
def set_signature(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Apply a C prototype to a function.

    Pass a full declaration: ``int decrypt(char *buf, int len, unsigned char key)``.
    Fixing a signature is often what makes the decompiled body suddenly readable, so
    do it before re-reading the C output rather than after giving up on it.
    """
    _require_write()
    entry = session.resolve(params)
    program = entry.program
    function = resolve_function(program, params.get("function") or params.get("target"))
    signature = params.get("signature") or params.get("prototype")
    if not signature:
        raise OpError("'signature' is required, e.g. 'int decrypt(char *buf, int len)'")
    signature = str(signature).strip()
    if not signature.endswith(";"):
        signature += ";"

    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd  # type: ignore
    from ghidra.app.util.cparser.C import CParserUtils  # type: ignore
    from jpype import JClass  # type: ignore

    before = str(function.getSignature().getPrototypeString())
    with session.transaction(entry, "MCP set signature"):
        try:
            # parseSignature is overloaded on its first parameter (ServiceProvider vs
            # DataTypeManagerService) and a bare None is ambiguous to JPype. Casting the
            # null picks the DataTypeManagerService overload, which tolerates a null
            # service and resolves types out of the program itself.
            service = JClass("ghidra.app.services.DataTypeManagerService") @ None
            definition = CParserUtils.parseSignature(service, program, signature)
        except Exception as exc:
            raise OpError(
                f"could not parse '{signature}': {exc}. Use plain C with named parameters "
                "and types Ghidra knows (see the data_types operation)."
            ) from exc
        if definition is None:
            raise OpError(f"could not parse signature '{signature}'")
        command = ApplyFunctionSignatureCmd(function.getEntryPoint(), definition, _source_type(params.get("source_type")))
        if not command.applyTo(program, session.monitor()):
            raise OpError(f"applying the signature failed: {command.getStatusMsg()}")

    session.save(entry)
    return {
        "program": entry.key,
        "function": str(function.getName()),
        "signature_before": before,
        "signature_after": str(function.getSignature().getPrototypeString()),
    }


@op("set_variable")
def set_variable(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Rename or retype a parameter or local variable inside a function.

    Most variables you see in decompiled C (``uVar1``, ``local_28``) exist only in the
    decompiler's view, not in the program database, so this first looks for a real
    database variable and falls back to committing the decompiler's symbol through
    ``HighFunctionDBUtil``. That fallback is what makes renaming a stack local work at
    all, and it is why this needs a decompile pass rather than a simple setter.
    """
    _require_write()
    entry = session.resolve(params)
    program = entry.program
    function = resolve_function(program, params.get("function"))
    variable_name = params.get("variable")
    if not variable_name:
        raise OpError("'variable' is required (the current name, as it appears in the decompilation)")
    variable_name = str(variable_name)
    new_name = params.get("new_name")
    new_type = params.get("type")
    if not new_name and not new_type:
        raise OpError("pass 'new_name' and/or 'type'")

    source = _source_type(params.get("source_type"))

    def parse_type(text: str) -> Any:
        from ghidra.util.data import DataTypeParser  # type: ignore

        manager = program.getDataTypeManager()
        parser = DataTypeParser(manager, manager, None, DataTypeParser.AllowedDataTypes.ALL)
        try:
            return parser.parse(str(text))
        except Exception as exc:
            raise OpError(f"could not parse type '{text}': {exc}") from exc

    # 1. A real database variable (a committed parameter or local).
    matches = [v for v in function.getAllVariables() if str(v.getName()) == variable_name]
    if matches:
        variable = matches[0]
        before = {"name": str(variable.getName()), "type": str(variable.getDataType().getName())}
        with session.transaction(entry, "MCP set variable"):
            if new_type:
                variable.setDataType(parse_type(str(new_type)), source)
            if new_name:
                variable.setName(str(new_name), source)
        session.save(entry)
        return {
            "program": entry.key,
            "function": str(function.getName()),
            "via": "database_variable",
            "before": before,
            "after": {"name": str(variable.getName()), "type": str(variable.getDataType().getName())},
        }

    # 2. A decompiler-only symbol: commit it to the database.
    timeout = clamp(params.get("timeout"), 5, 300, 60)
    interface = session.decompiler(entry)
    results = interface.decompileFunction(function, timeout, session.monitor())
    high_function = results.getHighFunction()
    if high_function is None:
        raise OpError(
            f"could not decompile {function.getName()} to look up '{variable_name}': "
            f"{results.getErrorMessage() or 'unknown error'}"
        )

    symbol_map = high_function.getLocalSymbolMap()
    high_symbol = None
    available: list[str] = []
    for candidate in symbol_map.getSymbols():
        name = str(candidate.getName())
        available.append(name)
        if name == variable_name:
            high_symbol = candidate
            break
    if high_symbol is None:
        raise OpError(
            f"'{variable_name}' is not a variable of {function.getName()}. "
            f"Decompiler variables here: {', '.join(sorted(set(available))[:20]) or '(none)'}"
        )

    before = {"name": str(high_symbol.getName()), "type": str(high_symbol.getDataType().getName())}
    from ghidra.program.model.pcode import HighFunctionDBUtil  # type: ignore

    with session.transaction(entry, "MCP set variable (decompiler)"):
        data_type = parse_type(str(new_type)) if new_type else high_symbol.getDataType()
        try:
            HighFunctionDBUtil.updateDBVariable(
                high_symbol,
                str(new_name) if new_name else str(high_symbol.getName()),
                data_type,
                source,
            )
        except Exception as exc:
            raise OpError(f"could not update '{variable_name}': {type(exc).__name__}: {exc}") from exc

    session.save(entry)
    return {
        "program": entry.key,
        "function": str(function.getName()),
        "via": "decompiler_symbol",
        "before": before,
        "after": {
            "name": str(new_name) if new_name else before["name"],
            "type": str(new_type) if new_type else before["type"],
        },
        "note": "committed the decompiler's symbol to the database",
    }


@op("apply_data_type")
def apply_data_type(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Apply a data type at an address, turning undefined bytes into a typed value."""
    _require_write()
    entry = session.resolve(params)
    program = entry.program
    address = parse_address(program, params.get("address"))
    type_name = params.get("type")
    if not type_name:
        raise OpError("'type' is required, e.g. 'int', 'char[32]', 'IMAGE_DOS_HEADER'")

    from ghidra.util.data import DataTypeParser  # type: ignore

    manager = program.getDataTypeManager()
    parser = DataTypeParser(manager, manager, None, DataTypeParser.AllowedDataTypes.ALL)
    try:
        data_type = parser.parse(str(type_name))
    except Exception as exc:
        raise OpError(f"could not parse type '{type_name}': {exc}") from exc

    listing = program.getListing()
    with session.transaction(entry, f"MCP apply type {type_name}"):
        if params.get("clear_existing", True):
            length = max(1, int(data_type.getLength()))
            try:
                listing.clearCodeUnits(address, address.add(length - 1), False)
            except Exception:
                pass
        try:
            created = listing.createData(address, data_type)
        except Exception as exc:
            raise OpError(f"could not apply {type_name} at {address}: {exc}") from exc

    session.save(entry)
    return {
        "program": entry.key,
        "address": str(address),
        "type": str(data_type.getName()),
        "length": int(created.getLength()) if created is not None else None,
        "value": str(created.getValue())[:500] if created is not None and created.getValue() is not None else None,
    }


@op("create_function")
def create_function(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Define a function at an address Ghidra did not recognise as one.

    Useful after finding a call target in obfuscated code, where auto-analysis left
    the bytes undefined.
    """
    _require_write()
    entry = session.resolve(params)
    program = entry.program
    address = parse_address(program, params.get("address"))
    name = params.get("name")

    from ghidra.app.cmd.function import CreateFunctionCmd  # type: ignore

    manager = program.getFunctionManager()
    existing = manager.getFunctionAt(address)
    if existing is not None and not params.get("recreate"):
        return {
            "program": entry.key,
            "created": function_summary(existing),
            "already_existed": True,
            "note": "a function already starts here; pass recreate=true to rebuild its body",
        }

    with session.transaction(entry, "MCP create function"):
        command = CreateFunctionCmd(str(name) if name else None, address, None, _source_type(params.get("source_type")))
        applied = bool(command.applyTo(program, session.monitor()))
        function = command.getFunction() or manager.getFunctionAt(address)
        if function is None:
            status = str(command.getStatusMsg() or "")
            hint = ""
            listing_unit = program.getListing().getCodeUnitAt(address)
            if listing_unit is not None and not hasattr(listing_unit, "getMnemonicString"):
                hint = " There is data here, not code: try disassemble_at first."
            raise OpError(f"could not create a function at {address}: {status or 'no reason given'}.{hint}")

    session.save(entry)
    return {
        "program": entry.key,
        "created": function_summary(function),
        "applied": applied,
        "already_existed": False,
    }


@op("disassemble_at")
def disassemble_at(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Force disassembly at an address, for bytes analysis left as data."""
    _require_write()
    entry = session.resolve(params)
    program = entry.program
    address = parse_address(program, params.get("address"))

    from ghidra.app.cmd.disassemble import DisassembleCommand  # type: ignore

    with session.transaction(entry, "MCP disassemble"):
        command = DisassembleCommand(address, None, bool(params.get("follow_flow", True)))
        ok = bool(command.applyTo(program, session.monitor()))
        disassembled = command.getDisassembledAddressSet()

    session.save(entry)
    return {
        "program": entry.key,
        "address": str(address),
        "ok": ok,
        "status": str(command.getStatusMsg() or ""),
        "instructions_created": int(disassembled.getNumAddresses()) if disassembled is not None else 0,
    }


@op("patch_bytes")
def patch_bytes(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Overwrite bytes in the program database.

    This changes the *analysis*, not the file on disk: use the ``export`` operation
    with ``format='binary'`` to write a patched file out. Patching over existing
    instructions needs ``clear_instructions=true``, because Ghidra refuses to let a
    write silently invalidate disassembly.
    """
    _require_write()
    entry = session.resolve(params)
    program = entry.program
    address = parse_address(program, params.get("address"))

    hex_bytes = params.get("hex")
    assembly = params.get("assembly") or params.get("asm")
    if not hex_bytes and not assembly:
        raise OpError("pass 'hex' (e.g. '90 90') or 'assembly' (e.g. 'NOP' / 'MOV EAX,1')")

    if assembly:
        from ghidra.app.plugin.assembler import Assemblers  # type: ignore

        assembler = Assemblers.getAssembler(program)
        try:
            encoded = assembler.assembleLine(address, str(assembly))
        except Exception as exc:
            raise OpError(f"could not assemble '{assembly}' at {address}: {exc}") from exc
        payload = from_jbytes(encoded)
    else:
        cleaned = re.sub(r"[\s,]+", "", str(hex_bytes)).replace("\\x", "").replace("0x", "")
        if len(cleaned) % 2 != 0:
            raise OpError("hex must have an even number of nibbles")
        try:
            payload = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise OpError(f"'{hex_bytes}' is not valid hex: {exc}") from exc

    if not payload:
        raise OpError("nothing to write")

    from jpype import JArray, JByte  # type: ignore

    memory = program.getMemory()
    listing = program.getListing()

    buffer = JArray(JByte)(len(payload))
    memory.getBytes(address, buffer, 0, len(payload))
    before = from_jbytes(buffer, len(payload))

    with session.transaction(entry, "MCP patch bytes"):
        if params.get("clear_instructions", True):
            try:
                listing.clearCodeUnits(address, address.add(len(payload) - 1), False)
            except Exception:
                pass
        try:
            memory.setBytes(address, to_jbytes(payload))
        except Exception as exc:
            raise OpError(
                f"could not write {len(payload)} bytes at {address}: {exc}. "
                "If this reports a conflict with an instruction, pass clear_instructions=true."
            ) from exc
        if params.get("redisassemble", True):
            from ghidra.app.cmd.disassemble import DisassembleCommand  # type: ignore

            DisassembleCommand(address, None, True).applyTo(program, session.monitor())

    session.save(entry)
    return {
        "program": entry.key,
        "address": str(address),
        "length": len(payload),
        "before": before.hex(),
        "after": payload.hex(),
        "assembled_from": str(assembly) if assembly else None,
        "note": "changed in the Ghidra database only; use export format='binary' to write a file",
    }


@op("assemble")
def assemble(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Assemble an instruction without writing it, to see its encoding."""
    entry = session.resolve(params)
    program = entry.program
    address = parse_address(program, params.get("address") or str(program.getMinAddress()))
    text = params.get("assembly") or params.get("asm")
    if not text:
        raise OpError("'assembly' is required, e.g. 'JMP 0x140001010'")

    from ghidra.app.plugin.assembler import Assemblers  # type: ignore

    assembler = Assemblers.getAssembler(program)
    try:
        encoded = assembler.assembleLine(address, str(text))
    except Exception as exc:
        raise OpError(f"could not assemble '{text}' at {address}: {exc}") from exc
    payload = from_jbytes(encoded)
    return {
        "program": entry.key,
        "address": str(address),
        "assembly": str(text),
        "hex": payload.hex(),
        "length": len(payload),
    }


@op("bookmark")
def bookmark(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Add a bookmark, which is how you leave a trail a human can follow in the GUI."""
    _require_write()
    entry = session.resolve(params)
    program = entry.program
    address = parse_address(program, params.get("address"))
    category = str(params.get("category") or "MCP")
    comment = str(params.get("comment") or params.get("note") or "")
    kind = str(params.get("type") or "Note")

    with session.transaction(entry, "MCP bookmark"):
        program.getBookmarkManager().setBookmark(address, kind, category, comment)

    session.save(entry)
    return {"program": entry.key, "address": str(address), "type": kind, "category": category, "comment": comment}


@op("list_bookmarks")
def list_bookmarks(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """List bookmarks, so a later session can pick up where this one stopped."""
    entry = session.resolve(params)
    manager = entry.program.getBookmarkManager()
    limit = clamp(params.get("limit"), 1, 2000, 200)
    out = []
    for bookmark_entry in manager.getBookmarksIterator():
        out.append(
            {
                "address": str(bookmark_entry.getAddress()),
                "type": str(bookmark_entry.getTypeString()),
                "category": str(bookmark_entry.getCategory()),
                "comment": str(bookmark_entry.getComment()),
            }
        )
        if len(out) >= limit:
            break
    return {"program": entry.key, "count": len(out), "bookmarks": out}


@op("clear")
def clear(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Clear code units in a range, undoing bad disassembly so it can be redone."""
    _require_write()
    entry = session.resolve(params)
    program = entry.program
    start = parse_address(program, params.get("address") or params.get("start"))
    length = clamp(params.get("length"), 1, 1 << 24, 16)
    end = start.add(length - 1)

    with session.transaction(entry, "MCP clear"):
        program.getListing().clearCodeUnits(start, end, bool(params.get("clear_context", False)))

    session.save(entry)
    return {"program": entry.key, "start": str(start), "end": str(end), "length": length}
