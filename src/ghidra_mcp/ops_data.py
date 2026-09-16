"""Data-level operations: strings, bytes, memory search, data types, and Ghidra scripts."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Callable

from ghidra_mcp.ghidra_ops import (
    OpError,
    Session,
    clamp,
    from_jbytes,
    op,
    parse_address,
    to_jbytes,
)


@op("strings")
def _read_string_at(memory: Any, address: Any, charset: str, *, limit: int = 512) -> str:
    """Read a NUL-terminated string around a memory hit (ascii or utf-16)."""
    try:
        raw = bytearray()
        for offset in range(0, limit, 2):
            chunk = memory.getByte(address.add(offset))
            raw.append(chunk & 0xFF)
            if charset == "utf-16" and len(raw) >= 2:
                if raw[-1] == 0 and raw[-2] == 0:
                    break
            elif charset != "utf-16" and chunk == 0:
                break
        data = bytes(raw)
        if charset == "utf-16":
            return data.decode("utf-16-le", "replace").rstrip("\x00")
        return data.decode("latin-1", "replace")
    except Exception:
        return ""


def _raw_string_search(session: Session, program: Any, needle: str, limit: int,
                       collected: list[dict[str, Any]], case_sensitive: bool) -> None:
    """Look for the filter as ASCII and UTF-16LE inside raw memory.

    Ghidra's ``getDefinedData`` only returns strings something already *defined*; on
    stripped or packed images a perfectly visible UTF-16 literal is not in that list,
    which is why ``filter="usage"`` returned nothing on where.exe. This scans memory.
    """
    from ghidra.program.model.data import StringDataInstance  # type: ignore

    from ghidra_mcp.ghidra_ops import to_jbytes

    memory = program.getMemory()
    reference_manager = program.getReferenceManager()
    function_manager = program.getFunctionManager()
    variants: list[tuple[str, bytes]] = []
    for label, encoding in (("ascii", "latin-1"), ("utf-16", "utf-16-le")):
        try:
            text = needle if case_sensitive else needle
            variants.append((label, text.encode(encoding, "ignore")))
        except Exception:
            continue
    for charset, raw in variants:
        if not raw:
            continue
        java_needle = to_jbytes(raw)
        start = program.getMinAddress()
        while len(collected) < limit:
            session.check_cancel()
            try:
                found = memory.findBytes(start, java_needle, None, True, session.monitor())
            except Exception:
                break
            if found is None:
                break
            value = _read_string_at(memory, found, charset)
            if len(value) >= 2:
                record: dict[str, Any] = {
                    "address": str(found),
                    "value": value,
                    "length": len(value),
                    "charset": charset,
                    "data_type": "raw-search",
                    "references": [],
                    "reference_count": 0,
                }
                holder = function_manager.getFunctionContaining(found)
                if holder is not None:
                    record["function"] = str(holder.getName())
                collected.append(record)
            try:
                start = found.add(1)
            except Exception:
                break


def strings(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Defined strings, with the functions that reference them.

    ``with_refs`` is the reason to prefer this over a raw ``strings`` dump: knowing
    which function reaches "license invalid" is usually the entire point.

    When ``filter`` matches nothing among Ghidra's defined strings - common on stripped
    images, where UTF-16 literals are not defined at all - a raw memory search runs in
    both encodings and reports those hits (``data_type: raw-search``). ``deep=True``
    forces that extra pass even when some defined strings matched.
    """
    entry = session.resolve(params)
    program = entry.program
    limit = clamp(params.get("limit"), 1, 20000, 200)
    offset = clamp(params.get("offset"), 0, 10**7, 0)
    min_length = clamp(params.get("min_length"), 1, 4096, 4)
    name_filter = params.get("filter")
    pattern = re.compile(params.get("regex")) if params.get("regex") else None
    with_refs = bool(params.get("with_refs", True))
    case_sensitive = bool(params.get("case_sensitive", False))
    deep = bool(params.get("deep", False))

    from ghidra.program.model.data import StringDataInstance  # type: ignore

    reference_manager = program.getReferenceManager()
    function_manager = program.getFunctionManager()

    collected: list[dict[str, Any]] = []
    for data in program.getListing().getDefinedData(True):
        session.check_cancel()
        instance = StringDataInstance.getStringDataInstance(data)
        if instance == StringDataInstance.NULL_INSTANCE:
            continue
        try:
            value = instance.getStringValue()
        except Exception:
            continue
        if value is None:
            continue
        value = str(value)
        if len(value) < min_length:
            continue
        if name_filter:
            needle = str(name_filter)
            haystack = value if case_sensitive else value.lower()
            if (needle if case_sensitive else needle.lower()) not in haystack:
                continue
        if pattern is not None and not pattern.search(value):
            continue
        record: dict[str, Any] = {
            "address": str(data.getAddress()),
            "value": value,
            "length": len(value),
            "charset": str(instance.getCharsetName()),
            "data_type": str(data.getDataType().getName()),
        }
        if with_refs:
            referrers = []
            for reference in reference_manager.getReferencesTo(data.getAddress()):
                holder = function_manager.getFunctionContaining(reference.getFromAddress())
                referrers.append(
                    {
                        "from": str(reference.getFromAddress()),
                        "function": str(holder.getName()) if holder is not None else None,
                    }
                )
                if len(referrers) >= 8:
                    break
            record["references"] = referrers
            record["reference_count"] = len(referrers)
        collected.append(record)

    searched_memory = False
    if name_filter and (deep or not collected):
        searched_memory = True
        _raw_string_search(session, program, str(name_filter), limit + offset, collected, case_sensitive)

    total = len(collected)
    page = collected[offset : offset + limit]
    return {
        "program": entry.key,
        "total": total,
        "offset": offset,
        "returned": len(page),
        "next_offset": (offset + len(page)) if offset + len(page) < total else None,
        "memory_search_used": searched_memory,
        "strings": page,
    }


@op("read_bytes")
def read_bytes(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Read raw bytes at an address, as hex plus an annotated hexdump."""
    entry = session.resolve(params)
    program = entry.program
    address = parse_address(program, params.get("address"))
    length = clamp(params.get("length"), 1, 1 << 20, 64)

    from jpype import JArray, JByte  # type: ignore

    buffer = JArray(JByte)(length)
    try:
        read = int(program.getMemory().getBytes(address, buffer, 0, length))
    except Exception as exc:
        raise OpError(f"cannot read {length} bytes at {address}: {exc}") from exc
    data = from_jbytes(buffer, read)

    lines = []
    for index in range(0, len(data), 16):
        chunk = data[index : index + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{int(address.getOffset()) + index:08x}  {hex_part}  |{ascii_part}|")

    return {
        "program": entry.key,
        "address": str(address),
        "requested": length,
        "read": read,
        "hex": data.hex(),
        "hexdump": "\n".join(lines),
    }


@op("search_bytes")
def search_bytes(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Search memory for a byte pattern, with ``??`` wildcards.

    Accepts ``hex`` (``48 8b ?? 24``), ``text`` for an ASCII literal, or
    ``utf16`` for a wide literal, which is what Windows binaries mostly hold.
    """
    entry = session.resolve(params)
    program = entry.program
    limit = clamp(params.get("limit"), 1, 2000, 50)

    hex_pattern = params.get("hex")
    text = params.get("text")
    utf16 = params.get("utf16")
    if not any((hex_pattern, text, utf16)):
        raise OpError("pass one of 'hex', 'text' or 'utf16'")

    mask: list[int] | None = None
    if hex_pattern:
        cleaned = re.sub(r"[\s,]+", "", str(hex_pattern))
        cleaned = cleaned.replace("\\x", "").replace("0x", "")
        if len(cleaned) % 2 != 0:
            raise OpError("hex pattern must have an even number of nibbles")
        pattern_bytes = bytearray()
        mask = []
        for index in range(0, len(cleaned), 2):
            pair = cleaned[index : index + 2]
            if pair in ("??", "**"):
                pattern_bytes.append(0)
                mask.append(0x00)
            else:
                try:
                    pattern_bytes.append(int(pair, 16))
                except ValueError as exc:
                    raise OpError(f"'{pair}' is not a hex byte or wildcard") from exc
                mask.append(0xFF)
        needle = bytes(pattern_bytes)
    elif text:
        needle = str(text).encode("utf-8")
    else:
        needle = str(utf16).encode("utf-16-le")

    if not needle:
        raise OpError("empty search pattern")

    memory = program.getMemory()
    monitor = session.monitor()
    java_pattern = to_jbytes(needle)
    # Ghidra's mask is a byte array: 0xFF means "this byte must match", 0x00 is a
    # wildcard. Passing None when there are no wildcards avoids the slower path.
    java_mask = to_jbytes(bytes(mask)) if mask is not None and not all(m == 0xFF for m in mask) else None

    hits: list[dict[str, Any]] = []
    start = parse_address(program, params.get("start")) if params.get("start") else program.getMinAddress()
    function_manager = program.getFunctionManager()

    while len(hits) < limit:
        session.check_cancel()
        try:
            found = memory.findBytes(start, java_pattern, java_mask, True, monitor)
        except Exception as exc:
            raise OpError(f"memory search failed: {exc}") from exc
        if found is None:
            break
        record: dict[str, Any] = {"address": str(found)}
        block = memory.getBlock(found)
        if block is not None:
            record["block"] = str(block.getName())
        holder = function_manager.getFunctionContaining(found)
        if holder is not None:
            record["function"] = str(holder.getName())
        hits.append(record)
        try:
            start = found.add(1)
        except Exception:
            break

    return {
        "program": entry.key,
        "pattern_length": len(needle),
        "wildcards": bool(java_mask is not None),
        "count": len(hits),
        "truncated": len(hits) >= limit,
        "hits": hits,
    }


_CRYPTO_SIGNATURES: dict[str, list[bytes]] = {
    "AES S-box": [bytes(range(0x63, 0x74)), b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76"],
    "AES inverse S-box": [b"\x52\x09\x6a\xd5\x30\x36\xa5\x38\xbf\x40\xa3\x9e\x81\xf3\xd7\xfb"],
    "SHA-256 K constants": [b"\x42\x8a\x2f\x98\x71\x37\x44\x91\xb5\xc0\xfb\xcf\xe9\xb5\xdb\xa5"],
    "SHA-1 H": [b"\x67\x45\x23\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x10\x32\x54\x76"],
    "MD5 K (T table head)": [b"\x78\xa4\x6a\xd7\x56\xb7\xc4\xe2\xdb\x70\x92\x0f\x17\x60\x41\x72"],
    "CRC32 poly": [b"\x20\x83\xb8\xed", b"\xed\xb8\x83\x20"],
    "CRC32 table head": [b"\x00\x00\x00\x00\x96\x30\x07\x77\x2c\x61\x0e\xee\xba\x51\x09\x99"],
    "RC4 (identity S-box head)": [],
    "Blowfish P-array head": [b"\x24\x3f\x6a\x88\x85\xa3\x08\xd3\x13\x19\xa5\xe9\x3a\x0e\x09\x31"],
    "ChaCha/Salsa sigma": [b"expand 32-byte k", b"expand 16-byte k"],
    "DES IP table head": [b"\x3a\x22\x1f\x28\x2e\x36\x27\x2f"],
    "CAST S-box head": [b"\x30\xfb\x40\xd4\x9f\xa8\xff\x5c\x2a\x68\x90\xad\xbc\xab\x4e\xa3"],
    "Twofish MDS poly": [b"\x01\x69\x8a\x37"],
    "RSA/ASN.1 OID": [b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"],
    "ASN.1 RSA-PSS OID": [b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a"],
    "PKCS1 MD5 sig OID": [b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04"],
    "DH OID": [b"\x2a\x86\x48\xce\x3e\x02\x01"],
    "base64 alphabet": [b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"],
    "hex lowercase alphabet": [b"0123456789abcdef"],
    "Gronsfeld/rot13 hint": [],
}


@op("find_crypto_constants")
def find_crypto_constants(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Locate crypto algorithm constants in the program's memory and name their functions.

    The 'what is this encrypting with' shortcut: AES S-boxes, SHA/MD5/Blowfish tables,
    ChaCha sigma, CRC32 tables, and ASN.1 OIDs cannot be omitted by a working
    implementation, so a hit is strong evidence rather than a hint.
    """
    entry = session.resolve(params)
    program = entry.program
    memory = program.getMemory()
    monitor = session.monitor()
    function_manager = program.getFunctionManager()
    limit = clamp(params.get("limit"), 1, 500, 60)

    findings: list[dict[str, Any]] = []
    for name, needles in _CRYPTO_SIGNATURES.items():
        if not needles:
            continue
        for needle in needles:
            java_needle = to_jbytes(needle)
            start = program.getMinAddress()
            hits_for_needle = 0
            while hits_for_needle < 8 and len(findings) < limit:
                session.check_cancel()
                try:
                    found = memory.findBytes(start, java_needle, None, True, monitor)
                except Exception:
                    break
                if found is None:
                    break
                record = {"algorithm": name, "address": str(found), "match_length": len(needle)}
                block = memory.getBlock(found)
                if block is not None:
                    record["block"] = str(block.getName())
                holder = function_manager.getFunctionContaining(found)
                if holder is not None:
                    record["function"] = str(holder.getName())
                    entry_point = holder.getEntryPoint()
                    record["function_entry"] = str(entry_point)
                findings.append(record)
                hits_for_needle += 1
                try:
                    start = found.add(1)
                except Exception:
                    break
                if len(findings) >= limit:
                    break

    algorithms = sorted({f["algorithm"] for f in findings})
    return {
        "program": entry.key,
        "algorithms_found": algorithms,
        "count": len(findings),
        "truncated": len(findings) >= limit,
        "hits": findings,
        "note": "a hit inside a function is a strong localization: that function likely implements or invokes the algorithm",
    }


@op("data")
def data_at(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """What Ghidra thinks lives at an address: type, value, and who references it."""
    entry = session.resolve(params)
    program = entry.program
    address = parse_address(program, params.get("address"))
    listing = program.getListing()

    data = listing.getDataContaining(address)
    code_unit = listing.getCodeUnitContaining(address)
    result: dict[str, Any] = {"program": entry.key, "address": str(address)}

    if data is not None:
        result["data"] = {
            "address": str(data.getAddress()),
            "type": str(data.getDataType().getName()),
            "length": int(data.getLength()),
            "value": str(data.getValue())[:2000] if data.getValue() is not None else None,
            "label": str(data.getLabel() or ""),
            "is_pointer": bool(data.isPointer()),
            "is_structure": bool(data.isStructure()),
        }
    if code_unit is not None:
        result["code_unit"] = str(code_unit)
    symbol = program.getSymbolTable().getPrimarySymbol(address)
    if symbol is not None:
        result["symbol"] = {"name": str(symbol.getName()), "type": str(symbol.getSymbolType())}
    function = program.getFunctionManager().getFunctionContaining(address)
    if function is not None:
        result["in_function"] = str(function.getName())
    block = program.getMemory().getBlock(address)
    if block is not None:
        result["block"] = str(block.getName())

    referrers = []
    for reference in program.getReferenceManager().getReferencesTo(address):
        holder = program.getFunctionManager().getFunctionContaining(reference.getFromAddress())
        referrers.append(
            {
                "from": str(reference.getFromAddress()),
                "type": str(reference.getReferenceType()),
                "function": str(holder.getName()) if holder is not None else None,
            }
        )
        if len(referrers) >= 20:
            break
    result["references"] = referrers
    return result


@op("data_types")
def data_types(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Search the program's data type manager, optionally expanding structure layout."""
    entry = session.resolve(params)
    manager = entry.program.getDataTypeManager()
    limit = clamp(params.get("limit"), 1, 2000, 100)
    name_filter = (params.get("filter") or "").lower()
    detail = params.get("name")

    if detail:
        matches = []
        iterator = manager.getAllDataTypes()
        for data_type in iterator:
            if str(data_type.getName()).lower() == str(detail).lower():
                matches.append(data_type)
        if not matches:
            for data_type in manager.getAllDataTypes():
                if str(detail).lower() in str(data_type.getName()).lower():
                    matches.append(data_type)
                    if len(matches) >= 10:
                        break
        if not matches:
            raise OpError(f"no data type matching '{detail}'")
        data_type = matches[0]
        record: dict[str, Any] = {
            "name": str(data_type.getName()),
            "category": str(data_type.getCategoryPath()),
            "length": int(data_type.getLength()),
            "description": str(data_type.getDescription() or ""),
            "class": type(data_type).__name__,
        }
        try:
            components = []
            for component in data_type.getComponents():
                components.append(
                    {
                        "offset": int(component.getOffset()),
                        "name": str(component.getFieldName() or ""),
                        "type": str(component.getDataType().getName()),
                        "length": int(component.getLength()),
                        "comment": str(component.getComment() or ""),
                    }
                )
            record["components"] = components
        except Exception:
            pass
        try:
            record["c_representation"] = str(data_type.getRepresentation(None, None, 0))
        except Exception:
            pass
        return {"program": entry.key, "type": record, "other_matches": [str(m.getName()) for m in matches[1:6]]}

    collected = []
    for data_type in manager.getAllDataTypes():
        name = str(data_type.getName())
        if name_filter and name_filter not in name.lower():
            continue
        collected.append(
            {
                "name": name,
                "category": str(data_type.getCategoryPath()),
                "length": int(data_type.getLength()),
                "class": type(data_type).__name__,
            }
        )
        if len(collected) >= limit:
            break
    return {"program": entry.key, "count": len(collected), "types": collected}


@op("labels")
def labels(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Defined labels in an address range, i.e. the map of what has been named."""
    entry = session.resolve(params)
    program = entry.program
    limit = clamp(params.get("limit"), 1, 5000, 200)
    table = program.getSymbolTable()

    start = parse_address(program, params["start"]) if params.get("start") else program.getMinAddress()
    end = parse_address(program, params["end"]) if params.get("end") else program.getMaxAddress()

    out = []
    iterator = table.getSymbolIterator(start, True)
    for symbol in iterator:
        address = symbol.getAddress()
        if address.compareTo(end) > 0:
            break
        out.append(
            {
                "name": str(symbol.getName()),
                "address": str(address),
                "type": str(symbol.getSymbolType()),
                "source": str(symbol.getSource()),
            }
        )
        if len(out) >= limit:
            break
    return {"program": entry.key, "start": str(start), "end": str(end), "count": len(out), "labels": out}


@op("run_script")
def run_script(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Run a Ghidra script (Java or Python) against the open program.

    The escape hatch: anything this server does not expose as an operation can be
    done here with the full Ghidra API. ``code`` is written to a temporary
    ``.py`` GhidraScript; ``path`` runs an existing script file.
    """
    entry = session.resolve(params)
    script_path = params.get("path")
    code = params.get("code")
    if not script_path and not code:
        raise OpError("pass 'path' to run a script file, or 'code' to run a snippet")

    temporary: Path | None = None
    if code:
        directory = Path(session.project_dir).parent / "scripts"
        directory.mkdir(parents=True, exist_ok=True)
        temporary = directory / f"mcp_snippet_{int(time.time() * 1000)}.py"
        temporary.write_text(str(code), encoding="utf-8")
        script_path = str(temporary)

    arguments = params.get("args") or []
    if isinstance(arguments, str):
        arguments = [arguments]

    started = time.time()
    try:
        stdout, stderr = session.pyghidra.ghidra_script(
            str(script_path),
            session.ensure_project(),
            program=entry.program,
            script_args=[str(a) for a in arguments],
            echo_stdout=False,
            echo_stderr=False,
        )
    except Exception as exc:
        raise OpError(f"script failed: {type(exc).__name__}: {exc}") from exc
    finally:
        if temporary is not None and not params.get("keep_script"):
            try:
                temporary.unlink()
            except OSError:
                pass

    session.save(entry)
    return {
        "program": entry.key,
        "script": str(script_path),
        "seconds": round(time.time() - started, 2),
        "stdout": str(stdout)[-20000:],
        "stderr": str(stderr)[-8000:],
    }


@op("export")
def export(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Export the program: ``c`` for full decompilation, ``binary`` for patched bytes.

    Exporting C for a large binary takes minutes and produces megabytes, so it writes
    to a file rather than returning the text.
    """
    entry = session.resolve(params)
    kind = str(params.get("format") or "c").lower()
    output = params.get("output")
    if not output:
        raise OpError("'output' file path is required")
    output_path = Path(str(output)).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    from java.io import File  # type: ignore

    if kind in ("c", "cpp", "decompile"):
        from ghidra.app.util.exporter import CppExporter  # type: ignore

        exporter = CppExporter()
    elif kind in ("binary", "bin", "raw"):
        from ghidra.app.util.exporter import BinaryExporter  # type: ignore

        exporter = BinaryExporter()
    elif kind in ("ascii", "listing", "txt"):
        from ghidra.app.util.exporter import AsciiExporter  # type: ignore

        exporter = AsciiExporter()
    else:
        raise OpError(f"unknown export format '{kind}'. Use c, binary or ascii.")

    started = time.time()
    ok = exporter.export(File(str(output_path)), entry.program, None, session.monitor())
    if not ok:
        log = ""
        try:
            log = str(exporter.getMessageLog())
        except Exception:
            pass
        raise OpError(f"export failed: {log or 'no detail from exporter'}")

    size = output_path.stat().st_size if output_path.exists() else 0
    return {
        "program": entry.key,
        "format": kind,
        "output": str(output_path),
        "bytes_written": size,
        "seconds": round(time.time() - started, 2),
    }
