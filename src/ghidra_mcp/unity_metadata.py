"""Unity Il2Cpp metadata parsing: the names Unity stripped out of the binary are all
in ``Data/il2cpp_data/Metadata/global-metadata.dat`` next to the GameAssembly.

What one call gives you:

* the metadata version (drives every struct layout, so it is reported first);
* the full string literal table - license messages, API endpoints, key formats, the
  strings a managed build never puts in the raw binary;
* every method definition with its .NET token (0x06xxxxxx), the join key between
  metadata and the native method-pointer table Il2CppDumper resolves next.

Struct layouts differ per metadata version; instead of hardcoding one, the parser
tries stride candidates and validates them (decoded names must look like identifiers,
method tokens must sit in the 0x06000000 range), so unknown-ish versions still parse.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

_METADATA_MAGIC = 0xFAB11BAF
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.`<>\\]*$")


def _find_metadata(game_dir: Path) -> Path | None:
    for candidate in game_dir.rglob("global-metadata.dat"):
        return candidate
    return None


def _read_cstring(blob: bytes, offset: int, limit: int = 512) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset, offset + limit)
    if end == -1:
        end = min(offset + limit, len(blob))
    return blob[offset:end].decode("utf-8", "replace")


def _header_pairs(data: bytes) -> list[tuple[int, int]]:
    """The metadata header is (offset, count) pairs after sanity+version."""
    pairs = []
    for i in range(8, len(data) - 8, 8):
        offset, count = struct.unpack_from("<II", data, i)
        pairs.append((offset, count))
        if len(pairs) >= 80:
            break
    return pairs


def _looks_like_names(strings_blob: bytes, name_indices: list[int]) -> bool:
    """Most sampled name indices decode to identifier-shaped strings."""
    sample = name_indices[:: max(1, len(name_indices) // 24)][:24]
    if not sample:
        return False
    good = sum(1 for idx in sample if _IDENTIFIER_RE.match(_read_cstring(strings_blob, idx, 256)))
    return good / len(sample) >= 0.8


def _parse_methods(data: bytes, strings_blob: bytes, offset: int, count: int, stride: int) -> list[dict[str, Any]] | None:
    """Try a stride for the method definition table; None when it does not validate.

    v27 field order: nameIndex, declaringType, returnType, returnParameterToken,
    parameterStart, genericContainerIndex, token, then shorts (flags, iflags, slot,
    parameterCount) = 36 bytes. Later versions append ints before the shorts.
    """
    if offset == 0 or count == 0 or offset + count * stride > len(data):
        return None
    methods = []
    name_indices = []
    tokens_ok = 0
    for i in range(count):
        base = offset + i * stride
        name_index, _declaring, _return_type, _rpt, _pstart, _gci, token = struct.unpack_from("<iiiiiii", data, base)
        name_indices.append(name_index)
        if 0x06000000 <= token <= 0x06FFFFFF:
            tokens_ok += 1
    if tokens_ok / count < 0.8:
        return None
    if not _looks_like_names(strings_blob, name_indices):
        return None
    for i in range(min(count, 100000)):
        base = offset + i * stride
        name_index, _declaring, _return_type, _rpt, _pstart, _gci, token = struct.unpack_from("<iiiiiii", data, base)
        methods.append({"name": _read_cstring(strings_blob, name_index, 256), "token": hex(token)})
    return methods


def unity_dump(game_path: str | Path, *, out_dir: str | None = None, max_strings: int = 400) -> dict[str, Any]:
    """One-call Unity Il2Cpp inventory: version, string literals, method tokens.

    ``game_path`` is the game root (the folder containing GameAssembly.dll) or the
    global-metadata.dat file itself. The full method list goes to
    ``il2cpp_methods.txt`` and the literal table to ``il2cpp_strings.txt`` next to
    the metadata - tens of thousands of entries, too many for a chat render. The
    tokens are the join key into Ghidra once the code registration is located.
    """
    path = Path(game_path)
    metadata_path = _find_metadata(path) if path.is_dir() else (path if path.is_file() else None)
    if metadata_path is None:
        return {"error": "global-metadata.dat not found (pass the game dir or the file itself)"}
    data = metadata_path.read_bytes()
    if len(data) < 64:
        return {"error": f"metadata too small: {len(data)} bytes"}

    sanity, version = struct.unpack_from("<II", data, 0)
    if sanity != _METADATA_MAGIC:
        return {"error": f"bad metadata magic {hex(sanity)} (expected 0xFAB11BAF) - not an Il2Cpp build"}

    pairs = _header_pairs(data)
    if len(pairs) < 6:
        return {"error": "header too short for a known metadata version"}
    # v27 layout: [stringLiteral, stringLiteralData, string, events, properties, methods, ...]
    (sl_off, sl_count), (sld_off, _sld_count), (str_off, str_count), _e, _p, (m_off, m_count) = pairs[:6]

    strings_blob = data[str_off : str_off + max(0, str_count)]

    # string literals: array of {length, dataIndex} pairs into the data blob
    literals: list[str] = []
    if sl_count and sl_off + sl_count * 8 <= len(data):
        for i in range(min(sl_count, 500000)):
            length, data_index = struct.unpack_from("<Ii", data, sl_off + i * 8)
            if 0 <= data_index < len(data) and 0 <= length < 8192:
                literals.append(data[sld_off + data_index : sld_off + data_index + length].decode("utf-8", "replace"))

    methods: list[dict[str, Any]] | None = None
    used_stride = None
    for stride in (36, 40, 44, 32, 48, 28):
        methods = _parse_methods(data, strings_blob, m_off, m_count, stride)
        if methods is not None:
            used_stride = stride
            break

    result: dict[str, Any] = {
        "metadata": str(metadata_path),
        "version": version,
        "size_bytes": len(data),
        "string_literals_total": len(literals),
        "methods_total": m_count,
        "method_stride_validated": used_stride,
        "string_literals_sample": literals[:max_strings],
        "methods_sample": (methods or [])[:50],
    }

    # full tables to files - they are too big for the chat render
    destination = Path(out_dir) if out_dir else metadata_path.parent
    methods_file = destination / "il2cpp_methods.txt"
    literals_file = destination / "il2cpp_strings.txt"
    try:
        if methods is not None:
            methods_file.write_text(
                "\n".join(f"{m['token']}\t{m['name']}" for m in methods), encoding="utf-8"
            )
            result["methods_file"] = str(methods_file)
            result["methods_written"] = len(methods)
        if literals:
            literals_file.write_text("\n".join(literals), encoding="utf-8")
            result["strings_file"] = str(literals_file)
            result["strings_written"] = len(literals)
    except OSError as exc:
        result["file_write_error"] = str(exc)
    return result
