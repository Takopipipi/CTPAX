"""Static binary analysis that does not need Ghidra or a JVM.

Everything here answers a question in milliseconds where the Ghidra path would cost
a JVM start plus an analysis pass. Use this first on an unknown file: format, sections,
imports, entropy, packer indicators, and a raw string dump tell you whether the file is
even worth a full analysis, and what to expect when you run one.

Optional dependencies degrade gracefully: LIEF for parsing, capstone for disassembly,
yara for rules, pefile for PE detail. A missing one disables its feature and says so
rather than failing the whole call.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import struct
from collections import Counter
from pathlib import Path
from typing import Any

MAX_READ = 512 * 1024 * 1024


def _optional(name: str) -> Any:
    try:
        return __import__(name)
    except Exception:
        return None


def read_file(path: str | Path, *, offset: int = 0, length: int | None = None) -> bytes:
    file_path = Path(str(path)).expanduser()
    if not file_path.exists():
        raise FileNotFoundError(f"file not found: {file_path}")
    if not file_path.is_file():
        raise ValueError(f"not a file: {file_path}")
    size = file_path.stat().st_size
    if length is None:
        length = min(size - offset, MAX_READ)
    with open(file_path, "rb") as handle:
        handle.seek(offset)
        return handle.read(max(0, length))


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte. Above ~7.2 means compressed or encrypted."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def hashes(path: str | Path) -> dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    with open(Path(str(path)).expanduser(), "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "size": size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


# --------------------------------------------------------------------------
# format identification
# --------------------------------------------------------------------------
_MAGIC: list[tuple[bytes, str, str]] = [
    (b"MZ", "PE/DOS", "Windows executable or DLL (verify the PE header at e_lfanew)"),
    (b"\x7fELF", "ELF", "Linux/Unix executable, shared object, or core"),
    (b"\xfe\xed\xfa\xce", "Mach-O", "32-bit Mach-O, big endian"),
    (b"\xfe\xed\xfa\xcf", "Mach-O", "64-bit Mach-O, big endian"),
    (b"\xce\xfa\xed\xfe", "Mach-O", "32-bit Mach-O, little endian"),
    (b"\xcf\xfa\xed\xfe", "Mach-O", "64-bit Mach-O, little endian"),
    (b"\xca\xfe\xba\xbe", "Mach-O/Java", "Mach-O universal binary or Java class file"),
    (b"dex\n", "DEX", "Android Dalvik executable"),
    (b"PK\x03\x04", "ZIP", "ZIP container (APK, JAR, XAPK, or plain archive)"),
    (b"Rar!\x1a\x07", "RAR", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
    (b"\x1f\x8b", "GZIP", "gzip stream"),
    (b"BZh", "BZIP2", "bzip2 stream"),
    (b"\xfd7zXZ", "XZ", "xz stream"),
    (b"\x04\x22\x4d\x18", "LZ4", "LZ4 frame"),
    (b"\x28\xb5\x2f\xfd", "ZSTD", "Zstandard frame"),
    (b"\x1bLua", "LuaC", "compiled Lua bytecode"),
    (b"\x03\xf3\r\n", "PYC", "CPython bytecode (3.11-ish magic; check the header)"),
    (b"\x55\xaa", "MBR", "possible boot sector"),
    (b"!<arch>", "AR", "static library archive"),
    (b"\x00asm", "WASM", "WebAssembly module"),
    (b"\xd0\xcf\x11\xe0", "OLE2", "MS Office legacy / MSI compound file"),
    (b"%PDF", "PDF", "PDF document"),
    (b"\xed\xab\xee\xdb", "RPM", "RPM package"),
]


def identify(data: bytes) -> dict[str, Any]:
    for magic, kind, note in _MAGIC:
        if data.startswith(magic):
            result = {"format": kind, "note": note, "magic": magic.hex()}
            if kind == "PE/DOS" and len(data) > 0x40:
                e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
                if 0 < e_lfanew < len(data) - 4 and data[e_lfanew : e_lfanew + 4] == b"PE\0\0":
                    result["format"] = "PE"
                    result["note"] = "Windows PE executable"
                else:
                    result["note"] = "DOS MZ header without a valid PE header"
            return result
    printable = sum(1 for b in data[:4096] if 9 <= b <= 13 or 32 <= b <= 126)
    if data[:4096] and printable / len(data[:4096]) > 0.95:
        return {"format": "text", "note": "mostly printable; probably source, script, or data"}
    return {"format": "unknown", "note": "no known magic at offset 0"}


# --------------------------------------------------------------------------
# strings
# --------------------------------------------------------------------------
_INTERESTING = [
    (re.compile(r"^https?://", re.I), "url"),
    (re.compile(r"^[A-Za-z]:\\\\|^[A-Za-z]:/"), "windows_path"),
    (re.compile(r"^/(usr|etc|var|home|tmp|opt|proc)/"), "unix_path"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "ip_address"),
    (re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$"), "base64_candidate"),
    (re.compile(r"^[0-9a-fA-F]{32,}$"), "hex_blob"),
    (re.compile(r"\b(?:password|passwd|secret|token|api[_-]?key|licen[cs]e|serial|activation)\b", re.I), "credential_word"),
    (re.compile(r"\b(?:Software\\\\|HKEY_|HKLM|HKCU)\b"), "registry"),
    (re.compile(r"\.(?:dll|exe|sys|so|dylib)$", re.I), "module_name"),
    (re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*\bFROM\b|\bCREATE TABLE\b", re.I), "sql"),
    (re.compile(r"-----BEGIN [A-Z ]+-----"), "pem_block"),
    (re.compile(r"\b(?:cmd\.exe|powershell|/bin/sh|/bin/bash|WScript)\b", re.I), "shell"),
]


def extract_strings(
    data: bytes,
    *,
    min_length: int = 4,
    encoding: str = "both",
    pattern: str | None = None,
    regex: bool = False,
    limit: int = 500,
    classify: bool = True,
) -> dict[str, Any]:
    """Pull ASCII and/or UTF-16LE strings, classifying the interesting ones.

    ``classify`` is what makes this more useful than the ``strings`` utility: URLs,
    paths, registry keys, base64 blobs and credential words get tagged, so a large
    dump can be filtered down to what actually matters.
    """
    found: list[dict[str, Any]] = []
    total = 0

    matcher: re.Pattern[str] | None = None
    if pattern:
        matcher = re.compile(pattern if regex else re.escape(pattern), re.IGNORECASE)

    def consider(offset: int, text: str, kind: str) -> None:
        nonlocal total
        if len(text) < min_length:
            return
        if matcher is not None and not matcher.search(text):
            return
        total += 1
        if len(found) >= limit:
            return
        record: dict[str, Any] = {"offset": offset, "offset_hex": f"0x{offset:x}", "encoding": kind, "value": text}
        if classify:
            tags = [label for expression, label in _INTERESTING if expression.search(text)]
            if tags:
                record["tags"] = tags
        found.append(record)

    if encoding in ("ascii", "both"):
        for match in re.finditer(rb"[\x20-\x7e\t]{%d,}" % max(1, min_length), data):
            consider(match.start(), match.group().decode("ascii", "replace"), "ascii")

    if encoding in ("utf16", "both"):
        for match in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % max(1, min_length), data):
            consider(match.start(), match.group().decode("utf-16-le", "replace").rstrip("\x00"), "utf16le")

    if classify:
        tag_counts = Counter(tag for record in found for tag in record.get("tags", []))
    else:
        tag_counts = Counter()

    return {
        "total": total,
        "returned": len(found),
        "truncated": total > len(found),
        "tag_summary": dict(tag_counts),
        "strings": found,
    }


# --------------------------------------------------------------------------
# PE / ELF / Mach-O detail via LIEF, with a pefile fallback for PE
# --------------------------------------------------------------------------
def _lief_binary(path: Path) -> Any:
    lief = _optional("lief")
    if lief is None:
        return None
    try:
        # Keep LIEF quiet: it logs parse warnings to stderr, which is noise here.
        try:
            lief.logging.disable()
        except Exception:
            pass
        return lief.parse(str(path))
    except Exception:
        return None


def _pe_characteristics(binary: Any) -> dict[str, Any]:
    header = binary.header
    optional_header = binary.optional_header
    return {
        "machine": str(header.machine).rsplit(".", 1)[-1],
        "characteristics": [str(c).rsplit(".", 1)[-1] for c in header.characteristics_list],
        "timestamp": int(header.time_date_stamps),
        "subsystem": str(optional_header.subsystem).rsplit(".", 1)[-1],
        "dll_characteristics": [str(c).rsplit(".", 1)[-1] for c in optional_header.dll_characteristics_lists],
        "entrypoint": hex(int(binary.entrypoint)),
        "imagebase": hex(int(optional_header.imagebase)),
        "sizeof_image": int(optional_header.sizeof_image),
        "sizeof_headers": int(optional_header.sizeof_headers),
        "checksum": hex(int(optional_header.checksum)),
        "major_os_version": int(optional_header.major_operating_system_version),
        "is_pie": bool(binary.is_pie) if hasattr(binary, "is_pie") else None,
        "has_nx": bool(binary.has_nx) if hasattr(binary, "has_nx") else None,
    }


def analyze_binary(path: str | Path, *, section_entropy: bool = True) -> dict[str, Any]:
    """Parse headers, sections, imports and exports without Ghidra.

    This is the cheap first look: it names the format, lists what the binary imports
    (which is most of what it can possibly do), and flags high-entropy sections that
    indicate packing.
    """
    file_path = Path(str(path)).expanduser()
    head = read_file(file_path, length=64 * 1024)
    result: dict[str, Any] = {
        "path": str(file_path),
        **hashes(file_path),
        **identify(head),
    }

    lief = _optional("lief")
    binary = _lief_binary(file_path)
    if binary is None:
        result["parser"] = "magic-only"
        result["parser_note"] = (
            "LIEF is not installed or could not parse this file; only magic detection is available"
            if lief is None
            else "LIEF could not parse this file (corrupt, packed, or an unsupported format)"
        )
        return result

    result["parser"] = "lief"
    format_name = str(binary.format).rsplit(".", 1)[-1]
    result["lief_format"] = format_name

    sections: list[dict[str, Any]] = []
    for section in binary.sections:
        record: dict[str, Any] = {
            "name": str(section.name),
            "virtual_address": hex(int(section.virtual_address)),
            "virtual_size": int(getattr(section, "virtual_size", 0) or section.size),
            "raw_size": int(section.size),
            "offset": int(getattr(section, "offset", getattr(section, "file_offset", 0)) or 0),
        }
        try:
            characteristics = getattr(section, "characteristics_lists", None)
            if characteristics:
                record["flags"] = [str(c).rsplit(".", 1)[-1] for c in characteristics]
        except Exception:
            pass
        if section_entropy:
            try:
                content = bytes(section.content)
                if content:
                    value = entropy(content)
                    record["entropy"] = round(value, 3)
                    if value > 7.2 and record["raw_size"] > 1024:
                        record["entropy_note"] = "very high: compressed, encrypted, or packed"
            except Exception:
                pass
        sections.append(record)
    result["sections"] = sections

    if format_name == "PE":
        try:
            result["pe"] = _pe_characteristics(binary)
        except Exception:
            pass
        libraries: dict[str, list[str]] = {}
        try:
            for imported in binary.imports:
                names = []
                for function in imported.entries:
                    names.append(str(function.name) if function.name else f"ordinal_{function.ordinal}")
                libraries[str(imported.name)] = names
        except Exception:
            pass
        result["imports"] = libraries
        result["import_count"] = sum(len(v) for v in libraries.values())
        try:
            result["exports"] = [str(e.name) for e in binary.exported_functions][:400]
        except Exception:
            result["exports"] = []
        try:
            if binary.has_resources:
                result["has_resources"] = True
            result["has_signature"] = bool(binary.has_signatures)
        except Exception:
            pass
        try:
            result["tls_present"] = bool(binary.has_tls)
        except Exception:
            pass
        try:
            debug_entries = [str(d.type).rsplit(".", 1)[-1] for d in binary.debug]
            if debug_entries:
                result["debug"] = debug_entries
            for directory in binary.debug:
                pdb_path = getattr(getattr(directory, "payload", None), "filename", None)
                if pdb_path:
                    result["pdb_path"] = str(pdb_path)
                    break
        except Exception:
            pass

    elif format_name == "ELF":
        try:
            result["elf"] = {
                "type": str(binary.header.file_type).rsplit(".", 1)[-1],
                "machine": str(binary.header.machine_type).rsplit(".", 1)[-1],
                "entrypoint": hex(int(binary.entrypoint)),
                "interpreter": str(binary.interpreter) if binary.has_interpreter else None,
                "is_pie": bool(binary.is_pie),
                "has_nx": bool(binary.has_nx),
                "stripped": not any(True for _ in binary.symbols),
            }
            result["libraries"] = [str(library) for library in binary.libraries]
            result["imports"] = {"(dynamic)": [str(f.name) for f in binary.imported_functions][:500]}
            result["exports"] = [str(f.name) for f in binary.exported_functions][:400]
        except Exception:
            pass

    elif format_name == "MACHO":
        try:
            result["macho"] = {
                "cpu": str(binary.header.cpu_type).rsplit(".", 1)[-1],
                "file_type": str(binary.header.file_type).rsplit(".", 1)[-1],
                "entrypoint": hex(int(binary.entrypoint)),
                "is_pie": bool(binary.is_pie),
            }
            result["libraries"] = [str(library.name) for library in binary.libraries]
            result["imports"] = {"(dyld)": [str(f.name) for f in binary.imported_functions][:500]}
            result["exports"] = [str(f.name) for f in binary.exported_functions][:400]
        except Exception:
            pass

    return result


# --------------------------------------------------------------------------
# packing / protection indicators
# --------------------------------------------------------------------------
_PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida/WinLicense", ".winlice": "Themida/WinLicense",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".enigma1": "Enigma Protector", ".enigma2": "Enigma Protector",
    ".petite": "Petite", ".pklstb": "PKLite", "pec1": "PECompact",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".nsp0": "NsPack", ".nsp1": "NsPack",
    ".yp": "Y0da Crypter", ".taz": "PESpin",
    ".boom": "Boomerang", "dierghia": "BitShape",
    ".packed": "generic packer", ".crypt": "generic crypter",
}

_PACKER_STRINGS = [
    (b"UPX!", "UPX"),
    (b"UPX0", "UPX"),
    (b"$Info: This file is packed with the UPX", "UPX"),
    (b"VMProtect", "VMProtect"),
    (b"Themida", "Themida"),
    (b"WinLicense", "WinLicense"),
    (b"ASPack", "ASPack"),
    (b"Enigma", "Enigma Protector"),
    (b"MPRESS", "MPRESS"),
    (b".NET Reactor", ".NET Reactor"),
    (b"ConfuserEx", "ConfuserEx"),
    (b"SmartAssembly", "SmartAssembly"),
    (b"Obfuscar", "Obfuscar"),
    (b"PyInstaller", "PyInstaller"),
    (b"MEIPASS", "PyInstaller"),
    (b"py2exe", "py2exe"),
    (b"Nuitka", "Nuitka"),
    (b"_cgo_", "Go cgo"),
    (b"go:buildid", "Go"),
    (b"rustc", "Rust"),
    (b"UnityPlayer", "Unity"),
    (b"electron.asar", "Electron"),
    (b"__pyarmor", "PyArmor"),
    (b"jphp", "JPHP"),
    (b"Nim", "Nim"),
]


def detect_packing(path: str | Path) -> dict[str, Any]:
    """Look for packers, protectors, and language runtimes.

    Two independent signals: section names (a ``UPX0`` section is not subtle) and
    strings in the raw bytes. High overall entropy with few imports is itself the
    strongest generic indicator, so that is reported too.
    """
    file_path = Path(str(path)).expanduser()
    data = read_file(file_path, length=min(32 * 1024 * 1024, file_path.stat().st_size))
    findings: list[dict[str, Any]] = []

    binary = _lief_binary(file_path)
    section_records = []
    import_count = None
    if binary is not None:
        try:
            for section in binary.sections:
                name = str(section.name).strip("\x00").lower()
                content = bytes(section.content)
                value = entropy(content) if content else 0.0
                section_records.append({"name": str(section.name), "entropy": round(value, 3), "size": len(content)})
                if name in _PACKER_SECTIONS:
                    findings.append(
                        {"indicator": "section_name", "detail": str(section.name), "suggests": _PACKER_SECTIONS[name]}
                    )
                if value > 7.5 and len(content) > 4096:
                    findings.append(
                        {
                            "indicator": "high_entropy_section",
                            "detail": f"{section.name} entropy {value:.2f}",
                            "suggests": "compressed or encrypted content",
                        }
                    )
                writable_executable = False
                try:
                    flags = {str(f).rsplit(".", 1)[-1] for f in section.characteristics_lists}
                    writable_executable = {"MEM_WRITE", "MEM_EXECUTE"} <= flags
                except Exception:
                    pass
                if writable_executable:
                    findings.append(
                        {
                            "indicator": "writable_executable_section",
                            "detail": str(section.name),
                            "suggests": "self-modifying or unpacking code",
                        }
                    )
        except Exception:
            pass
        try:
            import_count = len(list(binary.imported_functions))
        except Exception:
            import_count = None

    for needle, name in _PACKER_STRINGS:
        if needle in data:
            findings.append({"indicator": "string", "detail": needle.decode("latin-1"), "suggests": name})

    overall = entropy(data)
    if overall > 7.2:
        findings.append(
            {"indicator": "file_entropy", "detail": f"{overall:.2f} bits/byte", "suggests": "packed or encrypted"}
        )
    if import_count is not None and import_count <= 12 and overall > 6.5:
        findings.append(
            {
                "indicator": "few_imports",
                "detail": f"{import_count} imported functions with entropy {overall:.2f}",
                "suggests": "imports likely resolved at runtime, typical of packers",
            }
        )

    suggestions = sorted({f["suggests"] for f in findings})
    verdict = "no packing indicators found"
    if any(f["indicator"] in ("section_name", "string") for f in findings):
        verdict = "likely packed or protected: " + ", ".join(suggestions[:4])
    elif findings:
        verdict = "possible packing: " + ", ".join(suggestions[:4])

    return {
        "path": str(file_path),
        "file_entropy": round(overall, 3),
        "import_count": import_count,
        "verdict": verdict,
        "indicator_count": len(findings),
        "indicators": findings[:60],
        "sections": section_records,
    }


def entropy_map(path: str | Path, *, blocks: int = 64) -> dict[str, Any]:
    """Entropy per block across the file, to locate an encrypted blob inside it.

    A flat high plateau is a packed section; a spike in an otherwise low-entropy file
    is usually an embedded key, certificate, or compressed payload.
    """
    file_path = Path(str(path)).expanduser()
    size = file_path.stat().st_size
    if size == 0:
        raise ValueError("file is empty")
    blocks = max(4, min(512, int(blocks)))
    block_size = max(1, size // blocks)
    rows: list[dict[str, Any]] = []
    with open(file_path, "rb") as handle:
        for index in range(blocks):
            offset = index * block_size
            handle.seek(offset)
            chunk = handle.read(block_size)
            if not chunk:
                break
            value = entropy(chunk)
            bar = "#" * int(round(value * 4))
            rows.append(
                {
                    "offset": offset,
                    "offset_hex": f"0x{offset:x}",
                    "size": len(chunk),
                    "entropy": round(value, 3),
                    "bar": bar,
                }
            )
    values = [row["entropy"] for row in rows]
    return {
        "path": str(file_path),
        "size": size,
        "block_size": block_size,
        "min_entropy": round(min(values), 3) if values else 0,
        "max_entropy": round(max(values), 3) if values else 0,
        "mean_entropy": round(sum(values) / len(values), 3) if values else 0,
        "blocks": rows,
        "chart": "\n".join(f"{row['offset_hex']:>10} {row['entropy']:5.2f} {row['bar']}" for row in rows),
    }


# --------------------------------------------------------------------------
# disassembly via capstone (no Ghidra, works on raw shellcode)
# --------------------------------------------------------------------------
_ARCH_MAP = {
    "x86": ("CS_ARCH_X86", "CS_MODE_32"),
    "x86_32": ("CS_ARCH_X86", "CS_MODE_32"),
    "x86_64": ("CS_ARCH_X86", "CS_MODE_64"),
    "x64": ("CS_ARCH_X86", "CS_MODE_64"),
    "arm": ("CS_ARCH_ARM", "CS_MODE_ARM"),
    "thumb": ("CS_ARCH_ARM", "CS_MODE_THUMB"),
    "arm64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
    "aarch64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
    "mips": ("CS_ARCH_MIPS", "CS_MODE_MIPS32"),
    "mips64": ("CS_ARCH_MIPS", "CS_MODE_MIPS64"),
    "ppc": ("CS_ARCH_PPC", "CS_MODE_32"),
    "ppc64": ("CS_ARCH_PPC", "CS_MODE_64"),
    "sparc": ("CS_ARCH_SPARC", "CS_MODE_32"),
    "riscv32": ("CS_ARCH_RISCV", "CS_MODE_RISCV32"),
    "riscv64": ("CS_ARCH_RISCV", "CS_MODE_RISCV64"),
}


def disassemble_raw(
    data: bytes,
    *,
    arch: str = "x86_64",
    base: int = 0,
    limit: int = 200,
) -> dict[str, Any]:
    """Disassemble a byte buffer with capstone.

    Ghidra needs a whole program; this takes bytes, which is what you actually have
    when looking at shellcode, a decrypted blob, or a patch you are about to write.
    """
    capstone = _optional("capstone")
    if capstone is None:
        raise RuntimeError("capstone is not installed, so raw disassembly is unavailable")
    key = str(arch).lower().replace("-", "_")
    if key not in _ARCH_MAP:
        raise ValueError(f"unknown arch '{arch}'. Known: {', '.join(sorted(_ARCH_MAP))}")
    arch_name, mode_name = _ARCH_MAP[key]
    engine = capstone.Cs(getattr(capstone, arch_name), getattr(capstone, mode_name))
    engine.detail = False

    instructions = []
    for instruction in engine.disasm(data, base):
        instructions.append(
            {
                "address": hex(instruction.address),
                "bytes": instruction.bytes.hex(),
                "mnemonic": instruction.mnemonic,
                "operands": instruction.op_str,
                "text": f"{instruction.mnemonic} {instruction.op_str}".strip(),
            }
        )
        if len(instructions) >= limit:
            break

    decoded = sum(len(bytes.fromhex(i["bytes"])) for i in instructions)
    return {
        "arch": key,
        "base": hex(base),
        "count": len(instructions),
        "bytes_decoded": decoded,
        "bytes_total": len(data),
        "complete": decoded >= len(data),
        "instructions": instructions,
        "listing": "\n".join(f"{i['address']}  {i['bytes']:<20} {i['text']}" for i in instructions),
    }


# --------------------------------------------------------------------------
# YARA
# --------------------------------------------------------------------------
def yara_scan(path: str | Path, *, rules_source: str | None = None, rules_path: str | None = None) -> dict[str, Any]:
    """Scan a file with YARA rules given inline or as a file."""
    yara = _optional("yara")
    if yara is None:
        raise RuntimeError("yara-python is not installed, so YARA scanning is unavailable")
    if not rules_source and not rules_path:
        raise ValueError("pass 'rules_source' (inline rule text) or 'rules_path'")
    try:
        rules = yara.compile(source=rules_source) if rules_source else yara.compile(filepath=str(rules_path))
    except Exception as exc:
        raise ValueError(f"rule compilation failed: {exc}") from exc

    file_path = Path(str(path)).expanduser()
    matches = rules.match(str(file_path), timeout=120)
    out = []
    for match in matches:
        strings_hit = []
        for item in match.strings:
            for instance in item.instances:
                strings_hit.append(
                    {
                        "identifier": item.identifier,
                        "offset": instance.offset,
                        "offset_hex": f"0x{instance.offset:x}",
                        "matched": instance.matched_data[:64].hex(),
                    }
                )
                if len(strings_hit) >= 40:
                    break
        out.append(
            {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "meta": dict(match.meta),
                "string_hits": strings_hit,
            }
        )
    return {"path": str(file_path), "match_count": len(out), "matches": out}


# --------------------------------------------------------------------------
# hexdump / patterns
# --------------------------------------------------------------------------
def hexdump(path: str | Path, *, offset: int = 0, length: int = 256, width: int = 16) -> dict[str, Any]:
    data = read_file(path, offset=offset, length=length)
    width = max(4, min(64, int(width)))
    lines = []
    for index in range(0, len(data), width):
        chunk = data[index : index + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset + index:08x}  {hex_part}  |{ascii_part}|")
    return {
        "path": str(path),
        "offset": offset,
        "length": len(data),
        "hex": data.hex(),
        "dump": "\n".join(lines),
    }


def find_pattern(
    path: str | Path,
    *,
    hex_pattern: str | None = None,
    text: str | None = None,
    utf16: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Find a byte pattern in a file, with ``??`` wildcards, reporting file offsets."""
    data = read_file(path)
    if hex_pattern:
        cleaned = re.sub(r"[\s,]+", "", str(hex_pattern)).replace("\\x", "").replace("0x", "")
        if len(cleaned) % 2:
            raise ValueError("hex pattern needs an even number of nibbles")
        parts = []
        for index in range(0, len(cleaned), 2):
            pair = cleaned[index : index + 2]
            parts.append(b"." if pair in ("??", "**") else re.escape(bytes([int(pair, 16)])))
        expression = re.compile(b"".join(parts), re.DOTALL)
    elif text:
        expression = re.compile(re.escape(str(text).encode("utf-8")))
    elif utf16:
        expression = re.compile(re.escape(str(utf16).encode("utf-16-le")))
    else:
        raise ValueError("pass 'hex_pattern', 'text' or 'utf16'")

    hits = []
    for match in expression.finditer(data):
        start = match.start()
        context_start = max(0, start - 8)
        hits.append(
            {
                "offset": start,
                "offset_hex": f"0x{start:x}",
                "matched": match.group()[:32].hex(),
                "context": data[context_start : start + len(match.group()) + 8].hex(),
            }
        )
        if len(hits) >= limit:
            break
    return {"path": str(path), "count": len(hits), "truncated": len(hits) >= limit, "hits": hits}

# --------------------------------------------------------------------------
# file patching (binary diffs, byte replacement, backup-protected writes)
# --------------------------------------------------------------------------
def patch_file(
    path: str | Path,
    find_hex: str,
    replace_hex: str,
    *,
    offset: int | None = None,
    occurrence: int | None = None,
    replace_all: bool = False,
    backup: bool = True,
) -> dict[str, Any]:
    """Replace bytes in a file: the classic cracked-binary workflow, made reversible.

    ``find_hex`` must match ``replace_hex`` in length (in-place rewrite). By default the
    pattern must occur exactly once; ``occurrence=1`` (1-based) patches just the first
    match, ``offset`` narrows the search to start there, and ``replace_all=True``
    patches every occurrence - pick one way to disambiguate, not several. A ``.bak``
    copy keeps the original reversible.
    """
    file_path = Path(path)
    find = bytes.fromhex(find_hex)
    replace = bytes.fromhex(replace_hex)
    if len(find) != len(replace):
        raise ValueError(f"find ({len(find)} bytes) and replace ({len(replace)} bytes) must match in length")
    if not file_path.is_file():
        raise FileNotFoundError(f"no such file: {file_path}")
    if occurrence is not None and occurrence < 1:
        raise ValueError("occurrence is 1-based: the first match is 1")

    data = file_path.read_bytes()
    occurrences = []
    start = offset or 0
    while True:
        index = data.find(find, start)
        if index < 0:
            break
        occurrences.append(index)
        start = index + 1
    if not occurrences:
        return {"patched": False, "note": "pattern not found; check find_hex or the offset"}
    if replace_all:
        chosen = occurrences
    elif occurrence is not None:
        if occurrence > len(occurrences):
            return {
                "patched": False,
                "note": f"only {len(occurrences)} occurrence(s) exist; occurrence={occurrence} is out of range",
                "occurrences": [hex(o) for o in occurrences],
            }
        chosen = [occurrences[occurrence - 1]]
    elif len(occurrences) > 1 and offset is None:
        return {
            "patched": False,
            "note": f"pattern occurs {len(occurrences)} times; pass occurrence=1 for the first, or replace_all=true, or offset to narrow",
            "occurrences": [hex(o) for o in occurrences],
        }
    else:
        chosen = occurrences[:1]

    if backup:
        backup_path = file_path.with_suffix(file_path.suffix + ".bak")
        if not backup_path.exists():
            backup_path.write_bytes(data)
    for index in chosen:
        data = data[:index] + replace + data[index + len(find):]
    file_path.write_bytes(data)
    return {
        "patched": True,
        "file": str(file_path),
        "backup": str(file_path.with_suffix(file_path.suffix + ".bak")) if backup else None,
        "patch_count": len(chosen),
        "patches": [{"offset": hex(o), "find": find_hex, "replace": replace_hex} for o in chosen],
    }


def diff_files(path_a: str | Path, path_b: str | Path, *, limit: int = 100) -> dict[str, Any]:
    """Byte-level diff of two binaries: original vs patched, packed vs unpacked.

    Reports every differing run as (offset, original bytes, other bytes) - the fastest
    way to see what a crack actually changed, or what an unpacker produced.
    """
    data_a = Path(path_a).read_bytes()
    data_b = Path(path_b).read_bytes()
    if len(data_a) != len(data_b):
        return {
            "error": "sizes differ",
            "size_a": len(data_a),
            "size_b": len(data_b),
            "note": "a repack changed the layout; diff is only meaningful for same-size files",
        }
    runs: list[dict[str, Any]] = []
    index = 0
    size = len(data_a)
    while index < size and len(runs) < limit:
        if data_a[index] != data_b[index]:
            start = index
            while index < size and data_a[index] != data_b[index]:
                index += 1
            runs.append({
                "offset": hex(start),
                "original": data_a[start:index].hex(),
                "other": data_b[start:index].hex(),
                "length": index - start,
            })
        else:
            index += 1
    return {
        "size": size,
        "same": not runs,
        "different_runs": len(runs),
        "truncated": len(runs) >= limit,
        "runs": runs,
    }
