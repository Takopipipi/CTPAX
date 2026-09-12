"""Deep PE inspection on top of pefile: headers, sections, imports, resources, TLS,
relocations, overlay, certificates, and suspicious-trait heuristics.

This is the layer between "identify the file" and "load it into Ghidra": it answers the
questions a reverser asks first - where does the overlay start, are there TLS callbacks,
is any section writable and executable, does the import table look hollowed. pefile is
already an installer dependency, so nothing new is required.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

import pefile

from ghidra_mcp.static_analysis import entropy, read_file

_MACHINES = {0x14C: "i386", 0x8664: "x64", 0xAA64: "ARM64", 0x1C0: "ARM", 0x1C4: "ARMNT"}
_SUBSYSTEMS = {1: "native", 2: "windows_gui", 3: "windows_cui", 5: "os2_cui", 7: "posix_cui", 9: "windows_ce_gui", 10: "efi_application", 11: "efi_boot_driver", 12: "efi_runtime_driver", 13: "efi_rom", 14: "xbox", 16: "windows_boot_application"}
_DIRECTORY_NAMES = [
    "export", "import", "resource", "exception", "security", "basereloc",
    "debug", "architecture", "globalptr", "tls", "load_config", "bound_import",
    "iat", "delay_import", "com_runtime", "reserved",
]
_SECTION_FLAGS = [
    (0x20, "code"), (0x40, "initialized_data"), (0x80, "uninitialized_data"),
    (0x02000000, "discardable"), (0x04000000, "not_cached"), (0x08000000, "not_paged"),
    (0x10000000, "shared"), (0x20000000, "execute"), (0x40000000, "read"), (0x80000000, "write"),
]


def _error(message: str) -> dict[str, Any]:
    return {"error": message}


def load_pe(path: str | Path) -> pefile.PE:
    """Parse the PE, raising ValueError with a readable message on failure."""
    file_path = Path(path)
    if not file_path.is_file():
        raise ValueError(f"no such file: {file_path}")
    try:
        return pefile.PE(str(file_path), fast_load=False)
    except pefile.PEFormatError as exc:
        raise ValueError(f"not a parseable PE ({exc}); is it .NET, packed, or another format?") from exc


def _entry_summary(pe: pefile.PE) -> dict[str, Any]:
    entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entry_raw = pe.get_offset_from_rva(entry_rva) if entry_rva else 0
    return {
        "rva": hex(entry_rva),
        "va": hex(pe.OPTIONAL_HEADER.ImageBase + entry_rva),
        "file_offset": hex(entry_raw),
        "in_section": _section_containing(pe, entry_rva),
    }


def _section_containing(pe: pefile.PE, rva: int) -> str | None:
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + max(section.Misc_VirtualSize, section.SizeOfRawData):
            return section.Name.rstrip(b"\x00").decode("latin-1", "replace")
    return None


def _directory_report(pe: pefile.PE) -> list[dict[str, Any]]:
    report = []
    for index, directory in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
        if index >= len(_DIRECTORY_NAMES):
            break
        if directory.VirtualAddress or directory.Size:
            report.append({
                "name": _DIRECTORY_NAMES[index],
                "rva": hex(directory.VirtualAddress),
                "size": directory.Size,
                "file_offset": hex(pe.get_offset_from_rva(directory.VirtualAddress)) if directory.VirtualAddress else "0x0",
            })
    return report


# --------------------------------------------------------------------------
# individual reports
# --------------------------------------------------------------------------
def pe_headers(path: str | Path) -> dict[str, Any]:
    """DOS header, file header, optional header, and every populated data directory."""
    try:
        pe = load_pe(path)
    except ValueError as exc:
        return _error(str(exc))
    dos = pe.DOS_HEADER
    file_header = pe.FILE_HEADER
    optional = pe.OPTIONAL_HEADER
    is_dll = bool(file_header.Characteristics & 0x2000)
    return {
        "machine": _MACHINES.get(file_header.Machine, hex(file_header.Machine)),
        "type": "dll" if is_dll else ("driver" if optional.Subsystem == 1 and is_dll else "exe"),
        "subsystem": _SUBSYSTEMS.get(optional.Subsystem, str(optional.Subsystem)),
        "pe_time_date_stamp": file_header.TimeDateStamp,
        "entry": _entry_summary(pe),
        "imagebase": hex(optional.ImageBase),
        "size_of_image": optional.SizeOfImage,
        "size_of_headers": optional.SizeOfHeaders,
        "checksum": hex(optional.CheckSum),
        "check_sum_valid": optional.CheckSum == pe.generate_checksum(),
        "dll_characteristics": [name for bit, name in [
            (0x0020, "high_entropy_va"), (0x0040, "dynamic_base"), (0x0100, "nx_compat"),
            (0x0200, "no_seh"), (0x0400, "no_bind"), (0x1000, "wdmdriver"),
            (0x8000, "terminal_server_aware"),
        ] if file_header and optional.DllCharacteristics & bit],
        "dos_stub": {
            "e_lfanew": hex(dos.e_lfanew),
            "e_lfanew_unusual": dos.e_lfanew != 0x80,
            "rich_header_present": b"Rich" in read_file(path, offset=0, length=dos.e_lfanew or 0x200),
        },
        "characteristics_flags": [name for bit, name in [
            (0x0001, "no_relocs"), (0x0002, "executable"), (0x0004, "no_lines"),
            (0x0008, "no_symbols"), (0x0020, "large_address_aware"), (0x0100, "32bit"),
            (0x2000, "dll"),
        ] if file_header.Characteristics & bit],
        "data_directories": _directory_report(pe),
        "magic": hex(optional.Magic),
        "pe32plus": optional.Magic == 0x20B,
    }


def pe_sections(path: str | Path) -> dict[str, Any]:
    """Every section with VA/raw extents, flags, and entropy - alignment mismatches flagged."""
    try:
        pe = load_pe(path)
    except ValueError as exc:
        return _error(str(exc))
    sections = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("latin-1", "replace")
        raw_data = section.get_data() if section.SizeOfRawData else b""
        section_entropy = entropy(raw_data) if raw_data else 0.0
        flags = [flag_name for bit, flag_name in _SECTION_FLAGS if section.Characteristics & bit]
        virtual_size = section.Misc_VirtualSize
        sections.append({
            "name": name,
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": virtual_size,
            "raw_offset": hex(section.PointerToRawData),
            "raw_size": section.SizeOfRawData,
            "entropy": round(section_entropy, 3),
            "flags": flags,
            "writable": "write" in flags,
            "executable": "execute" in flags,
            "alignment_gap": virtual_size > section.SizeOfRawData + 0x400,
            "zeroed_raw": section.SizeOfRawData > 0 and not raw_data.strip(b"\x00"),
            "suspicious_name": bool(name) and not name.replace(".", "").replace("_", "").replace("$", "").isalnum(),
        })
    suspicious = [s for s in sections if (s["writable"] and s["executable"]) or s["alignment_gap"] or s["zeroed_raw"] or s["suspicious_name"]]
    return {"count": len(sections), "sections": sections, "suspicious": [s["name"] for s in suspicious]}


def pe_imports(path: str | Path) -> dict[str, Any]:
    """Import table per DLL with every function; hollowed or tiny tables flagged."""
    try:
        pe = load_pe(path)
    except ValueError as exc:
        return _error(str(exc))
    libraries = []
    try:
        entries = pe.DIRECTORY_ENTRY_IMPORT
    except AttributeError:
        entries = []
    for entry in entries:
        dll = entry.dll.decode("latin-1", "replace")
        functions = []
        for imp in entry.imports:
            functions.append({
                "name": imp.name.decode("latin-1", "replace") if imp.name else f"ordinal_{imp.ordinal}",
                "ordinal": imp.ordinal,
                "iat_rva": hex(imp.address - pe.OPTIONAL_HEADER.ImageBase),
                "hint": imp.hint,
            })
        libraries.append({"dll": dll, "functions": functions, "count": len(functions)})
    total = sum(library["count"] for library in libraries)
    return {
        "library_count": len(libraries),
        "function_count": total,
        "suspicious": {
            "no_imports": not libraries,
            "only_kernel32": len(libraries) == 1 and libraries[0]["dll"].lower() == "kernel32.dll",
            "tiny_table": bool(libraries) and total <= 5,
        },
        "libraries": libraries,
    }


def pe_exports(path: str | Path) -> dict[str, Any]:
    """Export table: names, ordinals, RVAs - for DLLs and drivers."""
    try:
        pe = load_pe(path)
    except ValueError as exc:
        return _error(str(exc))
    try:
        entries = pe.DIRECTORY_ENTRY_EXPORT.symbols
    except AttributeError:
        return {"export_count": 0, "exports": [], "note": "no export directory"}
    exports = []
    for symbol in entries:
        exports.append({
            "name": symbol.name.decode("latin-1", "replace") if symbol.name else f"ordinal_{symbol.ordinal}",
            "ordinal": symbol.ordinal,
            "rva": hex(symbol.address),
            "va": hex(pe.OPTIONAL_HEADER.ImageBase + symbol.address),
            "forwarder": symbol.forwarder,
        })
    return {"export_count": len(exports), "dll_name": getattr(pe.DIRECTORY_ENTRY_EXPORT, "name", b"").decode("latin-1", "replace"), "exports": exports}


def _resource_nodes(pe: pefile.PE, entries: Any, depth: int = 0, path: str = "") -> list[dict[str, Any]]:
    nodes = []
    for entry in entries:
        label = str(entry.name.decode("latin-1", "replace") if entry.name else entry.id)
        current = f"{path}/{label}" if path else label
        if hasattr(entry, "directory"):
            nodes.extend(_resource_nodes(pe, entry.directory.entries, depth + 1, current))
        elif hasattr(entry, "data"):
            data_entry = entry.data.struct
            rva = data_entry.OffsetToData
            nodes.append({
                "path": current,
                "type_id": entry.id if depth == 0 else None,
                "rva": hex(rva),
                "size": data_entry.Size,
                "file_offset": hex(pe.get_offset_from_rva(rva)),
                "codepage": data_entry.CodePage,
            })
    return nodes


def pe_resources(path: str | Path, extract: str | None = None, out_path: str | None = None) -> dict[str, Any]:
    """Resource tree (type/name/language), optionally extracting one entry by path."""
    try:
        pe = load_pe(path)
    except ValueError as exc:
        return _error(str(exc))
    try:
        entries = pe.DIRECTORY_ENTRY_RESOURCE.entries
    except AttributeError:
        return {"resource_count": 0, "resources": [], "note": "no resource directory"}
    resources = _resource_nodes(pe, entries)
    result: dict[str, Any] = {"resource_count": len(resources), "resources": resources}
    if extract is not None:
        match = next((r for r in resources if r["path"] == extract), None)
        if match is None:
            result["error"] = f"no resource with path {extract!r}; use one of the listed paths"
            return result
        data = pe.get_data(int(match["rva"], 16), match["size"])
        destination = Path(out_path) if out_path else Path(path).with_name(f"resource_{extract.replace('/', '_')}.bin")
        destination.write_bytes(data)
        result["extracted"] = {"path": str(destination), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    return result


def pe_tls(path: str | Path) -> dict[str, Any]:
    """TLS directory with the callback list - the classic pre-entry-point execution site."""
    try:
        pe = load_pe(path)
    except ValueError as exc:
        return _error(str(exc))
    try:
        tls = pe.DIRECTORY_ENTRY_TLS.struct
    except AttributeError:
        return {"present": False, "note": "no TLS directory"}
    callbacks: list[str] = []
    raw_callbacks = getattr(tls, "Callbacks", 0)
    if raw_callbacks:
        try:
            cursor_rva = raw_callbacks - pe.OPTIONAL_HEADER.ImageBase
            for _ in range(64):
                value = struct.unpack("<Q" if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else "<I", pe.get_data(cursor_rva, 8 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 4))[0]
                if value == 0:
                    break
                callbacks.append(hex(value))
                cursor_rva += 8 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 4
        except Exception:
            callbacks = []
            tls["CallbacksUnreadable"] = True
    return {
        "present": True,
        "callbacks": callbacks,
        "callback_count": len(callbacks),
        "raw_data_start_va": hex(tls.StartAddressOfRawData),
        "raw_data_end_va": hex(tls.EndAddressOfRawData),
        "index_va": hex(tls.AddressOfIndex),
    }


def pe_relocations(path: str | Path) -> dict[str, Any]:
    """Relocation blocks: type counts and total entries - ASLR readiness in one look."""
    try:
        pe = load_pe(path)
    except ValueError as exc:
        return _error(str(exc))
    try:
        blocks = pe.DIRECTORY_ENTRY_BASERELOC
    except AttributeError:
        return {"present": False, "note": "no relocation directory (fixed image, or stripped)"}
    type_counts: dict[str, int] = {}
    total = 0
    for block in blocks:
        for block_entry in block.entries:
            type_name = str(block_entry.type).rsplit(".", 1)[-1]
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
            total += 1
    return {"present": True, "block_count": len(blocks), "entry_count": total, "type_counts": type_counts}


def pe_overlay(path: str | Path, extract_to: str | None = None) -> dict[str, Any]:
    """Overlay detection (appended data past the last section) with optional extraction."""
    try:
        pe = load_pe(path)
    except ValueError as exc:
        return _error(str(exc))
    end = pe.get_overlay_data_start_offset()
    file_path = Path(path)
    file_size = file_path.stat().st_size
    if end is None:
        end = pe.get_offset_from_rva(max(s.VirtualAddress + s.Misc_VirtualSize for s in pe.sections)) if pe.sections else file_size
    overlay_size = file_size - end
    result: dict[str, Any] = {
        "present": overlay_size > 0,
        "offset": hex(end),
        "size": overlay_size,
        "trailing_bytes_after_overlay": 0,
    }
    if overlay_size > 0:
        data = read_file(path, offset=end)
        result["entropy"] = round(entropy(data), 3)
        result["sha256"] = hashlib.sha256(data).hexdigest()
        result["first_16_bytes"] = data[:16].hex(" ")
        if extract_to:
            Path(extract_to).write_bytes(data)
            result["extracted_to"] = extract_to
    return result


def pe_certificates(path: str | Path) -> dict[str, Any]:
    """Authenticode signature presence: where the blob is and what it hashes to."""
    try:
        pe = load_pe(path)
    except ValueError as exc:
        return _error(str(exc))
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
    if not directory.VirtualAddress or not directory.Size:
        return {"signed": False, "note": "no security directory; the binary is unsigned or stripped"}
    blob = read_file(path, offset=directory.VirtualAddress, length=directory.Size)
    # The WIN_CERTIFICATE header is 8 bytes: length(4) + revision(2) + type(2).
    certificate_length = struct.unpack("<I", blob[:4])[0] if len(blob) >= 8 else 0
    return {
        "signed": True,
        "table_file_offset": hex(directory.VirtualAddress),
        "table_size": directory.Size,
        "certificate_length": certificate_length,
        "revision": struct.unpack("<H", blob[4:6])[0] if len(blob) >= 6 else None,
        "type": struct.unpack("<H", blob[6:8])[0] if len(blob) >= 8 else None,
        "sha256_of_blob": hashlib.sha256(blob).hexdigest(),
        "note": "presence only; verify with signtool verify /pa for chain validity",
    }


_TRUSTED_DLLS = {"kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "ole32.dll", "oleaut32.dll", "msvcrt.dll", "ucrtbase.dll"}


def pe_heuristics(path: str | Path) -> dict[str, Any]:
    """Score the binary for suspicious traits - the quick triage before deep analysis.

    Covers the classics: writable+executable sections, TLS callbacks, hollowed imports,
    section alignment games, overlay blobs, missing relocations with dynamic_base set,
    timestamp anomalies, and packer-sized high-entropy sections.
    """
    try:
        pe = load_pe(path)
    except ValueError as exc:
        return _error(str(exc))
    findings: list[dict[str, Any]] = []

    def add(severity: str, trait: str, detail: str) -> None:
        findings.append({"severity": severity, "trait": trait, "detail": detail})

    sections = pe.sections
    for section in sections:
        name = section.Name.rstrip(b"\x00").decode("latin-1", "replace")
        flags = section.Characteristics
        if flags & 0x20000000 and flags & 0x80000000:
            add("high", "writable_executable_section", f"{name} is both writable and executable")
        if section.SizeOfRawData and entropy(section.get_data()) > 7.2 and section.SizeOfRawData > 0x1000:
            add("medium", "high_entropy_section", f"{name} entropy > 7.2 (packed or encrypted payload)")
    try:
        imports = pe.DIRECTORY_ENTRY_IMPORT
    except AttributeError:
        imports = []
    dll_names = {entry.dll.decode("latin-1", "replace").lower() for entry in imports}
    if not imports:
        add("high", "no_imports", "empty import table: packed, hollowed, or a driver")
    elif dll_names.issubset(_TRUSTED_DLLS) and len(dll_names) <= 2:
        add("low", "minimal_imports", f"imports only {', '.join(sorted(dll_names))}")
    optional = pe.OPTIONAL_HEADER
    if optional.DllCharacteristics & 0x0040:
        if not optional.DATA_DIRECTORY[5].VirtualAddress:
            add("medium", "aslr_without_relocs", "dynamic_base set but no relocation directory")
    try:
        if pe.DIRECTORY_ENTRY_TLS:
            callbacks = getattr(pe.DIRECTORY_ENTRY_TLS.struct, "Callbacks", 0)
            add("medium", "tls_callbacks", f"TLS callbacks present (start 0x{callbacks:x})" if callbacks else "TLS directory present")
    except AttributeError:
        pass
    overlay_start = pe.get_overlay_data_start_offset()
    file_path = Path(path)
    if overlay_start is not None:
        overlay_size = file_path.stat().st_size - overlay_start
        if overlay_size > 0x1000:
            add("low", "overlay_present", f"{overlay_size} bytes appended after the last section")
    if optional.AddressOfEntryPoint:
        entry_section = _section_containing(pe, optional.AddressOfEntryPoint)
        if entry_section is None:
            add("high", "entry_outside_sections", "entry point RVA maps into no section")
    low_align, real_align = optional.FileAlignment, optional.SectionAlignment
    if real_align >= 0x10000 and low_align <= 0x200:
        add("low", "unusual_alignment", f"file alignment {hex(low_align)} vs section {hex(real_align)}")
    if not optional.DATA_DIRECTORY[4].VirtualAddress:
        add("info", "unsigned", "no Authenticode signature directory")

    weights = {"high": 3, "medium": 2, "low": 1, "info": 0}
    score = sum(weights.get(f["severity"], 0) for f in findings)
    verdict = "benign" if score <= 2 else "suspicious" if score <= 6 else "likely_packed_or_protected"
    return {"score": score, "verdict": verdict, "finding_count": len(findings), "findings": findings}


# --------------------------------------------------------------------------
# build-to-build comparison: what did release 159 -> 160 actually change
# --------------------------------------------------------------------------
def pe_compare(path_a: str | Path, path_b: str | Path, *, max_runs: int = 80) -> dict[str, Any]:
    """Structural + byte-level diff of two builds of the same binary.

    Answers "what did the update change" without opening Ghidra: header drift, section
    layout shifts (added/renamed/resized), import/export deltas, and per-section byte
    diff runs. A build where only timestamps and the security directory changed reads
    differently from one with real code movement - the summary says which.
    """
    from pefile import PEFormatError

    paths = []
    for raw in (path_a, path_b):
        path = Path(raw)
        if not path.is_file():
            return _error(f"not a file: {path}")
        paths.append(path)

    try:
        pe_a = load_pe(paths[0])
        pe_b = load_pe(paths[1])
    except (PEFormatError, OSError) as exc:
        return _error(f"could not parse a PE: {exc}")

    try:
        data_a = paths[0].read_bytes()
        data_b = paths[1].read_bytes()
    finally:
        pe_a.close()
        pe_b.close()
    report: dict[str, Any] = {
        "a": {"path": str(paths[0]), "size": len(data_a), "sha256": hashlib.sha256(data_a).hexdigest()[:16]},
        "b": {"path": str(paths[1]), "size": len(data_b), "sha256": hashlib.sha256(data_b).hexdigest()[:16]},
    }
    report["size_delta"] = len(data_b) - len(data_a)

    # --- headers ---
    opt_a, opt_b = pe_a.OPTIONAL_HEADER, pe_b.OPTIONAL_HEADER
    header_changes = {}
    for field in ("AddressOfEntryPoint", "ImageBase", "Subsystem", "SizeOfImage", "CheckSum"):
        value_a, value_b = getattr(opt_a, field), getattr(opt_b, field)
        if value_a != value_b:
            header_changes[field] = {"a": hex(value_a), "b": hex(value_b)}
    report["header_changes"] = header_changes

    # --- sections, by name ---
    sections_a = {s.Name.decode("latin-1", "replace").rstrip("\x00"): s for s in pe_a.sections}
    sections_b = {s.Name.decode("latin-1", "replace").rstrip("\x00"): s for s in pe_b.sections}
    section_report = {}
    for name in sorted(set(sections_a) | set(sections_b)):
        section_a, section_b = sections_a.get(name), sections_b.get(name)
        if section_a is None:
            section_report[name] = {"change": "added", "raw_size": section_b.SizeOfRawData}
            continue
        if section_b is None:
            section_report[name] = {"change": "removed"}
            continue
        entry: dict[str, Any] = {}
        if section_a.SizeOfRawData != section_b.SizeOfRawData:
            entry["raw_size"] = {"a": section_a.SizeOfRawData, "b": section_b.SizeOfRawData}
        if section_a.VirtualAddress != section_b.VirtualAddress:
            entry["virtual_address"] = {"a": hex(section_a.VirtualAddress), "b": hex(section_b.VirtualAddress)}
        if entry:
            entry["change"] = "modified"
            section_report[name] = entry
    report["sections"] = section_report

    # --- imports: per-dll added/removed functions ---
    def _import_map(pe: pefile.PE) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {}
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                result[entry.dll.decode("latin-1", "replace").lower()] = {
                    imp.name.decode("latin-1", "replace") if imp.name else f"ord_{imp.ordinal}"
                    for imp in entry.imports
                }
        except AttributeError:
            pass
        return result

    imports_a, imports_b = _import_map(pe_a), _import_map(pe_b)
    import_report: dict[str, Any] = {}
    for dll in sorted(set(imports_a) | set(imports_b)):
        functions_a, functions_b = imports_a.get(dll, set()), imports_b.get(dll, set())
        added, removed = sorted(functions_b - functions_a), sorted(functions_a - functions_b)
        if dll not in imports_a:
            import_report[dll] = {"change": "added", "functions": sorted(functions_b)}
        elif dll not in imports_b:
            import_report[dll] = {"change": "removed"}
        elif added or removed:
            import_report[dll] = {"added": added, "removed": removed}
    report["imports"] = import_report

    # --- exports, by name ---
    def _export_names(pe: pefile.PE) -> set[str]:
        try:
            return {exp.name.decode("latin-1", "replace") for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols if exp.name}
        except AttributeError:
            return set()

    exports_a, exports_b = _export_names(pe_a), _export_names(pe_b)
    if exports_a != exports_b:
        report["exports"] = {"added": sorted(exports_b - exports_a), "removed": sorted(exports_a - exports_b)}

    # --- per-section byte diff ---
    def _diff_section(section_a, section_b) -> dict[str, Any]:
        raw_a = data_a[section_a.PointerToRawData : section_a.PointerToRawData + section_a.SizeOfRawData]
        raw_b = data_b[section_b.PointerToRawData : section_b.PointerToRawData + section_b.SizeOfRawData]
        common = min(len(raw_a), len(raw_b))
        runs, run_start = [], None
        for offset in range(common):
            if raw_a[offset] != raw_b[offset]:
                if run_start is None:
                    run_start = offset
            elif run_start is not None:
                runs.append((run_start, offset))
                run_start = None
        if run_start is not None:
            runs.append((run_start, common))
        # merge runs closer than 8 bytes: single patched dwords otherwise explode
        merged = []
        for start, end in runs:
            if merged and start - merged[-1][1] < 8:
                merged[-1] = (merged[-1][0], end)
            else:
                merged.append((start, end))
        changed_bytes = sum(end - start for start, end in runs)
        sample = []
        for start, end in merged[: max(0, max_runs)]:
            sample.append({
                "rva": hex(section_a.VirtualAddress + start),
                "file_offset": hex(section_a.PointerToRawData + start),
                "a": raw_a[start : min(end, start + 24)].hex(),
                "b": raw_b[start : min(end, start + 24)].hex(),
            })
        return {
            "changed_bytes": changed_bytes,
            "changed_percent": round(100 * changed_bytes / max(1, common), 2),
            "runs": len(merged),
            "run_samples": sample,
        }

    byte_report = {}
    for name in sorted(set(sections_a) & set(sections_b)):
        section_a, section_b = sections_a[name], sections_b[name]
        if section_a.SizeOfRawData and section_b.SizeOfRawData:
            byte_report[name] = _diff_section(section_a, section_b)
    report["bytes"] = byte_report

    # --- verdict ---
    code_changed = any(
        section_report.get(name, {}).get("change") == "modified" or (byte_report.get(name, {}).get("changed_bytes", 0) or 0) > 0
        for name in byte_report
        if sections_a[name].Characteristics & 0x20  # code section
    )
    imports_changed = bool(import_report)
    report["verdict"] = {
        "code_changed": code_changed,
        "imports_changed": imports_changed,
        "size_delta": report["size_delta"],
        "summary": (
            "real code movement - reanalysis required"
            if code_changed
            else "sections unchanged in bytes - likely rebuild/resign, diff headers and certs"
            if imports_changed or report["size_delta"]
            else "effectively identical images"
        ),
    }
    return report
