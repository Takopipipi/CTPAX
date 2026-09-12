"""Language-level reversing: Java/JVM decompilation via CFR, .NET metadata and IL,
and native PDB symbol resolution from Microsoft's symbol server.

These are the closest thing to recovering actual source code: a Java jar decompiled
with CFR is nearly the original source; a .NET assembly yields full type/method/string
tables plus IL; a PDB-matched native binary gets every function named automatically
in Ghidra.
"""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

from ghidra_mcp.runtime import SETTINGS
from ghidra_mcp.static_analysis import read_file

_CFR_DIR = SETTINGS.home / "bin"
_CFR_JAR = _CFR_DIR / "cfr.jar"


def _java() -> str | None:
    """The java.exe to run CFR with: JAVA_HOME, PATH, or the Ghidra-adjacent JDK."""
    candidates = []
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidates.append(Path(java_home) / "bin" / "java.exe")
    candidates.append(Path("java.exe"))  # PATH resolution via subprocess
    ghidra_jdk = Path(os.environ.get("GHIDRA_INSTALL_DIR", "")) / "bin" / "java.exe"
    candidates.append(ghidra_jdk)
    for candidate in candidates:
        if candidate and (candidate.is_file() or str(candidate) == "java.exe"):
            return str(candidate)
    return None


def ensure_cfr() -> dict[str, Any]:
    """Download CFR once (it is a single jar, no installer)."""
    if _CFR_JAR.is_file():
        return {"jar": str(_CFR_JAR), "ready": True, "downloaded": "already present"}
    import urllib.request

    _CFR_DIR.mkdir(parents=True, exist_ok=True)
    urls = [
        "https://repo1.maven.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar",
        "https://repo1.maven.org/maven2/org/benf/cfr/0.150/cfr-0.150.jar",
    ]
    last_error = None
    for url in urls:
        try:
            urllib.request.urlretrieve(url, _CFR_JAR)
            return {"jar": str(_CFR_JAR), "ready": True, "downloaded": url.rsplit("/", 1)[-1]}
        except Exception as exc:
            last_error = exc
    return {"ready": False, "error": f"could not download CFR: {last_error}"}


def decompile_java(path: str, *, extra_args: str = "") -> dict[str, Any]:
    """Decompile a jar/class file to (nearly) original Java source with CFR.

    CFR reconstructs control flow, generics and lambdas. For a jar the output is
    per-class; for a single class it is one file. This is the closest to real source
    recovery this toolkit offers - most obfuscated-but-valid jars decompile outright.
    """
    jar = ensure_cfr()
    if not jar.get("ready"):
        return jar
    java = _java()
    if java is None:
        return {"error": "no java.exe found (JAVA_HOME unset and not on PATH); CFR needs it"}
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {target}"}

    out_dir = Path(tempfile.mkdtemp(prefix="cfr_out_"))
    command = [java, "-jar", jar["jar"], str(target), f"--outputdir", str(out_dir)]
    if extra_args:
        command += extra_args.split()
    started = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=600, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {"error": "CFR did not finish within 600s; try decompiling a single class instead"}
    if result.returncode != 0:
        return {"error": f"CFR failed: {(result.stderr or result.stdout)[-400:]}", "elapsed": round(time.time() - started, 1)}

    sources = sorted(out_dir.rglob("*.java"))
    total_lines = 0
    listing = []
    for source in sources[:500]:
        try:
            lines = len(source.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            lines = 0
        total_lines += lines
        listing.append({"class": str(source.relative_to(out_dir)), "lines": lines, "path": str(source)})
    return {
        "decompiled": True,
        "classes": len(sources),
        "total_lines": total_lines,
        "elapsed": round(time.time() - started, 1),
        "output_dir": str(out_dir),
        "files": listing[:100],
        "note": "read the files with file tools; they are plain .java sources",
    }


# --------------------------------------------------------------------------
# .NET: metadata tables + IL via dnfile (pure python, no runtime needed)
# --------------------------------------------------------------------------
def dotnet_inspect(path: str) -> dict[str, Any]:
    """Dump a .NET assembly's types, methods, fields, strings, and resources.

    Uses dnfile (pure-Python CIL metadata reader). The type/method tables are the
    skeleton of the original code; pair with decompile_search in Ghidra (after the
    native stub) or de4dot/ILSpy for full source.
    """
    dnfile = _optional_dnfile()
    if dnfile is None:
        return {"error": "dnfile is not installed; run install.bat again or: pip install dnfile dncil"}
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {target}"}
    try:
        pe = dnfile.dnPE(str(target))
    except Exception as exc:
        return {"error": f"not a .NET assembly ({exc})"}

    types = []
    try:
        type_table = pe.net.mdtables.TypeDef
    except Exception:
        type_table = []
    for row in type_table or []:
        methods = []
        try:
            for method in row.MethodList:
                if method.row is None:
                    continue
                methods.append({
                    "name": str(method.row.Name),
                    "impl_flags": str(method.row.ImplFlags),
                    "rva": hex(method.row.Rva) if method.row.Rva else None,
                })
        except Exception:
            pass
        namespace = str(row.TypeNamespace) if row.TypeNamespace else ""
        typename = str(row.TypeName) if row.TypeName else ""
        types.append({"namespace": namespace, "name": typename, "method_count": len(methods), "methods": methods[:50]})

    user_strings = []
    try:
        us_stream = pe.net.user_strings
        if us_stream:
            data = us_stream.__data__
            import re as _re

            for match in _re.finditer(rb"[\x20-\x7e]{6,}", data[:0x40000]):
                user_strings.append(match.group().decode("ascii", "replace"))
    except Exception:
        pass

    try:
        flags_value = int(pe.net.Flags) if pe.net else None
    except (TypeError, ValueError):
        flags_value = str(pe.net.Flags) if pe.net else None
    return {
        "file": str(target),
        "runtime_version": str(pe.net.metadata.struct.MajorVersion) + "." + str(pe.net.metadata.struct.MinorVersion) if pe.net and pe.net.metadata else None,
        "type_count": len(types),
        "types": types[:200],
        "user_strings_sample": user_strings[:80],
        "entrypoint_token": flags_value,
        "note": "full source recovery for .NET: de4dot or ILSpy on this file; user_strings often holds license messages",
    }


def dotnet_il(path: str, type_name: str | None = None) -> dict[str, Any]:
    """Disassemble a .NET method's IL (via dncil) - the 'assembly' of managed code."""
    dnfile = _optional_dnfile()
    dncil = _optional_dncil()
    if dnfile is None or dncil is None:
        return {"error": "dnfile/dncil are not installed; pip install dnfile dncil"}
    target = Path(path)
    try:
        pe = dnfile.dnPE(str(target))
    except Exception as exc:
        return {"error": f"not a .NET assembly ({exc})"}

    results = []
    try:
        method_table = pe.net.mdtables.MethodDef
    except Exception:
        method_table = []
    for row in method_table or []:
        if not row.Rva:
            continue
        if type_name and type_name.lower() not in str(row.Name).lower():
            continue
        try:
            reader = dnfile.utils.DnfileDotNetCodeReader(pe, row.Rva)
            il = dncil.dotnet_body_il(reader)
            instructions = [str(ins.opcode) + " " + str(ins.operand if ins.operand is not None else "") for ins in il.instructions]
            results.append({"method": row.Name, "instruction_count": len(instructions), "il": instructions[:120]})
        except Exception:
            continue
        if len(results) >= 20:
            break
    return {"method_count": len(results), "methods": results}


def _optional_dnfile() -> Any:
    try:
        import dnfile

        return dnfile
    except ImportError:
        return None


def _optional_dncil() -> Any:
    try:
        import dncil

        return dncil
    except ImportError:
        return None


# --------------------------------------------------------------------------
# PDB: locate the symbol path, download from the Microsoft symbol server, apply in Ghidra
# --------------------------------------------------------------------------
def _append_codeview_entry(entries: list[dict[str, Any]], guid_raw: bytes, age: int, pdb_name: str) -> None:
    """Build the symbol-server key from a raw 16-byte GUID.

    The key is the GUID's *structured* form without dashes - Data1 as a DWORD value,
    Data2/Data3 as WORD values, then Data4's raw bytes - not the little-endian memory
    hex, which is why cdb's cache folders never match a naive hex dump.
    """
    data1 = int.from_bytes(guid_raw[0:4], "little")
    data2 = int.from_bytes(guid_raw[4:6], "little")
    data3 = int.from_bytes(guid_raw[6:8], "little")
    data4 = guid_raw[8:16]
    guid_key = f"{data1:08X}{data2:04X}{data3:04X}{data4.hex().upper()}"
    # The symbol server folder is GUID + age in hex - cdb's cache layout proves it,
    # and the URL 404s without the age suffix.
    key = f"{guid_key}{age:X}"
    pdb_file = Path(pdb_name).name
    entries.append({
        "pdb": pdb_name,
        "guid_struct": guid_key,
        "guid_raw_hex": guid_raw.hex().upper(),
        "age": age,
        "symbol_server_key": key,
        "symbol_server_url": f"https://msdl.microsoft.com/download/symbols/{pdb_file}/{key}/{pdb_file}",
    })


def pdb_path_from_binary(path: str) -> dict[str, Any]:
    """Read the debug directory (RSDS) for the PDB name and GUID the binary was built with.

    That GUID+age+name triple is exactly what the symbol server needs; with it,
    symchk-style downloads recover symbols for Windows binaries and for anything built
    with debug info that was shipped.
    """
    from ghidra_mcp.pe_tools import load_pe

    try:
        pe = load_pe(path)
    except ValueError as exc:
        return {"error": str(exc)}
    try:
        debug_entries = pe.DIRECTORY_ENTRY_DEBUG
    except AttributeError:
        return {"pdb": None, "note": "no debug directory"}
    entries = []
    for entry in debug_entries:
        if entry.struct.Type != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        # The RSDS record is fixed-layout: "RSDS" + GUID(16) + age(4) + path. Raw bytes
        # beat pefile's parsed field names, which vary between CV_INFO_PDB versions.
        raw = read_file(path, offset=entry.struct.AddressOfRawData, length=entry.struct.SizeOfData)
        if raw[:4] != b"RSDS":
            continue
        guid = raw[4:20]
        age = struct.unpack("<I", raw[20:24])[0]
        pdb_name = raw[24:].split(b"\x00")[0].decode("latin-1", "replace")
        if pdb_name:
            _append_codeview_entry(entries, guid, age, pdb_name)
    return {
        "file": str(path),
        "codeview_entries": entries,
        "note": "feed the URL to pdb_download; Ghidra also picks the PDB up automatically when it sits next to the binary",
    }


def pdb_download(path: str, *, out_dir: str | None = None) -> dict[str, Any]:
    """Try to fetch the matching PDB from the Microsoft symbol server.

    Works for Windows binaries; for everything else it fails cleanly - third-party
    PDBs rarely ship unless the developer leaked them, and that leak is your luck.
    """
    info = pdb_path_from_binary(path)
    entries = info.get("codeview_entries") or []
    if not entries:
        return info
    import urllib.request

    destination_dir = Path(out_dir) if out_dir else Path(path).parent
    downloaded = []
    for entry in entries:
        url = entry["symbol_server_url"]
        target = destination_dir / Path(entry["pdb"]).name
        try:
            urllib.request.urlretrieve(url, target)
            downloaded.append({"pdb": str(target), "bytes": target.stat().st_size})
        except Exception as exc:
            downloaded.append({"pdb": entry["pdb"], "error": f"{type(exc).__name__}: not on the public server or network blocked"})
    return {"file": str(path), "results": downloaded}
