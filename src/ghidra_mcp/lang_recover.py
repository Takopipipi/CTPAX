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
import sys
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


_EFN = "med"  # engine fallback note (kept local so the note below reads naturally)

_JVM_ENGINES = {
    # name -> (jar filename, [mirror download urls])
    "cfr": ("cfr.jar", ["https://repo1.maven.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar"]),
    "procyon": (
        "procyon-decompiler.jar",
        # no live mirror: Central never hosted the decompiler artifact, JCenter is dead
        # (would-be com.github.kwart), Bitbucket downloads are gone, and jitpack builds
        # of mstrobel/procyon do not publish the submodule jar. The engine is still fully
        # wired - drop the jar at <home>/bin/jvm/procyon-decompiler.jar to enable it.
        [],
    ),
    "jd": (
        "jd-cli.jar",
        # kwart/jd-cli lives on Central as groupId com.github.kwart.jd, artifact jd-cli.
        ["https://repo1.maven.org/maven2/com/github/kwart/jd/jd-cli/1.2.1/jd-cli-1.2.1.jar"],
    ),
}


def _fetch(urls: list[str], destination: Path, label: str, timeout: float = 180.0) -> dict[str, Any]:
    """Download to ``destination`` trying each URL, returning an outcome dict."""
    import ssl as ssl_module
    import urllib.request

    context = None
    if os.environ.get("CTPAX_INSECURE_TLS"):
        context = ssl_module._create_unverified_context()
    destination.parent.mkdir(parents=True, exist_ok=True)
    last_error = None
    for url in urls:
        try:
            if context is not None:
                with urllib.request.urlopen(url, timeout=timeout, context=context) as response:
                    data = response.read()
                destination.write_bytes(data)
            else:
                urllib.request.urlretrieve(url, destination)
            return {"ready": True, "path": str(destination), "bytes": destination.stat().st_size, "from": url}
        except Exception as exc:
            last_error = exc
    return {"ready": False, "label": label, "error": str(last_error)}


def java_engine_status(engine: str) -> dict[str, Any]:
    """Is a given JVM decompiler engine's jar present (and its java available)?"""
    if engine not in _JVM_ENGINES:
        return {"error": f"unknown engine {engine!r}; known: {', '.join(_JVM_ENGINES)}"}
    name, _ = _JVM_ENGINES[engine]
    jar = _CFR_DIR / name
    return {
        "engine": engine,
        "jar": str(jar),
        "ready": jar.is_file() and _java() is not None,
        "downloaded": jar.is_file(),
        "java": _java(),
    }


def _ensure_engine(engine: str) -> dict[str, Any]:
    """Download one JVM decompiler engine's jar (idempotent); also re-fetches CFR."""
    name, urls = _JVM_ENGINES[engine]
    jar = _CFR_DIR / name
    if jar.is_file():
        java = _java()
        if java is None:
            return {"ready": False, "error": "no java.exe found (JAVA_HOME unset and not on PATH); a JVM decompiler needs it"}
        return {"ready": True, "jar": str(jar), "downloaded": "already present"}
    if not urls:
        java = _java()
        if java is None:
            return {"ready": False, "engine": engine, "error": "no java.exe found (JAVA_HOME unset and not on PATH)"}
        return {
            "ready": False,
            "engine": engine,
            "error": f"{engine} has no working auto-download mirror (upstream distributions are gone)",
            "hint": f"drop the jar yourself at {jar} and retry",
        }
    result = _fetch(urls, jar, engine)
    if not result.get("ready"):
        return result
    java = _java()
    if java is None:
        return {"ready": False, "error": "downloaded, but no java.exe found (JAVA_HOME unset and not on PATH)"}
    return {"ready": True, "jar": str(jar), "downloaded": f"{engine} {result.get('bytes')} bytes"}


def ensure_cfr() -> dict[str, Any]:
    """Download CFR once (it is a single jar, no installer)."""
    if _CFR_JAR.is_file():
        return {"jar": str(_CFR_JAR), "ready": True, "downloaded": "already present"}
    result = _ensure_engine("cfr")
    if result.get("ready"):
        result["jar"] = str(_CFR_JAR)
    return result


def decompile_java(path: str, *, engine: str = "cfr", extra_args: str = "") -> dict[str, Any]:
    """Decompile a jar/class file to (nearly) original Java source.

    Engines: ``cfr`` (default - best generics/control-flow recovery), ``procyon``
    (aggressive at reconstructing switch/closure patterns), ``jd`` (jd-cli, quickest).
    Each is a single jar downloaded on first use into <home>/bin. For a jar the output
    is per-class; for a single class it is one file. This is the closest to real source
    recovery this toolkit offers - most obfuscated-but-valid jars decompile outright.
    """
    if engine not in _JVM_ENGINES:
        return {"error": f"unknown engine {engine!r}; known: {', '.join(_JVM_ENGINES)}"}
    jar = _ensure_engine(engine)
    if not jar.get("ready"):
        return jar
    java = _java()
    if java is None:
        return {"error": "no java.exe found (JAVA_HOME unset and not on PATH); the decompiler needs it"}
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {target}"}

    out_dir = Path(tempfile.mkdtemp(prefix=f"{engine}_out_"))
    if engine == "cfr":
        command = [java, "-jar", jar["jar"], str(target), f"--outputdir", str(out_dir)]
    elif engine == "procyon":
        command = [java, "-jar", jar["jar"], str(target), "-o", str(out_dir)]
    else:  # jd
        command = [java, "-jar", jar["jar"], "-od", str(out_dir), str(target)]
    if extra_args:
        command += extra_args.split()
    started = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=600, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {"error": f"{engine} did not finish within 600s; try decompiling a single class instead"}
    if result.returncode != 0:
        return {"error": f"{engine} failed: {(result.stderr or result.stdout)[-400:]}", "elapsed": round(time.time() - started, 1)}

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
        "note": f"decompiled with {engine}; read the files with file tools - they are plain .java sources",
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


# --------------------------------------------------------------------------
# Python: bytecode info + decompilation (pycdc, uncompyle6, decompyle3)
# --------------------------------------------------------------------------
# Magic numbers for the bytecode the .pyc was compiled with; the auto-pick in
# decompile_python goes from these. Values are the standard CPython magics.
_PYC_MAGICS = {
    62211: "2.7",
    3180: "3.2",
    3231: "3.3",
    3301: "3.4",
    3320: "3.5",
    3379: "3.6",
    3390: "3.6.1",
    3394: "3.7",
    3413: "3.8",
    3425: "3.9",
    3439: "3.10",
    3495: "3.11",
    3531: "3.12",
    3560: "3.13",
}


def _pycdc_dir() -> Path:
    return SETTINGS.home / "bin" / "pycdc"


def _pycdc_exe() -> Path | None:
    for candidate in (_pycdc_dir() / "pycdc.exe", _pycdc_dir() / "samczsun" / "pycdc.exe", _pycdc_dir() / "bin" / "pycdc.exe"):
        if candidate.is_file():
            return candidate
    for found in sorted(_pycdc_dir().rglob("pycdc.exe")):
        return found
    return None


def ensure_pycdc() -> dict[str, Any]:
    """Fetch a prebuilt pycdc for Windows once into <home>/bin/pycdc."""
    if _pycdc_exe() is not None:
        return {"ready": True, "exe": str(_pycdc_exe()), "installed": "already present"}
    # zrsx/pycdc ships binaries only as GitHub Actions artifacts (auth-gated), so the
    # release-tracked builds are the reliable sources: extremecoders-re's CI and the
    # tahmidrayat mirror both publish pycdc-windows.zip on every successful build.
    candidate_suffixes = ["pycdc-windows.zip", "pycdc-windows-mingw.zip"]
    from ghidra_mcp import managed

    for repo in ("extremecoders-re/decompyle-builds", "tahmidrayat/pycdc-windows"):
        info = None
        for suffix in candidate_suffixes:
            info = managed._latest_asset(repo, suffix)
            if info.get("ok"):
                break
        if not (info or {}).get("ok"):
            continue
        archive = SETTINGS.home / "bin" / "pycdc.zip"
        result = managed._download([info["url"]], archive, "pycdc")
        if not result.get("ready"):
            continue
        _pycdc_dir().mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(_pycdc_dir())
            archive.unlink(missing_ok=True)
        except Exception as exc:
            return {"ready": False, "error": f"unzip failed: {exc}"}
        exe = _pycdc_exe()
        if exe is not None:
            return {"ready": True, "exe": str(exe), "downloaded": f"{repo}@{info.get('tag')}"}
    return {
        "ready": False,
        "error": "could not fetch a pycdc Windows build",
        "hint": "install uncompyle6/decompyle3 (pip) and rely on engine auto-pick instead",
    }


def _run_module_python_decompiler(module: str, path: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", module, path],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, stdin=subprocess.DEVNULL,
    )


def pyc_info(path: str) -> dict[str, Any]:
    """Read a .pyc's header: magic, target Python version, mtime, optional size.

    On-disk magic is a 4-byte little-endian value whose low 16 bits are the classic
    CPython magic table; the header layout after it differs by version (3.7: 12
    bytes, 3.8+: 16 bytes with mtime+size, 3.11+: pad preserved, <=3.6: 8 bytes).
    The bytecode version drives which decompiler is most likely to succeed.
    """
    from ghidra_mcp.static_analysis import read_file

    raw = read_file(path, offset=0, length=32)
    if len(raw) < 8:
        return {"error": "file is not a Python bytecode (too short)"}
    magic_u32 = int.from_bytes(raw[0:4], "little")
    magic = magic_u32 & 0xFFFF
    version = _PYC_MAGICS.get(magic) or "unknown"
    version_digits = [p for p in version.split(".") if p.isdigit()]
    major = int(version_digits[0]) if version_digits else 3
    import datetime as dt

    def _parse() -> dict[str, Any]:
        if major >= 3 and (magic >= 3413):  # 3.8+: magic(4) flags(2) pad(2) mtime(4) size(4)
            flags = int.from_bytes(raw[4:6], "little")
            mtime = int.from_bytes(raw[8:12], "little")
            size = int.from_bytes(raw[12:16], "little")
            header = 16
        elif major >= 3 and magic >= 3394:  # 3.7: magic(4) flags(2) mtime(4)
            flags = int.from_bytes(raw[4:6], "little")
            mtime = int.from_bytes(raw[6:10], "little")
            size = None
            header = 12
        else:  # <= 3.6: magic(4) mtime(4)
            flags = None
            mtime = int.from_bytes(raw[4:8], "little")
            size = None
            header = 8
        try:
            stamp = dt.datetime.fromtimestamp(mtime, dt.timezone.utc).isoformat() if mtime else None
        except (OverflowError, OSError, ValueError):
            stamp = None
        return {"flags": flags, "header_bytes": header, "mtime_utc": stamp, "source_size": size, "mtime_raw": mtime}

    parsed = _parse()
    parsed.update(
        {
            "file": str(path),
            "magic": magic,
            "magic_u32": magic_u32,
            "python_version": version,
            "pyc_size": Path(path).stat().st_size,
            "leading_hex": raw[:min(16, len(raw))].hex(" "),
            "note": "uncompyle6/decompyle3 cover 2.7-3.8 well; pycdc handles 3.9+; decompile_python auto-picks",
        }
    )
    return parsed


def python_decompiler_status() -> dict[str, Any]:
    """Which Python decompilers are usable right now (pycdc, uncompyle6, decompyle3)."""
    import importlib.util

    return {
        "pycdc": {"ready": _pycdc_exe() is not None, "exe": str(_pycdc_exe()) if _pycdc_exe() else None},
        "uncompyle6": {"ready": importlib.util.find_spec("uncompyle6") is not None},
        "decompyle3": {"ready": importlib.util.find_spec("decompyle3") is not None},
        "note": "pycdc download is automatic on first decompile; uncompyle6/decompyle3 install with pip",
    }


def _pick_python_engine(major: int, minor: int, has_pycdc: bool, has_uncompyle6: bool, has_decompyle3: bool) -> str | None:
    """Choose a decompiler by bytecode version: 3.9+ gets pycdc (uncompyle6's
    range ends around 3.8/3.9), the rest prefer uncompyle6, then decompyle3."""
    if major >= 3 and minor >= 9 and has_pycdc:
        return "pycdc"
    if has_uncompyle6:
        return "uncompyle6"
    if has_decompyle3:
        return "decompyle3"
    if has_pycdc:
        return "pycdc"
    return None


def decompile_python(path: str, *, engine: str = "auto") -> dict[str, Any]:
    """Decompile a .pyc to Python source.

    Engine selection: ``auto`` (default) picks by the bytecode's CPython magic -
    uncompyle6/decompyle3 for 2.7-3.8, pycdc for 3.9+ with fallback to uncompyle6 for
    the versions it still handles. Pass ``pycdc``, ``uncompyle6``, or ``decompyle3``
    to force one. The chosen module runs in this server's interpreter.
    """
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {target}"}
    info = pyc_info(str(target))
    version = (info.get("python_version") or "").split(".")[:2]
    minor = int(version[1]) if version and version[0].isdigit() and len(version) > 1 and version[1].isdigit() else 0
    major = int(version[0]) if version and version[0].isdigit() else 3
    py3 = major >= 3

    import importlib.util
    import sys as _sys

    has_pycdc = _pycdc_exe() is not None
    has_u6 = importlib.util.find_spec("uncompyle6") is not None
    has_d3 = importlib.util.find_spec("decompyle3") is not None

    if engine == "auto":
        if not (has_pycdc or has_u6 or has_d3):
            ensure_pycdc()
            has_pycdc = _pycdc_exe() is not None
            has_u6 = importlib.util.find_spec("uncompyle6") is not None
            has_d3 = importlib.util.find_spec("decompyle3") is not None
        chosen = _pick_python_engine(major, minor, has_pycdc, has_u6, has_d3)
        if chosen is None:
            return {"error": "no Python decompiler available; run install.bat again or: pip install uncompyle6 decompyle3"}
        engine = chosen

    started = time.time()
    if engine == "pycdc":
        ready = ensure_pycdc()
        if not ready.get("ready"):
            return ready
        try:
            result = subprocess.run([ready["exe"], str(target)], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return {"error": "pycdc did not finish within 600s"}
        source = result.stdout
        error = result.stderr
    elif engine in ("uncompyle6", "decompyle3"):
        if not importlib.util.find_spec(engine):
            return {"error": f"{engine} is not installed; pip install {engine}"}
        try:
            result = _run_module_python_decompiler(engine, str(target))
        except subprocess.TimeoutExpired:
            return {"error": f"{engine} did not finish within 600s"}
        source = result.stdout
        error = result.stderr
    else:
        return {"error": f"unknown engine {engine!r}; use auto/pycdc/uncompyle6/decompyle3"}

    if not source.strip() and error:
        return {"error": f"{engine} failed: {error.strip()[-400:]}", "python_version": info.get("python_version"), "elapsed": round(time.time() - started, 1)}
    return {
        "decompiled": True,
        "engine": engine,
        "python_version": info.get("python_version"),
        "magic": info.get("magic"),
        "lines": len(source.splitlines()),
        "source": source,
        "had_stderr": bool(error),
        "elapsed": round(time.time() - started, 1),
    }


def pycdas_disasm(path: str) -> dict[str, Any]:
    """Disassemble a .pyc's bytecode with pycdas (low-level instruction listing)."""
    ready = ensure_pycdc()
    if not ready.get("ready"):
        return ready
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {target}"}
    pycdas = _pycdc_dir().rglob("pycdas.exe")
    exe = next((p for p in pycdas), None)
    if exe is None:
        return {"error": "pycdas.exe not present in the pycdc build; only pycdc.exe was found"}
    try:
        result = subprocess.run([str(exe), str(target)], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {"error": "pycdas did not finish within 600s"}
    if result.returncode != 0:
        return {"error": (result.stderr or result.stdout)[-400:]}
    return {"disassembly": result.stdout, "lines": len(result.stdout.splitlines())}
