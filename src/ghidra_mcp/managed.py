"""Managed third-party reversing tools, found or installed on demand into the CTPAX home.

Binary Ninja (headless), ILSpy/dnSpy/dotPeek, and MegaDumper live here. Java and Python
decompilers live in ``lang_recover``; Frida has its own module (``frida_mcp``). Nothing
in this module imports an external tool at import time - each function reports what is
missing and how to get it, so the MCP server boots cleanly on a machine with none of them.
"""

from __future__ import annotations

import os
import shutil
import ssl
import subprocess
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from ghidra_mcp.runtime import SETTINGS


def bin_dir() -> Path:
    path = SETTINGS.home / "bin"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _ssl_context() -> ssl.SSLContext | None:
    if os.environ.get("CTPAX_INSECURE_TLS"):
        return ssl._create_unverified_context()
    return None


def _download(urls: list[str], destination: Path, label: str, *, timeout: float = 120.0) -> dict[str, Any]:
    """Try each URL in order; returns a dict describing the outcome."""
    context = _ssl_context()
    for url in urls:
        try:
            opener = urllib.request.build_opener() if context is None else urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
            with opener.open(url, timeout=timeout) as response:
                data = response.read()
            destination.write_bytes(data)
            return {"ready": True, "path": str(destination), "bytes": len(data), "from": url}
        except Exception as exc:
            last = f"{type(exc).__name__}: {exc}"
    return {"ready": False, "label": label, "error": last}


def _latest_asset(owner_repo: str, suffix: str) -> dict[str, Any]:
    """Fetch a matching asset from a GitHub release's available files."""
    context = _ssl_context()
    url = f"https://api.github.com/repos/{owner_repo}/releases/latest"
    try:
        opener = urllib.request.build_opener() if context is None else urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        opener.addheaders = [("User-Agent", "ctpax-mcp")]
        with opener.open(url, timeout=60) as response:
            import json

            release = json.loads(response.read().decode("utf-8", "replace"))
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    assets = release.get("assets") or []
    match = next((a for a in assets if str(a.get("name", "")).endswith(suffix)), None)
    if match is None:
        return {"ok": False, "names": [a.get("name") for a in assets] or None, "tag": release.get("tag_name")}
    return {"ok": True, "name": match["name"], "url": match["browser_download_url"], "tag": release.get("tag_name")}


# --------------------------------------------------------------------------
# Binary Ninja (headless, via its Python API)
# --------------------------------------------------------------------------
_BN_VIEWS: dict[str, Any] = {}


def _find_binaryninja() -> dict[str, Any]:
    """Locate the binaryninja module without importing it eagerly if absent."""
    try:
        import binaryninja  # noqa: F401

        return {"found": True, "module": "binaryninja", "importable": True}
    except (ImportError, OSError):
        pass
    override = os.environ.get("BN_INSTALL_DIR")
    candidates = ([Path(override)] if override else []) + [
        Path(os.environ.get("USERPROFILE", "")) / ".binaryninja",
        Path("C:/Program Files/Vector35/BinaryNinja"),
        Path("C:/Program Files/Binary Ninja"),
    ]
    for root in candidates:
        python_api = None
        for name in ("python/binaryninja", "binaryninja"):
            candidate = root / name
            if candidate.is_dir():
                python_api = candidate
                break
        if python_api is not None:
            return {"found": True, "root": str(root), "python_api": str(python_api), "path_based": True}
    return {
        "found": False,
        "hint": "install Binary Ninja (it ships python/binaryninja) or set BN_INSTALL_DIR to its install folder",
    }


def binaryninja_status() -> dict[str, Any]:
    """Is the Binary Ninja headless API reachable, and from where?"""
    info = _find_binaryninja()
    if not info["found"]:
        return info
    try:
        import binaryninja

        return {
            **info,
            "found": True,
            "version": getattr(binaryninja, "core_version", None) or getattr(binaryninja, "__version__", "unknown"),
        }
    except Exception as exc:
        return {**info, "found": False, "error": f"{type(exc).__name__}: {exc}"}


def _bn_boot(path: str, *, analyze: bool = True) -> dict[str, Any]:
    info = _find_binaryninja()
    if not info["found"]:
        return {"error": "Binary Ninja is not available", "hint": info.get("hint")}
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {target}"}
    key = str(target.resolve())
    if key in _BN_VIEWS:
        return {"view": key, "reused": True}
    try:
        import binaryninja

        bv = binaryninja.open_view(str(target), update_analysis=True if analyze else False)
        if bv is None:
            return {"error": "Binary Ninja could not open the file (no available loader)"}
    except Exception as exc:
        return {"error": f"Binary Ninja failed to open: {type(exc).__name__}: {exc}"}
    _BN_VIEWS[key] = bv
    return {"view": key, "reused": False}


def binaryninja_open(path: str, *, analyze: bool = True, close_others: bool = False) -> dict[str, Any]:
    """Open a file in headless Binary Ninja; the view is kept for later calls."""
    if close_others:
        _BN_VIEWS.clear()
    result = _bn_boot(path, analyze=analyze)
    if "error" in result:
        return result
    bv = _BN_VIEWS[result["view"]]
    entry = bv.entry_functions[0].start if getattr(bv, "entry_functions", None) else bv.start
    return {
        "opened": str(path),
        "architecture": str(bv.arch.name) if getattr(bv, "arch", None) else None,
        "platform": str(bv.platform.name) if getattr(bv, "platform", None) else None,
        "base": hex(bv.start),
        "entry": hex(int(entry)) if entry is not None else None,
        "sections": len(getattr(bv, "sections", {}) or {}),
        "functions": len(list(getattr(bv, "functions", []))),
        "strings": len(list(getattr(bv, "strings", []))),
        "note": "headless analysis runs in this process; use binaryninja functions/decompile/disassemble",
    }


def binaryninja_info(path: str | None = None) -> dict[str, Any]:
    """Sections, functions preview, and strings for the open (or named) BN view."""
    key = _resolve_bn_view(path)
    if "error" in key:
        return key
    bv = _BN_VIEWS[key["view"]]
    sections = []
    for name, section in (getattr(bv, "sections", {}) or {}).items():
        sections.append({"name": name, "start": hex(int(section.start)), "size": int(section.length)})
    functions = []
    for fn in list(getattr(bv, "functions", []))[:20]:
        functions.append({"name": _bn_name(fn), "start": hex(int(fn.start)), "bytes": int(fn.total_bytes)})
    strings = [{"address": hex(int(s.start)), "value": s.value} for s in list(getattr(bv, "strings", []))[:30]]
    return {
        "file": key["view"],
        "sections": sections[:40],
        "function_count": len(list(getattr(bv, "functions", []))),
        "functions_sample": functions,
        "strings_sample": strings,
        "note": "pass an address to binaryninja_decompile for the full pseudo-source of a function",
    }


def _bn_name(fn: Any) -> str:
    try:
        if getattr(fn, "symbol", None) is not None:
            return str(fn.symbol.short_name)
    except Exception:
        pass
    try:
        return str(fn.name)
    except Exception:
        return hex(int(fn.start))


def _resolve_bn_view(path: str | None) -> dict[str, Any]:
    if not _BN_VIEWS:
        return {"error": "no Binary Ninja view is open; call binaryninja_open first"}
    if path:
        key = str(Path(path).resolve())
        if key not in _BN_VIEWS:
            return {"error": f"'{path}' is not open in Binary Ninja", "open_views": sorted(_BN_VIEWS)}
        return {"view": key}
    return {"view": sorted(_BN_VIEWS)[0]}


def binaryninja_functions(path: str | None = None, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
    """List functions in the open BN view (name/address/size), newest-analysis order."""
    key = _resolve_bn_view(path)
    if "error" in key:
        return key
    bv = _BN_VIEWS[key["view"]]
    needle = (filter or "").lower()
    out = []
    for fn in getattr(bv, "functions", []):
        name = _bn_name(fn)
        if needle and needle not in name.lower():
            continue
        out.append({"name": name, "start": hex(int(fn.start)), "bytes": int(fn.total_bytes)})
        if len(out) >= limit:
            break
    return {"file": key["view"], "function_count": len(out) if not needle else len(list(getattr(bv, "functions", []))), "functions": out}


def binaryninja_decompile(address: str, path: str | None = None, *, level: str = "hlil") -> dict[str, Any]:
    """Decompile a function to Binary Ninja pseudo-source (HLIL/MLIL/LLIL).

    The Decompiler's text view is the High-Level IL; ``level`` picks ``hlil``,
    ``mlil``, or ``llil`` when you want the progressively lower-level IR.
    """
    key = _resolve_bn_view(path)
    if "error" in key:
        return key
    bv = _BN_VIEWS[key["view"]]
    try:
        target = int(str(address), 0)
    except ValueError:
        return {"error": f"address must be a number or 0x..., got {address!r}"}
    fn = bv.get_function_at(target)
    if fn is None:
        containing = bv.get_functions_containing(target)
        if not containing:
            return {"error": f"no function at {address}"}
        fn = containing[0]
    il = {"hlil": None, "mlil": None, "llil": None}
    try:
        il["hlil"] = str(fn.high_level_il) if hasattr(fn, "high_level_il") else str(fn.render_high_level_il())
    except Exception as exc:
        il["hlil"] = f"(hlil failed: {exc})"
    try:
        il["mlil"] = str(fn.medium_level_il)
    except Exception:
        il["mlil"] = None
    try:
        il["llil"] = str(fn.low_level_il)
    except Exception:
        il["llil"] = None
    text = il.get(level) or il["hlil"]
    return {
        "function": _bn_name(fn),
        "address": hex(int(target)),
        "level": level if il.get(level) else "hlil",
        "lines": len(text.splitlines()),
        "source": text,
        "other_levels": {k: v is not None for k, v in il.items()},
    }


def binaryninja_disassemble(address: str, path: str | None = None, count: int = 40) -> dict[str, Any]:
    """Linear disassembly from an address as Binary Ninja Low-Level IL lines."""
    key = _resolve_bn_view(path)
    if "error" in key:
        return key
    bv = _BN_VIEWS[key["view"]]
    try:
        target = int(str(address), 0)
    except ValueError:
        return {"error": f"address must be a number or 0x..., got {address!r}"}
    fn = bv.get_function_at(target)
    if fn is None:
        containing = bv.get_functions_containing(target)
        if not containing:
            return {"error": f"no function at {address}"}
        fn = containing[0]
    lines = []
    try:
        block = fn.get_low_level_il_at(target)
        address = int(block.address)
        for ins in block.instructions[:count]:
            lines.append({"address": hex(int(ins.address)), "text": str(ins)})
    except Exception:
        for ins in list(fn.low_level_il.instructions)[:count]:
            lines.append({"address": hex(int(ins.address)), "text": str(ins)})
    return {"function": _bn_name(fn), "count": len(lines), "instructions": lines}


def binaryninja_strings(path: str | None = None, limit: int = 100, filter: str | None = None) -> dict[str, Any]:
    """Strings in the open BN view with addresses."""
    key = _resolve_bn_view(path)
    if "error" in key:
        return key
    bv = _BN_VIEWS[key["view"]]
    needle = (filter or "").lower()
    out = []
    for s in list(getattr(bv, "strings", [])):
        value = s.value
        if needle and needle not in str(value).lower():
            continue
        out.append({"address": hex(int(s.start)), "value": str(value)})
        if len(out) >= limit:
            break
    return {"file": key["view"], "count": len(out), "strings": out}


# --------------------------------------------------------------------------
# ILSpy (ilspycmd), dnSpy, dotPeek - .NET decompilers
# --------------------------------------------------------------------------
def _ilspycmd() -> dict[str, Any]:
    override = shutil.which("ilspycmd")
    candidates = [Path(override)] if override else []
    candidates += [Path.home() / ".dotnet" / "tools" / "ilspycmd.exe"]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return {"found": True, "path": str(candidate)}
    return {"found": False, "hint": "install with: dotnet tool install --global ilspycmd"}


def ensure_ilspycmd() -> dict[str, Any]:
    """Locate ilspycmd, or install the .NET global tool when dotnet is present."""
    existing = _ilspycmd()
    if existing.get("found"):
        return {"ready": True, "path": existing["path"], "installed": "already present"}
    dotnet = shutil.which("dotnet") or Path("C:/Program Files/dotnet/dotnet.exe")
    if not (dotnet and (str(dotnet) == "dotnet" or Path(dotnet).is_file())):
        return {
            "ready": False,
            "hint": "install the .NET SDK (https://dotnet.microsoft.com/download) or run: dotnet tool install --global ilspycmd",
        }
    try:
        result = subprocess.run(
            [str(dotnet), "tool", "install", "--global", "ilspycmd"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, stdin=subprocess.DEVNULL,
        )
    except Exception as exc:
        return {"ready": False, "error": str(exc)}
    if result.returncode != 0:
        return {"ready": False, "error": (result.stderr or result.stdout)[-400:]}
    fresh = _ilspycmd()
    return {"ready": True, "path": fresh["path"], "installed": "dotnet tool installed"}


def dotnet_decompile(path: str, *, engine: str = "ilspy", out_dir: str | None = None, project: bool = False) -> dict[str, Any]:
    """Decompile a .NET assembly to C# with ILSpy (ilspycmd).

    Without ``out_dir`` the source is returned inline (best for a single assembly);
    with ``out_dir`` a project is written there (one .cs per type when ``project``).
    """
    if engine not in ("ilspy", "dnspy", "dotpeek"):
        return {"error": f"engine must be ilspy, dnspy, or dotpeek; got {engine!r}"}
    if engine != "ilspy":
        return {"error": f"{engine} is graphical - use dnspy_open/dotpeek_open and drive its window", "engine": engine}
    ready = ensure_ilspycmd()
    if not ready.get("ready"):
        return ready
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {target}"}
    command = [ready["path"]]
    if out_dir:
        command += ["-o", out_dir]
        if project:
            command += ["-p"]
    else:
        if project:
            return {"error": "project mode needs out_dir"}
    command.append(str(target))
    started = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {"error": "ilspycmd did not finish within 600s"}
    if result.returncode != 0:
        return {"error": f"ilspycmd failed: {(result.stderr or result.stdout)[-400:]}", "elapsed": round(time.time() - started, 1)}
    if out_dir:
        output_dir = Path(out_dir)
        sources = sorted(output_dir.rglob("*.cs"))
        files = [{"file": str(s.relative_to(output_dir)), "lines": len(s.read_text(encoding="utf-8", errors="replace").splitlines())} for s in sources[:300]]
        return {"decompiled": True, "output_dir": str(output_dir), "cs_files": len(sources), "files": files, "elapsed": round(time.time() - started, 1)}
    return {
        "decompiled": True,
        "lines": len((result.stdout or "").splitlines()),
        "source": result.stdout,
        "elapsed": round(time.time() - started, 1),
    }


# --------------------------------------------------------------------------
# dnSpy / dotPeek (GUI): download dnSpy once, launch it on a file; the
# window-driving tools (window_focus/input_*) then operate the session.
# --------------------------------------------------------------------------
def _dnspy_dir() -> Path:
    return bin_dir() / "dnSpy"


def ensure_dnspy() -> dict[str, Any]:
    """Download the dnSpy release zip into <home>/bin/dnSpy if absent."""
    exe = _dnspy_dir() / "dnSpy.exe"
    if exe.is_file():
        return {"ready": True, "exe": str(exe), "installed": "already present"}
    info = _latest_asset("icsharpcode/dnSpy", "dnSpy-net-win64.zip")
    if not info.get("ok"):
        return {"ready": False, "error": f"no dnSpy release asset: {info}"}
    archive = bin_dir() / "dnSpy-net-win64.zip"
    downloaded = _download([info["url"]], archive, "dnSpy")
    if not downloaded.get("ready"):
        return downloaded
    _dnspy_dir().mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(_dnspy_dir())
        archive.unlink(missing_ok=True)
    except Exception as exc:
        return {"ready": False, "error": f"unzip failed: {exc}"}
    return {"ready": exe.is_file(), "exe": str(exe) if exe.is_file() else None, "extracted_to": str(_dnspy_dir())}


def dnspy_open(path: str | None = None, *, binary: str | None = None) -> dict[str, Any]:
    """Launch the dnSpy GUI (downloading it first) with an assembly, or empty."""
    ready = ensure_dnspy()
    if not ready.get("ready"):
        return ready
    command = [ready["exe"]]
    target = binary or path
    if target:
        if not Path(target).is_file():
            return {"error": f"no such file: {target}"}
        command.append(str(target))
    subprocess.Popen(command, cwd=str(_dnspy_dir()), stdin=subprocess.DEVNULL)
    return {
        "launched": True,
        "exe": ready["exe"],
        "target": target,
        "note": "dnSpy is opening in its own window; drive it with window_focus/input_* (it also debugs assemblies)",
    }


def _find_dotpeek() -> dict[str, Any]:
    override = shutil.which("dotpeek.exe")
    candidates = [Path(override)] if override else []
    for probe in (
        r"C:\Program Files\JetBrains\dotPeek\dotpeek.exe",
        r"C:\Program Files\JetBrains\JetBrains dotPeek 2023.1\dotpeek.exe",
    ):
        probes = [Path(probe.replace("2023.1", f"{year}.{minor}")) for year in (2021, 2022, 2023, 2024, 2025) for minor in (1, 2, 3)]
        candidates.append(Path(probe))
        candidates.extend(probes)
    for candidate in candidates:
        if candidate and (candidate.is_file()):
            return {"found": True, "exe": str(candidate)}
    return {"found": False, "hint": "install JetBrains dotPeek (free) or set its install folder"}


def dotpeek_open(path: str | None = None) -> dict[str, Any]:
    """Open an assembly in the JetBrains dotPeek GUI (if installed)."""
    info = _find_dotpeek()
    if not info["found"]:
        return info
    command = [info["exe"]]
    if path:
        if not Path(path).is_file():
            return {"error": f"no such file: {path}"}
        command.append(str(path))
    subprocess.Popen(command, stdin=subprocess.DEVNULL)
    return {"launched": True, "exe": info["exe"], "target": path, "note": "drive its window with window_* tools; dotPeek decompiles to C# in the GUI"}


# --------------------------------------------------------------------------
# MegaDumper: dump a running process's loaded image (native + .NET).
# --------------------------------------------------------------------------
_MEGADUMPER_REPOS = ["kzorin52/MegaDumper", "CodeCracker-Tools/MegaDumper"]


def _megadumper_exe() -> Path:
    return bin_dir() / "MegaDumper" / "MegaDumper.exe"


def ensure_megadumper() -> dict[str, Any]:
    exe = _megadumper_exe()
    if exe.is_file():
        return {"ready": True, "exe": str(exe), "installed": "already present"}
    for repo in _MEGADUMPER_REPOS:
        info = _latest_asset(repo, ".zip")
        if not info.get("ok"):
            continue
        archive = bin_dir() / "MegaDumper.zip"
        downloaded = _download([info["url"]], archive, "MegaDumper")
        if not downloaded.get("ready"):
            continue
        dest = bin_dir() / "MegaDumper"
        dest.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(dest)
            archive.unlink(missing_ok=True)
        except Exception as exc:
            return {"ready": False, "error": f"unzip failed: {exc}"}
        if exe.is_file():
            return {"ready": True, "exe": str(exe), "downloaded": f"{repo}@{info.get('tag')}"}
    return {"ready": False, "error": "could not fetch a MegaDumper release zip", "tried_repos": _MEGADUMPER_REPOS}


def mega_dump(pid: int, *, out_dir: str | None = None, timeout: float = 45.0) -> dict[str, Any]:
    """Dump a process's loaded image with MegaDumper.

    The dumper runs with the pid argument; for a GUI build it starts MegaDumper's
    window and the dump still lands next to the exe (or in ``out_dir``). The result
    lists fresh dump files so you can read them with the PE tools.
    """
    ready = ensure_megadumper()
    if not ready.get("ready"):
        return ready
    working = Path(out_dir) if out_dir else bin_dir() / "MegaDumper"
    working.mkdir(parents=True, exist_ok=True)
    before = {p.name for p in working.glob("*.exe")} | {p.name for p in working.glob("*.bin")}
    started = time.time()
    try:
        result = subprocess.run(
            [ready["exe"], str(pid)], cwd=str(working), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, stdin=subprocess.DEVNULL,
        )
        returncode: int | None = result.returncode
        output = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired:
        returncode = None
        output = "(timed out - dump may still be in progress; check files below)"
    time.sleep(0.5)
    produced = [
        {"name": p.name, "size": p.stat().st_size, "path": str(p)}
        for p in working.iterdir()
        if p.suffix in (".exe", ".bin", ".dll") and p.name not in before
    ]
    dump = next((p for p in produced if p["name"].lower().endswith(".exe")), None)
    return {
        "pid": pid,
        "returncode": returncode,
        "elapsed": round(time.time() - started, 1),
        "output_tail": output.strip().splitlines()[-8:] if output.strip() else [],
        "dumped_files": produced,
        "primary_dump": dump,
        "note": "if no files were produced the build is GUI-only; its window should be open - look for a dump next to the exe",
    }


# --------------------------------------------------------------------------
# aggregated status for doctor
# --------------------------------------------------------------------------
def managed_status() -> dict[str, Any]:
    """One-shot availability report for every managed third-party tool."""
    python_tools: dict[str, Any] = {}
    try:
        from ghidra_mcp import lang_recover, frida_mcp
    except Exception:
        lang_recover = None
        frida_mcp = None
    if lang_recover is not None:
        for name in ("cfr", "procyon", "jd"):
            jar = lang_recover.java_engine_status(name)
            python_tools["decompile_jvm"] = python_tools.get("decompile_jvm") or {}
            python_tools["decompile_jvm"][name] = jar.get("ready", False)
        python_tools["python_decompilers"] = lang_recover.python_decompiler_status()
    frida: dict[str, Any] = {"available": False}
    if frida_mcp is not None:
        try:
            frida = frida_mcp.status() | {"available": not frida_mcp.status().get("missing")}
        except Exception:
            pass
    return {
        "binary_ninja": binaryninja_status(),
        "ilspycmd": {"ready": _ilspycmd()["found"]},
        "dnspy": {"ready": _dnspy_dir().joinpath("dnSpy.exe").is_file()},
        "dotpeek": _find_dotpeek(),
        "megadumper": {"ready": _megadumper_exe().is_file()},
        "frida": frida,
        "python_decompilers": python_tools if not python_tools.get("python_decompilers") else python_tools,
        "note": "binary_ninja, frida, and the decompilers self-install/download on first use where possible",
    }