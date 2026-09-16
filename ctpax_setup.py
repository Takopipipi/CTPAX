"""CTPAX one-shot installer: banner -> disk choice -> full install -> client registration.

Double-click CTPAX.bat (or run this file with any Python 3.10+): it scans the fixed
drives for the most free space, lays the whole toolkit into <drive>:\\CTPAX, runs the
engine installer (venv, dependencies, Ghidra/JDK detection, x64dbg plugins, ScyllaHide,
Nuclei + templates, Wireshark) with a live console progress bar, and finally registers
the MCP server into every AI client it finds: OpenCode, Cursor, Claude Code, Codex.

A re-run is safe: everything is idempotent, and re-installing into the existing CTPAX
folder just updates it in place.
"""

from __future__ import annotations

import argparse
import ctypes
import importlib.util
import os
import shutil
import sys
import threading
import time
import traceback
from pathlib import Path

IS_WINDOWS = os.name == "nt"

SMALL_BANNER = "revers mcp server by teto"

# Big block letters spelling CTPAX in unambiguous shapes (reads as the word, not as
# squashed "СТОАК" - each glyph is a 6-row dot-matrix letter).
_GLYPH_ROWS = {
    "C": [" ██████ ", "██      ", "██      ", "██      ", "██      ", " ██████ "],
    "T": ["████████", "   ██   ", "   ██   ", "   ██   ", "   ██   ", "   ██   "],
    "P": ["██████  ", "██   ██ ", "██████  ", "██      ", "██      ", "██      "],
    "A": ["  ████  ", " ██  ██ ", "████████", "██    ██", "██    ██", "██    ██"],
    "X": ["██    ██", " ██  ██ ", "  ████  ", "  ████  ", " ██  ██ ", "██    ██"],
}


def build_banner(word: str = "CTPAX") -> str:
    rows = ["" for _ in range(6)]
    for letter in word:
        glyph = _GLYPH_ROWS.get(letter.upper())
        if glyph is None:
            continue
        for index in range(6):
            rows[index] += ("   " if rows[index] else "") + glyph[index]
    return "\n".join(rows)


CTPAX_ART = "\n" + build_banner() + "\n"

ACCENT = "\x1b[96m"
DIM = "\x1b[90m"
GREEN = "\x1b[92m"
YELLOW = "\x1b[93m"
RESET = "\x1b[0m"
USE_COLOR = IS_WINDOWS


def _enable_vt() -> None:
    """Force UTF-8 output and ask conhost for ANSI escape processing."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if not IS_WINDOWS:
        return
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


def _clear() -> None:
    os.system("cls" if IS_WINDOWS else "clear")


def c(text: str) -> str:
    return f"{ACCENT}{text}{RESET}" if USE_COLOR else text


def dim(text: str) -> str:
    return f"{DIM}{text}{RESET}" if USE_COLOR else text


def ok_text(text: str) -> str:
    return f"{GREEN}{text}{RESET}" if USE_COLOR else text


# --------------------------------------------------------------------------
# drive scanning
# --------------------------------------------------------------------------
class _DiscSpace(ctypes.Structure):
    _fields_ = [
        ("low_free_bytes_for_user", ctypes.c_uint32),
        ("high_free_bytes_for_user", ctypes.c_uint32),
        ("low_total_bytes", ctypes.c_uint32),
        ("high_total_bytes", ctypes.c_uint32),
        ("low_total_free_bytes", ctypes.c_uint32),
        ("high_total_free_bytes", ctypes.c_uint32),
    ]


def scan_drives() -> list[dict]:
    """All fixed drives with their free space, most free first."""
    drives = []
    if IS_WINDOWS:
        kernel32 = ctypes.windll.kernel32
        mask = kernel32.GetLogicalDrives()
        for index in range(26):
            if not (mask >> index) & 1:
                continue
            letter = chr(ord("A") + index)
            root = f"{letter}:\\"
            try:
                kind = kernel32.GetDriveTypeW(root)
            except OSError:
                continue
            if kind != 3:  # DRIVE_FIXED only: skip removable / network / cdrom
                continue
            free_user = ctypes.c_uint64()
            total = ctypes.c_uint64()
            total_free = ctypes.c_uint64()
            if not kernel32.GetDiskFreeSpaceExW(root, ctypes.byref(free_user), ctypes.byref(total), ctypes.byref(total_free)):
                continue
            drives.append({
                "root": root,
                "letter": letter,
                "free_gb": free_user.value / (1024**3),
                "total_gb": total.value / (1024**3),
                "system": root.upper() == Path(os.environ.get("SystemDrive", "C:\\")).as_posix()[:2] + "\\",
            })
    else:
        usage = shutil.disk_usage("/")
        drives.append({"root": "/", "letter": "/", "free_gb": usage.free / (1024**3), "total_gb": usage.total / (1024**3), "system": True})
    drives.sort(key=lambda d: -d["free_gb"])
    return drives


def mini_bar(fraction: float, width: int = 22) -> str:
    filled = int(round(fraction * width))
    return "█" * filled + "░" * (width - filled)


# --------------------------------------------------------------------------
# progress bar (single animated line)
# --------------------------------------------------------------------------
class Progress:
    """Console progress bar: call .set(fraction, stage); it redraws one line."""

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled and sys.stdout.isatty()
        self._last = 0.0
        self._stop = threading.Event()

    def set(self, stage: str, fraction: float) -> None:
        if not self._enabled:
            print(f"    -> {stage} ({int(fraction * 100)}%)", flush=True)
            return
        if time.time() - self._last < 0.05 and fraction < 1.0:
            return
        self._last = time.time()
        bar = mini_bar(fraction, 30)
        line = f"  {c('CTPAX')} [{bar}] {int(fraction * 100):3d}%  {stage}"[: (shutil.get_terminal_size((110, 20)).columns - 1)]
        sys.stdout.write("\r" + line + " " * max(0, 110 - len(line)))
        sys.stdout.flush()
        if fraction >= 1.0:
            sys.stdout.write("\n")
            sys.stdout.flush()


# --------------------------------------------------------------------------
# the engine: import install.py from the laid-down copy (never from the exe)
# --------------------------------------------------------------------------
def load_engine(script: Path) -> object:
    script = Path(script)
    if not script.is_file():
        raise FileNotFoundError(f"installer engine missing: {script}")
    spec = importlib.util.spec_from_file_location("ctpax_install", script)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode_backup = getattr(sys, "dont_write_bytecode", False)
    sys.dont_write_bytecode = True  # keep the source tree free of __pycache__
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = sys.dont_write_bytecode_backup
    return module


def extract_bundled_project(destination: Path) -> Path:
    """Frozen exe mode: unpack the project zip embedded in the binary.

    build_release.py packs the whole source tree as CTPAX-project.zip and PyInstaller
    ships it inside the exe; at run time it lands in CTPAX\\installer and the engine
    loads from there, so the single exe is genuinely self-contained.
    """
    bundle = Path(getattr(sys, "_MEIPASS", ".")) / "CTPAX-project.zip"
    if not bundle.is_file():
        raise FileNotFoundError("the exe has no embedded project payload")
    destination.mkdir(parents=True, exist_ok=True)
    import zipfile

    with zipfile.ZipFile(bundle) as archive:
        archive.extractall(destination)
    return destination


def get_installer_dir(target_root: Path) -> Path:
    """Where install.py lives for this run: extracted payload (exe) or file copy (bat)."""
    if getattr(sys, "frozen", False):
        return extract_bundled_project(target_root / "installer")
    return self_copy_into(target_root)


def self_copy_into(target: Path) -> Path:
    """Copy this project (everything except caches) into CTPAX\\installer and return it."""
    source = Path(__file__).resolve().parent
    destination = target / "installer"
    if source == destination or source.is_relative_to(destination):
        return source
    destination.mkdir(parents=True, exist_ok=True)
    for entry in source.iterdir():
        if entry.name in {"__pycache__", ".git", "node_modules", "venv", "ctpax"}:
            continue
        # skip our own install target if it lives inside the source tree
        try:
            entry.resolve().relative_to(target.resolve())
            continue
        except ValueError:
            pass
        target_path = destination / entry.name
        if entry.is_dir():
            shutil.copytree(entry, target_path, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy2(entry, target_path)
    return destination


# --------------------------------------------------------------------------
# prerequisites on a clean machine: Ghidra + a JDK 21
# --------------------------------------------------------------------------
GHIDRA_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
ADOPTIUM_API = (
    "https://api.adoptium.net/v3/assets/latest/21/hotspot"
    "?architecture=x64&image_type=jdk&os=windows&vendor=eclipse"
)


def _download(url: str, destination: Path, label: str) -> None:
    """Stream a download with a console progress bar (Content-Length when offered)."""
    import urllib.request

    request = urllib.request.Request(url, headers={"User-Agent": "CTPAX-Setup"})
    with urllib.request.urlopen(request, timeout=120) as response, open(destination, "wb") as handle:
        total = int(response.headers.get("Content-Length") or 0)
        done = 0
        last = 0.0
        while True:
            chunk = response.read(1024 * 256)
            if not chunk:
                break
            handle.write(chunk)
            done += len(chunk)
            now = time.time()
            if now - last > 0.2:
                last = now
                if total:
                    fraction = done / total
                    sys.stdout.write(f"\r    {label:<28} {mini_bar(fraction, 24)} {done / 1048576:6.1f}/{total / 1048576:.0f} MB")
                else:
                    sys.stdout.write(f"\r    {label:<28} {done / 1048576:6.1f} MB")
                sys.stdout.flush()
    sys.stdout.write("\n")
    sys.stdout.flush()


def _find_marker(root: Path, marker: str) -> Path | None:
    if not root.is_dir():
        return None
    for candidate in root.rglob(marker):
        return candidate
    return None


def ensure_ghidra(target_root: Path, *, offline: bool = False) -> Path | None:
    """A Ghidra install inside CTPAX (downloading it on a clean machine)."""
    import json
    import urllib.request
    import zipfile

    local = target_root / "ghidra"
    marker = _find_marker(local, "analyzeHeadless.bat")
    if marker is not None:
        print(f"    {ok_text('Ghidra found')}: {marker.parent.parent}")
        return marker.parent.parent
    if offline:
        return None

    try:
        request = urllib.request.Request(GHIDRA_API, headers={"User-Agent": "CTPAX-Setup"})
        with urllib.request.urlopen(request, timeout=30) as response:
            release = json.loads(response.read())
        asset = next(
            (a for a in release["assets"] if a["name"].lower().endswith(".zip") and "public" in a["name"].lower() and "ghidra_" in a["name"].lower()),
            None,
        )
        if asset is None:
            print(f"    {YELLOW}no Ghidra zip in the latest release; install it manually{RESET}")
            return None
        print(f"    downloading Ghidra {release['tag_name']} (~450MB) ...")
        archive = target_root / "_ghidra.zip"
        _download(asset["browser_download_url"], archive, f"Ghidra {release['tag_name']}")
        local.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(local)
        archive.unlink(missing_ok=True)
        marker = _find_marker(local, "analyzeHeadless.bat")
        if marker is None:
            print(f"    {YELLOW}Ghidra archive layout unexpected{RESET}")
            return None
        print(f"    {ok_text('Ghidra installed')}: {marker.parent.parent}")
        return marker.parent.parent
    except Exception as exc:
        print(f"    {YELLOW}could not install Ghidra automatically ({exc}){RESET}")
        return None


def ensure_jdk(target_root: Path, *, offline: bool = False) -> Path | None:
    """A JDK 21 inside CTPAX (Eclipse Temurin, downloading it on a clean machine)."""
    import json
    import urllib.request
    import zipfile

    local = target_root / "jdk"
    marker = _find_marker(local, "java.exe")
    if marker is not None:
        print(f"    {ok_text('JDK found')}: {marker.parent.parent}")
        return marker.parent.parent
    if offline:
        return None

    try:
        request = urllib.request.Request(ADOPTIUM_API, headers={"User-Agent": "CTPAX-Setup"})
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read())
        link = payload[0]["binary"]["package"]["link"]
        name = payload[0]["binary"]["package"]["name"]
        print(f"    downloading {name} (~190MB) ...")
        archive = target_root / "_jdk.zip"
        _download(link, archive, "JDK 21 (Temurin)")
        local.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(local)
        archive.unlink(missing_ok=True)
        marker = _find_marker(local, "java.exe")
        if marker is None:
            print(f"    {YELLOW}JDK archive layout unexpected{RESET}")
            return None
        home = marker.parent.parent
        print(f"    {ok_text('JDK installed')}: {home}")
        return home
    except Exception as exc:
        print(f"    {YELLOW}could not install a JDK automatically ({exc}){RESET}")
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="CTPAX installer")
    parser.add_argument("--check", action="store_true", help="show the plan, install nothing")
    parser.add_argument("--engine-only", action="store_true", help="lay the sources down, load the engine, then stop (self-test)")
    parser.add_argument("--recreate-venv", action="store_true", help="rebuild the virtual environment")
    parser.add_argument("--offline", action="store_true", help="skip all downloads")
    args = parser.parse_args()

    _enable_vt()

    # --- phase 1: the two-stage banner ---
    print(c(f"  {SMALL_BANNER}"), flush=True)
    time.sleep(1.6)
    _clear()
    print(c(CTPAX_ART), flush=True)
    print(dim(f"  {'full reverse-engineering MCP toolkit - one-shot installer':^56}"), flush=True)
    print(dim("  " + "-" * 56), flush=True)

    if not IS_WINDOWS:
        print("  Windows is required for this installer.", file=sys.stderr)
        return 1
    if sys.version_info < (3, 10):
        print("  Python 3.10+ is required to run the installer.", file=sys.stderr)
        return 1

    # --- phase 2: choose the drive ---
    drives = scan_drives()
    if not drives:
        print("  No fixed drives found.", file=sys.stderr)
        return 1
    biggest = drives[0]
    print("  Drives:", flush=True)
    for drive in drives[:6]:
        need = 12
        marker = ok_text(" <- CTPAX here") if drive is biggest else (dim("   (too full)") if drive["free_gb"] < need else "")
        print(f"   {c(drive['root']):<5} free {drive['free_gb']:7.1f} GB / {drive['total_gb']:6.1f} GB  [{mini_bar(drive['free_gb'] / max(1, drive['total_gb']), 14)}]{marker}", flush=True)
    if biggest["free_gb"] < 12:
        print("\n  Not enough free space: the toolkit (venv + Ghidra projects + Nuclei templates) needs ~12 GB.", file=sys.stderr)
        return 1

    target_root = Path(biggest["root"]) / "CTPAX"
    home = target_root / "GhidraMCP"
    print(dim(f"  plan: copy installer -> {target_root}\\installer, everything -> {home}"), flush=True)

    if args.check:
        print("  --check: nothing installed.", flush=True)
        return 0

    # --- phase 3: lay the sources down (embedded zip for the exe, file copy for the bat)
    print(f"\n  {c('1/3')} checking Ghidra and JDK 21 ...", flush=True)
    prereq_offline = args.offline or args.engine_only  # the self-test downloads nothing
    ghidra_home = ensure_ghidra(target_root, offline=prereq_offline)
    java_home = ensure_jdk(target_root, offline=prereq_offline)
    if ghidra_home is None or java_home is None:
        print(f"    {YELLOW}not found locally; the installer will look for them on the system{RESET}")

    print(f"  {c('2/3')} laying the project into {target_root}\\installer ...", flush=True)
    engine_dir = get_installer_dir(target_root)
    print(f"      {ok_text('done')}", flush=True)

    # --- phase 4: run the engine with progress ---
    print(f"  {c('3/3')} installing everything (this is the long part):\n", flush=True)
    sys.path.insert(0, str(engine_dir))
    try:
        engine = load_engine(engine_dir / "install.py")
    except Exception as exc:
        print(f"  could not load the installer engine: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1
    os.chdir(engine_dir)

    if args.engine_only:
        print(f"  {ok_text('engine loaded')} from {engine_dir} (--engine-only: stopping here)")
        return 0

    bar = Progress()
    engine.PROGRESS = bar.set
    namespace = argparse.Namespace(
        check=False, uninstall=False,
        home=str(home),
        ghidra=str(ghidra_home) if ghidra_home else None,
        java=str(java_home) if java_home else None,
        opencode_config=None, cursor=False, cursor_config=None,
        claude=False, codex=False, all_clients=True,
        heap=os.environ.get("CTPAX_HEAP", "4G"),
        recreate_venv=args.recreate_venv, offline=args.offline,
        skip_verify=False, force=False,
    )
    try:
        code = engine.do_install(namespace)
    except KeyboardInterrupt:
        print("\n  Interrupted. Re-run CTPAX.bat to resume safely.", flush=True)
        return 130
    finally:
        engine.PROGRESS = None

    # --- phase 5: summary ---
    print()
    print(ok_text("  CTPAX is in place."))
    print(f"    toolkit root : {target_root}")
    print(f"    server home  : {home}")
    print(f"    venv         : {home / 'venv'}")
    print(f"    projects     : {home / 'projects'}")
    try:
        clients = engine.detect_clients()
        found = [name for name, yes in clients.items() if yes]
        print(f"    AI clients   : {', '.join(found) or 'none detected - re-run after installing a client'}")
    except Exception:
        pass
    print(dim("    restart the AI client, then ask it: run doctor from the ghidra mcp"))
    return code


if __name__ == "__main__":
    sys.exit(main())
