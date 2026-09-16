"""Runtime configuration and environment discovery for the Ghidra reverse-engineering MCP server.

Configuration is resolved in this order (first hit wins):

1. process environment (``GHIDRA_INSTALL_DIR``, ``JAVA_HOME``, ...)
2. ``config.json`` inside ``GHIDRA_MCP_HOME`` (written by ``install.bat``)
3. a best-effort filesystem probe

Nothing here imports Ghidra or JPype: the MCP server process itself never loads a
JVM, that only happens inside the worker subprocess (see ``worker.py``).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

APP_NAME = "GhidraMCP"

# Directory-name patterns used when probing for an unconfigured installation.
_GHIDRA_DIR_RE = re.compile(r"^ghidra[_-].*", re.IGNORECASE)
_JDK_DIR_RE = re.compile(r"^(jdk|java|openjdk|temurin|zulu|graalvm|corretto|liberica|semeru).*", re.IGNORECASE)

MIN_JAVA_VERSION = 21


def default_home() -> Path:
    """Where the install lives: venv, copied sources, projects, logs, notes."""
    env = os.environ.get("GHIDRA_MCP_HOME")
    if env:
        return Path(env)
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME")
    if base:
        return Path(base) / APP_NAME
    return Path.home() / f".{APP_NAME.lower()}"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def _candidate_roots() -> list[Path]:
    """Plausible parents of a Ghidra or JDK installation, cheapest first."""
    roots: list[Path] = []
    for var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "LOCALAPPDATA", "USERPROFILE"):
        value = os.environ.get(var)
        if value:
            roots.append(Path(value))
    home = Path.home()
    roots += [home, home / "Downloads", home / "Desktop", home / "tools", home / "Documents"]
    if os.name == "nt":
        # Bare drive roots: people unzip Ghidra to D:\ or E:\ or even I:\ constantly,
        # so probe every drive letter that actually exists rather than a fixed subset.
        import string

        for letter in string.ascii_uppercase:
            drive = Path(f"{letter}:\\")
            if drive.exists():
                roots.append(drive)
                roots.append(drive / "tools")
    else:
        roots += [Path("/opt"), Path("/usr/share"), Path("/usr/local"), Path("/usr/lib/jvm")]
    seen: set[str] = set()
    unique: list[Path] = []
    for root in roots:
        key = str(root).lower()
        if key not in seen:
            seen.add(key)
            unique.append(root)
    return unique


def _iter_dirs(root: Path) -> Iterable[Path]:
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        yield Path(entry.path)
                except OSError:
                    continue
    except OSError:
        return


def is_ghidra_dir(path: Path) -> bool:
    return (path / "support" / "analyzeHeadless.bat").exists() or (path / "support" / "analyzeHeadless").exists()


def ghidra_version(path: Path) -> str | None:
    props = path / "Ghidra" / "application.properties"
    if not props.exists():
        return None
    try:
        for line in props.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("application.version="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return None


def probe_ghidra() -> Path | None:
    """Look for an unpacked Ghidra release without walking the whole filesystem."""
    for root in _candidate_roots():
        if is_ghidra_dir(root):
            return root
        for child in _iter_dirs(root):
            if _GHIDRA_DIR_RE.match(child.name) and is_ghidra_dir(child):
                return child
            # One extra level: ...\tools\ghidra\ghidra_11.3_PUBLIC
            if child.name.lower() in {"ghidra", "tools", "re", "reverse"}:
                for grand in _iter_dirs(child):
                    if is_ghidra_dir(grand):
                        return grand
    return None


def java_home_of(path: Path) -> Path | None:
    """Normalise *path* to a JDK home that contains both ``java`` and ``jvm`` libraries."""
    if not path:
        return None
    candidates = [path]
    if path.name.lower() == "bin":
        candidates.append(path.parent)
    for cand in candidates:
        launcher = cand / "bin" / ("java.exe" if os.name == "nt" else "java")
        if launcher.exists():
            return cand
    return None


def java_version_of(home: Path) -> int | None:
    launcher = home / "bin" / ("java.exe" if os.name == "nt" else "java")
    if not launcher.exists():
        return None
    try:
        out = subprocess.run(
            [str(launcher), "-version"],
            capture_output=True, stdin=subprocess.DEVNULL,
            text=True,
            timeout=25,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return None
    text = f"{out.stderr}\n{out.stdout}"
    match = re.search(r'version "(\d+)(?:\.(\d+))?', text)
    if not match:
        return None
    major = int(match.group(1))
    if major == 1 and match.group(2):  # 1.8.0 style
        major = int(match.group(2))
    return major


def has_jvm_library(home: Path) -> bool:
    """JPype needs the shared library, which a plain JRE-on-PATH sometimes lacks."""
    patterns = ("jvm.dll", "libjvm.so", "libjvm.dylib")
    for sub in ("bin/server", "bin/client", "lib/server", "jre/bin/server", "lib"):
        directory = home / sub
        for name in patterns:
            if (directory / name).exists():
                return True
    return False


def probe_java(min_version: int = MIN_JAVA_VERSION, ghidra_dir: Path | None = None) -> Path | None:
    """Find a JDK new enough for Ghidra, preferring what Ghidra itself remembers."""
    checked: set[str] = set()

    def accept(home: Path | None) -> Path | None:
        if not home:
            return None
        home = java_home_of(home)
        if not home:
            return None
        key = str(home).lower()
        if key in checked:
            return None
        checked.add(key)
        if not has_jvm_library(home):
            return None
        version = java_version_of(home)
        if version is None or version < min_version:
            return None
        return home

    # 1. Ghidra's own remembered JDK ("lastrun" style files under the user settings dir).
    if ghidra_dir is not None:
        for saved in _ghidra_saved_jdks(ghidra_dir):
            found = accept(saved)
            if found:
                return found

    # 2. Explicit environment.
    for var in ("JAVA_HOME", "JDK_HOME"):
        found = accept(Path(os.environ[var])) if os.environ.get(var) else None
        if found:
            return found

    # 3. Whatever is on PATH.
    which = shutil.which("java")
    if which:
        found = accept(Path(which).parent.parent)
        if found:
            return found

    # 4. Probe common install locations.
    for root in _candidate_roots():
        for child in _iter_dirs(root):
            if _JDK_DIR_RE.match(child.name):
                found = accept(child)
                if found:
                    return found
                for grand in _iter_dirs(child):  # e.g. ...\Eclipse Adoptium\jdk-21.0.5+11
                    if _JDK_DIR_RE.match(grand.name):
                        found = accept(grand)
                        if found:
                            return found
    return None


def _ghidra_saved_jdks(ghidra_dir: Path) -> list[Path]:
    """Parse the JDK paths Ghidra saved from a previous successful launch."""
    results: list[Path] = []
    version = ghidra_version(ghidra_dir) or ""
    settings_roots: list[Path] = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        settings_roots.append(Path(appdata) / "ghidra")
    settings_roots.append(Path.home() / ".ghidra")
    for root in settings_roots:
        if not root.exists():
            continue
        for child in _iter_dirs(root):
            if version and version not in child.name:
                continue
            for name in ("java_home_save", "lastrun", "launch.properties"):
                candidate = child / name
                if not candidate.exists():
                    continue
                try:
                    text = candidate.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line and not Path(line).exists():
                        line = line.split("=", 1)[1].strip()
                    path = Path(line)
                    if path.exists():
                        results.append(path)
    return results


@dataclass
class Settings:
    home: Path = field(default_factory=default_home)
    ghidra_dir: Path | None = None
    java_home: Path | None = None
    project_dir: Path | None = None
    log_dir: Path | None = None
    # Guard rails, all overridable through config.json / environment.
    max_output_chars: int = 60000
    decompile_timeout: int = 90
    worker_start_timeout: float = 240.0
    request_timeout: float = 600.0
    max_file_size: int = 2 * 1024 * 1024 * 1024
    jvm_max_heap: str = "4G"
    allow_write: bool = True
    notes_file: Path | None = None
    # WinDbg symbol path for cdb runs and sessions; override for offline machines
    # (SYM* paths, a local symbol cache) or a different symbol cache location.
    symbol_path: str = r"srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
    # Where x64dbg lives (the installer records the copy it unpacked under <CTPAX>).
    x64dbg_dir: Path | None = None

    def __post_init__(self) -> None:
        self.home = Path(self.home)
        self.project_dir = Path(self.project_dir) if self.project_dir else self.home / "projects"
        self.log_dir = Path(self.log_dir) if self.log_dir else self.home / "logs"
        self.notes_file = Path(self.notes_file) if self.notes_file else self.home / "notes.json"
        self.x64dbg_dir = Path(self.x64dbg_dir) if self.x64dbg_dir else None

    @classmethod
    def load(cls) -> "Settings":
        home = default_home()
        data = _read_json(home / "config.json")

        def pick(key: str, env: str | None = None) -> Any:
            if env and os.environ.get(env):
                return os.environ[env]
            return data.get(key)

        ghidra = pick("ghidra_dir", "GHIDRA_INSTALL_DIR")
        java = pick("java_home", "JAVA_HOME")
        x64dbg = pick("x64dbg_dir", "X64DBG_DIR")
        settings = cls(
            home=home,
            ghidra_dir=Path(ghidra) if ghidra else None,
            java_home=java_home_of(Path(java)) if java else None,
            project_dir=Path(data["project_dir"]) if data.get("project_dir") else None,
            log_dir=Path(data["log_dir"]) if data.get("log_dir") else None,
            x64dbg_dir=Path(x64dbg) if x64dbg else None,
        )
        for key in (
            "max_output_chars",
            "decompile_timeout",
            "worker_start_timeout",
            "request_timeout",
            "max_file_size",
        ):
            if key in data:
                setattr(settings, key, type(getattr(settings, key))(data[key]))
        if data.get("jvm_max_heap"):
            settings.jvm_max_heap = str(data["jvm_max_heap"])
        if os.environ.get("GHIDRA_MCP_HEAP"):
            settings.jvm_max_heap = os.environ["GHIDRA_MCP_HEAP"]
        if data.get("symbol_path"):
            settings.symbol_path = str(data["symbol_path"])
        if os.environ.get("GHIDRA_MCP_SYMBOL_PATH"):
            settings.symbol_path = os.environ["GHIDRA_MCP_SYMBOL_PATH"]
        if "allow_write" in data:
            settings.allow_write = bool(data["allow_write"])
        if os.environ.get("GHIDRA_MCP_READONLY") == "1":
            settings.allow_write = False

        if settings.ghidra_dir and not is_ghidra_dir(settings.ghidra_dir):
            settings.ghidra_dir = None
        if settings.ghidra_dir is None:
            settings.ghidra_dir = probe_ghidra()
        if settings.java_home is None or not has_jvm_library(settings.java_home):
            settings.java_home = probe_java(ghidra_dir=settings.ghidra_dir)
        return settings

    # -- helpers ---------------------------------------------------------
    def ensure_dirs(self) -> None:
        for directory in (self.home, self.project_dir, self.log_dir):
            try:
                Path(directory).mkdir(parents=True, exist_ok=True)
            except OSError:
                pass

    def describe(self) -> dict[str, Any]:
        return {
            "home": str(self.home),
            "ghidra_dir": str(self.ghidra_dir) if self.ghidra_dir else None,
            "ghidra_version": ghidra_version(self.ghidra_dir) if self.ghidra_dir else None,
            "java_home": str(self.java_home) if self.java_home else None,
            "java_version": java_version_of(self.java_home) if self.java_home else None,
            "project_dir": str(self.project_dir),
            "log_dir": str(self.log_dir),
            "jvm_max_heap": self.jvm_max_heap,
            "symbol_path": self.symbol_path,
            "allow_write": self.allow_write,
            "read_only_reason": None if self.allow_write else "GHIDRA_MCP_READONLY=1 or config allow_write=false",
        }

    def problems(self) -> list[str]:
        issues: list[str] = []
        if not self.ghidra_dir:
            issues.append(
                "Ghidra installation not found. Set GHIDRA_INSTALL_DIR (the folder that contains "
                "support/analyzeHeadless) or re-run install.bat."
            )
        if not self.java_home:
            issues.append(
                f"No JDK {MIN_JAVA_VERSION}+ with a JVM shared library found. Set JAVA_HOME to a full JDK."
            )
        return issues
