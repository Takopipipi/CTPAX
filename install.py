"""Installer for the Ghidra reverse-engineering MCP server.

Driven by ``install.bat``, but usable directly: ``python install.py [--check] [--uninstall]``.

What it does, in order:

1. locates a suitable Python, Ghidra installation, and JDK 21+ (probing, then asking);
2. creates a private virtual environment under ``%LOCALAPPDATA%\\GhidraMCP``;
3. installs the dependencies, working around the fact that ``pyghidra`` pins an old
   JPype that fails on some paths;
4. copies the server sources next to the venv, so the install keeps working if this
   source folder moves or is deleted;
5. writes ``config.json`` with the discovered paths;
6. registers the server in OpenCode's config, preserving everything already in it and
   keeping a timestamped backup;
7. starts the server and calls its own ``doctor`` tool to prove the install works.

Step 7 is the point: an installer that reports success without having run the thing it
installed is just a file copier.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE_ROOT = HERE / "src"
PACKAGE = "ghidra_mcp"
MCP_SERVER_NAME = "ghidra"

MIN_PYTHON = (3, 10)
MIN_JAVA = 21

# pyghidra 3.1.0 requires JPype1==1.5.2 exactly, so it is installed with --no-deps and
# JPype pinned separately. Bumping JPype breaks Ghidra's class loading.
REQUIREMENTS = [
    "mcp==1.29.1",
    "capstone==5.0.9",
    "lief==0.17.6",
    "pefile==2024.8.26",
    "pyelftools==0.32",
    "yara-python==4.5.4",
    "pycryptodome==3.23.0",
    "x64dbg-automate==0.9.2",
    "dnfile==0.17.0",
    "dncil==1.0.2",
    "msgpack==1.2.2",
]
REQUIREMENTS_NO_DEPS = ["pyghidra==3.1.0"]
REQUIREMENTS_PINNED = ["JPype1==1.5.2", "packaging"]


# --------------------------------------------------------------------------
# console output
# --------------------------------------------------------------------------
class Console:
    def __init__(self) -> None:
        self.quiet = False

    def step(self, text: str) -> None:
        print(f"\n=== {text}")

    def info(self, text: str) -> None:
        print(f"    {text}")

    def ok(self, text: str) -> None:
        print(f"  [ok] {text}")

    def warn(self, text: str) -> None:
        print(f"  [!!] {text}")

    def fail(self, text: str) -> None:
        print(f"  [XX] {text}")


out = Console()


def die(message: str, *, code: int = 1) -> "NoReturn":  # type: ignore[valid-type]
    out.fail(message)
    print("\nInstallation aborted. Nothing was registered in OpenCode.")
    sys.exit(code)


def ask(prompt: str, *, default: str = "") -> str:
    if not sys.stdin or not sys.stdin.isatty():
        return default
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"    {prompt}{suffix}: ").strip().strip('"')
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return answer or default


def confirm(prompt: str, *, default: bool = True) -> bool:
    if not sys.stdin or not sys.stdin.isatty():
        return default
    hint = "Y/n" if default else "y/N"
    try:
        answer = input(f"    {prompt} [{hint}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not answer:
        return default
    return answer.startswith(("y", "Рґ"))


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------
def load_config_module():
    """Import the server's own config module, which already knows how to probe."""
    if str(SOURCE_ROOT) not in sys.path:
        sys.path.insert(0, str(SOURCE_ROOT))
    from ghidra_mcp import config  # noqa: PLC0415

    return config


def find_ghidra(config, preset: str | None) -> Path:
    out.step("Locating Ghidra")
    if preset:
        candidate = Path(preset).expanduser()
        if config.is_ghidra_dir(candidate):
            out.ok(f"{candidate} (version {config.ghidra_version(candidate) or 'unknown'})")
            return candidate
        out.warn(f"{candidate} does not look like a Ghidra installation")

    for source, value in (("GHIDRA_INSTALL_DIR", os.environ.get("GHIDRA_INSTALL_DIR")),):
        if value and config.is_ghidra_dir(Path(value)):
            found = Path(value)
            out.ok(f"{found} (from {source}, version {config.ghidra_version(found) or 'unknown'})")
            return found

    out.info("searching common locations...")
    found = config.probe_ghidra()
    if found:
        out.ok(f"{found} (version {config.ghidra_version(found) or 'unknown'})")
        if confirm("Use this installation?"):
            return found

    print()
    out.info("Ghidra was not found automatically.")
    out.info("Enter the folder that contains 'support\\analyzeHeadless.bat',")
    out.info(r"for example E:\ghidra_11.3_PUBLIC")
    for _ in range(3):
        answer = ask("Ghidra folder")
        if not answer:
            break
        candidate = Path(answer).expanduser()
        if config.is_ghidra_dir(candidate):
            out.ok(f"{candidate} (version {config.ghidra_version(candidate) or 'unknown'})")
            return candidate
        out.warn(f"no support/analyzeHeadless found under {candidate}")
    die("Ghidra is required. Download it from https://ghidra-sre.org and unzip it, then re-run this installer.")


def find_java(config, preset: str | None, ghidra_dir: Path) -> Path:
    out.step(f"Locating a JDK (Java {MIN_JAVA} or newer, with a JVM shared library)")
    if preset:
        home = config.java_home_of(Path(preset).expanduser())
        if home and config.has_jvm_library(home):
            version = config.java_version_of(home)
            if version and version >= MIN_JAVA:
                out.ok(f"{home} (Java {version})")
                return home
            out.warn(f"{home} is Java {version}, which is older than {MIN_JAVA}")
        else:
            out.warn(f"{preset} is not a usable JDK home")

    out.info("searching JAVA_HOME, PATH, and common install locations...")
    found = config.probe_java(min_version=MIN_JAVA, ghidra_dir=ghidra_dir)
    if found:
        out.ok(f"{found} (Java {config.java_version_of(found)})")
        return found

    print()
    out.info(f"No JDK {MIN_JAVA}+ was found. Ghidra needs a full JDK, not a JRE.")
    out.info("Get one from https://adoptium.net (Temurin 21, JDK not JRE).")
    for _ in range(3):
        answer = ask("JDK folder (the one containing bin\\java.exe)")
        if not answer:
            break
        home = config.java_home_of(Path(answer).expanduser())
        if not home:
            out.warn("no bin/java there")
            continue
        if not config.has_jvm_library(home):
            out.warn("that looks like a JRE: no jvm.dll under bin/server. A full JDK is required.")
            continue
        version = config.java_version_of(home)
        if not version or version < MIN_JAVA:
            out.warn(f"that is Java {version}; {MIN_JAVA} or newer is required")
            continue
        out.ok(f"{home} (Java {version})")
        return home
    die(f"A JDK {MIN_JAVA}+ is required.")


def check_python() -> None:
    out.step("Checking Python")
    if sys.version_info < MIN_PYTHON:
        die(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required; this is {sys.version.split()[0]}")
    out.ok(f"Python {sys.version.split()[0]} at {sys.executable}")


def check_install_path(home: Path) -> None:
    """Reject install paths JPype cannot cope with.

    JPype fails to create its Java reflector when any component of the interpreter's path
    ends with '!' - the classpath entry it builds is then read as a JAR-internal path. The
    failure surfaces much later as an opaque 'Unable to create reflector' error, so it is
    worth catching here rather than after installing everything.
    """
    for part in home.resolve().parts:
        if part.rstrip("\\/").endswith("!"):
            die(
                f"the install path contains a folder ending with '!' ({part}). "
                "JPype cannot start a JVM from such a path. Choose a different location "
                "with --home, e.g. --home C:\\Tools\\GhidraMCP"
            )


# --------------------------------------------------------------------------
# environment build
# --------------------------------------------------------------------------
def build_venv(home: Path, *, recreate: bool) -> Path:
    out.step("Creating the virtual environment")
    venv = home / "venv"
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    if venv.exists() and recreate:
        out.info("removing the previous environment")
        shutil.rmtree(venv, ignore_errors=True)

    if python.exists():
        out.ok(f"reusing {venv}")
        return python

    home.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([sys.executable, "-m", "venv", str(venv)], capture_output=True, text=True)
    if result.returncode != 0 or not python.exists():
        die(f"could not create a virtual environment at {venv}\n{result.stderr.strip()[:800]}")
    out.ok(str(venv))
    return python


def pip(python: Path, arguments: list[str], *, label: str) -> None:
    command = [str(python), "-m", "pip", "install", "--disable-pip-version-check", *arguments]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        tail = (result.stderr or result.stdout).strip().splitlines()[-12:]
        die(f"{label} failed:\n      " + "\n      ".join(tail))


def install_dependencies(python: Path, *, offline: bool) -> None:
    out.step("Installing dependencies")
    if offline:
        out.warn("offline mode: skipping installation, assuming the environment is ready")
        return

    out.info("upgrading pip")
    subprocess.run(
        [str(python), "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--upgrade", "pip"],
        capture_output=True,
        text=True,
    )

    out.info(f"installing {len(REQUIREMENTS)} packages (mcp, lief, capstone, yara, pycryptodome, ...)")
    pip(python, ["--quiet", *REQUIREMENTS], label="installing the main dependencies")

    out.info("installing pyghidra without its dependency pin")
    pip(python, ["--quiet", "--no-deps", *REQUIREMENTS_NO_DEPS], label="installing pyghidra")

    out.info("installing JPype 1.5.2, the version Ghidra 11+ needs")
    pip(python, ["--quiet", *REQUIREMENTS_PINNED], label="installing JPype")

    check = subprocess.run(
        [
            str(python),
            "-c",
            "import mcp, jpype, pyghidra, capstone, lief, pefile, elftools, yara, Crypto;"
            "print(jpype.__version__)",
        ],
        capture_output=True,
        text=True,
    )
    if check.returncode != 0:
        die(f"the installed environment is not importable:\n      {check.stderr.strip()[:600]}")
    out.ok(f"all dependencies import cleanly (JPype {check.stdout.strip()})")


def copy_sources(home: Path) -> Path:
    """Copy the package into the install directory.

    Running from the install directory rather than this source folder means the MCP
    registration keeps working after this folder is moved, renamed, or deleted.
    """
    out.step("Copying the server sources")
    if not (SOURCE_ROOT / PACKAGE / "server.py").exists():
        die(f"the sources are missing: expected {SOURCE_ROOT / PACKAGE / 'server.py'}")
    destination = home / "src"
    target = destination / PACKAGE
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True, exist_ok=True)
    copied = 0
    for item in (SOURCE_ROOT / PACKAGE).glob("*.py"):
        shutil.copy2(item, target / item.name)
        copied += 1
    # native helpers ship precompiled next to the package (exception logger DLL)
    native_source = SOURCE_ROOT / PACKAGE / "native"
    if native_source.exists():
        native_target = target / "native"
        native_target.mkdir(exist_ok=True)
        for item in native_source.iterdir():
            if item.suffix in (".dll", ".c"):
                shutil.copy2(item, native_target / item.name)
                copied += 1
    out.ok(f"{copied} modules -> {target}")
    return destination


def write_config(home: Path, ghidra_dir: Path, java_home: Path, heap: str) -> Path:
    out.step("Writing config.json")
    path = home / "config.json"
    existing: dict = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            existing = {}
    existing.update(
        {
            "ghidra_dir": str(ghidra_dir),
            "java_home": str(java_home),
            "project_dir": str(home / "projects"),
            "log_dir": str(home / "logs"),
            "jvm_max_heap": heap,
            "installed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "installer_version": 1,
        }
    )
    existing.setdefault("allow_write", True)
    existing.setdefault("max_output_chars", 60000)
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    for directory in ("projects", "logs", "scripts"):
        (home / directory).mkdir(parents=True, exist_ok=True)
    out.ok(str(path))
    return path


# --------------------------------------------------------------------------
# OpenCode registration
# --------------------------------------------------------------------------
def opencode_config_path(preset: str | None) -> Path:
    if preset:
        return Path(preset).expanduser()
    candidates: list[Path] = []
    override = os.environ.get("OPENCODE_CONFIG")
    if override:
        candidates.append(Path(override))
    base = Path.home() / ".config" / "opencode"
    candidates += [base / "opencode.jsonc", base / "opencode.json"]
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates += [Path(appdata) / "opencode" / "opencode.jsonc", Path(appdata) / "opencode" / "opencode.json"]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return base / "opencode.jsonc"


def cursor_config_path(preset: str | None) -> Path:
    """Global Cursor MCP config: ``~/.cursor/mcp.json`` (a superset of Cursor's own).

    Cursor merges this global file with each project's ``.cursor/mcp.json``; the global
    one makes the server available in every project. Its schema differs from OpenCode's:
    top-level key is ``mcpServers``, and a stdio server is ``command`` (an executable
    string) + ``args`` + ``env`` rather than a single ``command`` list.
    """
    if preset:
        return Path(preset).expanduser()
    override = os.environ.get("CURSOR_MCP")
    if override:
        return Path(override)
    return Path.home() / ".cursor" / "mcp.json"


def strip_jsonc(text: str) -> str:
    """Remove comments so a JSONC file can be parsed, without touching string contents."""
    result: list[str] = []
    index = 0
    length = len(text)
    in_string = False
    while index < length:
        character = text[index]
        if in_string:
            result.append(character)
            if character == "\\" and index + 1 < length:
                result.append(text[index + 1])
                index += 2
                continue
            if character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            result.append(character)
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index)
            index = length if newline < 0 else newline
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = length if end < 0 else end + 2
            continue
        result.append(character)
        index += 1
    # Trailing commas are legal in JSONC but not in JSON.
    return re.sub(r",(\s*[}\]])", r"\1", "".join(result))


def _tokens(text: str):
    """Tokenise JSONC into ``(index, kind, value)`` where kind is ``"string"`` or ``"char"``.

    Comments are skipped. Strings are reported as single tokens with their raw span, so a
    brace or a ``//`` inside a string value cannot be mistaken for structure - which is the
    whole reason this is a tokeniser rather than a few regexes.
    """
    index = 0
    length = len(text)
    while index < length:
        character = text[index]
        if character == '"':
            start = index
            index += 1
            while index < length:
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == '"':
                    index += 1
                    break
                index += 1
            yield start, "string", text[start:index]
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index)
            index = length if newline < 0 else newline
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = length if end < 0 else end + 2
            continue
        if character not in " \t\r\n":
            yield index, "char", character
        index += 1


def _iter_members(text: str, object_open: int):
    """Yield ``(key_name, key_start)`` for the *direct* members of one object.

    Depth tracking is what makes this correct: a plain search for ``"mcp"`` also matches a
    provider option nested three levels down, and editing that instead of the real block is
    exactly the silent corruption a config editor must never commit.
    """
    if object_open < 0 or object_open >= len(text) or text[object_open] != "{":
        return
    depth = 0
    expect_key = True
    for index, kind, value in _tokens(text):
        if index < object_open:
            continue
        if kind == "char":
            if value in "{[":
                depth += 1
                expect_key = depth == 1
                continue
            if value in "}]":
                depth -= 1
                if depth <= 0:
                    return
                continue
            if depth == 1:
                if value == ",":
                    expect_key = True
                elif value == ":":
                    expect_key = False
            continue
        # kind == "string"
        if depth == 1 and expect_key:
            yield value[1:-1], index
            expect_key = False


def _match_brace(text: str, open_index: int) -> int:
    """Index of the brace or bracket closing the one at ``open_index``, or -1."""
    opener = text[open_index]
    closer = {"{": "}", "[": "]"}[opener]
    depth = 0
    for index, kind, value in _tokens(text):
        if index < open_index or kind != "char":
            continue
        if value in "{[":
            depth += 1
        elif value in "}]":
            depth -= 1
            if depth == 0:
                return index if value == closer else -1
    return -1


def _object_span_for_key(text: str, key: str, *, object_open: int | None = None) -> tuple[int, int, int] | None:
    """Locate ``"key": { ... }`` among the direct members of an object.

    ``object_open`` is the index of the enclosing ``{``; it defaults to the document root.
    Returns ``(key_start, brace_open, brace_close)``.
    """
    if object_open is None:
        object_open = text.find("{")
    for name, key_index in _iter_members(text, object_open):
        if name != key:
            continue
        colon = text.find(":", key_index)
        if colon < 0:
            return None
        cursor = colon + 1
        while cursor < len(text) and text[cursor] in " \t\r\n":
            cursor += 1
        if cursor >= len(text) or text[cursor] != "{":
            return None
        closing = _match_brace(text, cursor)
        if closing < 0:
            return None
        return key_index, cursor, closing
    return None



def _entry_end(text: str, entry_start: int) -> int:
    """End index of the ``"key": value`` pair beginning at ``entry_start``.

    Returns the index just past the value, not including a trailing comma.
    """
    colon = text.find(":", entry_start)
    cursor = colon + 1
    while cursor < len(text) and text[cursor] in " \t\r\n":
        cursor += 1
    if cursor < len(text) and text[cursor] in "{[":
        closing = _match_brace(text, cursor)
        return closing + 1 if closing > 0 else -1
    # A scalar value runs until the next comma or closing brace at this level.
    for index, kind, value in _tokens(text):
        if index <= cursor or kind != "char":
            continue
        if value in ",}":
            return index
    return -1


def splice_mcp_entry(text: str, name: str, entry: dict, indent: str = "  ") -> str | None:
    """Insert or replace ``mcp.<name>`` in JSONC text, preserving comments and formatting.

    Returns the edited text, or None when the structure is not what we expect, in which
    case the caller falls back to a full rewrite. Keeping comments matters because people
    annotate their OpenCode config, and silently deleting those annotations to add a tool
    is a poor trade.
    """
    rendered = json.dumps(entry, indent=2, ensure_ascii=False)
    body = "\n".join(f"{indent}{indent}{line}" for line in rendered.splitlines()).lstrip()

    mcp_span = _object_span_for_key(text, "mcp")
    if mcp_span is None:
        # No mcp block: add one just inside the top-level object.
        root_open = text.find("{")
        if root_open < 0:
            return None
        root_close = _match_brace(text, root_open)
        if root_close < 0:
            return None
        inner = text[root_open + 1 : root_close]
        block = f'\n{indent}"mcp": {{\n{indent}{indent}"{name}": {body}\n{indent}}}'
        separator = "," if inner.strip() else ""
        return text[: root_open + 1] + block + separator + text[root_open + 1 :]

    _, brace_open, brace_close = mcp_span
    existing = _object_span_for_key(text, name, object_open=brace_open)
    if existing is not None:
        entry_start, _, _ = existing
        entry_stop = _entry_end(text, entry_start)
        if entry_stop < 0:
            return None
        replacement = f'"{name}": {body}'
        return text[:entry_start] + replacement + text[entry_stop:]

    inner = text[brace_open + 1 : brace_close]
    if inner.strip():
        # Append after the last entry, adding the comma the previous entry now needs.
        tail = text[:brace_close].rstrip()
        if tail.endswith(","):
            insertion = f'\n{indent}{indent}"{name}": {body}\n{indent}'
            return tail + insertion + text[brace_close:]
        insertion = f',\n{indent}{indent}"{name}": {body}\n{indent}'
        return tail + insertion + text[brace_close:]
    insertion = f'\n{indent}{indent}"{name}": {body}\n{indent}'
    return text[: brace_open + 1] + insertion + text[brace_close:]



def register_with_opencode(
    config_path: Path,
    python: Path,
    source_root: Path,
    home: Path,
    ghidra_dir: Path,
    java_home: Path,
) -> None:
    out.step(f"Registering the MCP server in {config_path.name}")

    entry = {
        "type": "local",
        "command": [str(python), "-m", "ghidra_mcp.server"],
        "enabled": True,
        "timeout": 120000,
        "environment": {
            "PYTHONPATH": str(source_root),
            "GHIDRA_INSTALL_DIR": str(ghidra_dir),
            "JAVA_HOME": str(java_home),
            "GHIDRA_MCP_HOME": str(home),
            "PYTHONIOENCODING": "utf-8",
        },
    }

    config_path.parent.mkdir(parents=True, exist_ok=True)
    original = config_path.read_text(encoding="utf-8-sig") if config_path.exists() else ""

    if original.strip():
        backup = config_path.with_name(f"{config_path.name}.backup-{time.strftime('%Y%m%d-%H%M%S')}")
        backup.write_text(original, encoding="utf-8")
        out.ok(f"backup: {backup.name}")

    if not original.strip():
        data = {
            "$schema": "https://opencode.ai/config.json",
            "mcp": {MCP_SERVER_NAME: entry},
        }
        config_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        out.ok(f"created {config_path} with mcp.{MCP_SERVER_NAME}")
        return

    # Validate the file parses before editing it, so a broken config is reported rather
    # than silently mangled.
    try:
        parsed = json.loads(strip_jsonc(original))
        if not isinstance(parsed, dict):
            raise ValueError("the top level of the config is not an object")
    except Exception as exc:
        out.warn(f"could not parse the existing config ({exc}).")
        if not confirm("Replace it with a minimal config that registers this server?", default=False):
            out.warn("skipping registration; add the block from README.md by hand")
            return
        data = {"$schema": "https://opencode.ai/config.json", "mcp": {MCP_SERVER_NAME: entry}}
        config_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        out.ok(f"rewrote {config_path}")
        return

    if not isinstance(parsed.get("mcp", {}), dict):
        die("the 'mcp' key in the OpenCode config is not an object; fix it by hand and re-run")

    replaced = MCP_SERVER_NAME in (parsed.get("mcp") or {})
    others = [name for name in (parsed.get("mcp") or {}) if name != MCP_SERVER_NAME]

    # Preferred path: a surgical splice that keeps comments and formatting intact.
    edited = splice_mcp_entry(original, MCP_SERVER_NAME, entry)
    if edited is not None:
        try:
            check = json.loads(strip_jsonc(edited))
            if (check.get("mcp") or {}).get(MCP_SERVER_NAME) != entry:
                raise ValueError("the spliced entry did not read back correctly")
            for name in others:
                if name not in (check.get("mcp") or {}):
                    raise ValueError(f"the splice lost the '{name}' server")
        except Exception as exc:
            out.info(f"in-place edit rejected ({exc}); rewriting the file instead")
            edited = None

    if edited is not None:
        config_path.write_text(edited, encoding="utf-8")
        out.ok(("replaced" if replaced else "added") + f" mcp.{MCP_SERVER_NAME} in {config_path}")
        out.info("comments and formatting preserved")
    else:
        parsed.setdefault("$schema", "https://opencode.ai/config.json")
        parsed.setdefault("mcp", {})[MCP_SERVER_NAME] = entry
        config_path.write_text(json.dumps(parsed, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        out.ok(("replaced" if replaced else "added") + f" mcp.{MCP_SERVER_NAME} in {config_path}")
        if "//" in original or "/*" in original:
            out.warn("the file had comments; they were dropped when rewriting it (the backup keeps them)")

    if others:
        out.info(f"other MCP servers left untouched: {', '.join(others)}")


def _cursor_entry(python: Path, source_root: Path, home: Path, ghidra_dir: Path, java_home: Path) -> dict:
    """Build the Cursor-flavoured server entry.

    Cursor's schema splits the executable from its arguments: ``command`` is a single
    string, ``args`` the rest, and environment variables go under ``env``. There is no
    ``type: local`` and no single-list ``command`` like OpenCode uses.
    """
    return {
        "type": "stdio",
        "command": str(python),
        "args": ["-m", "ghidra_mcp.server"],
        "env": {
            "PYTHONPATH": str(source_root),
            "GHIDRA_INSTALL_DIR": str(ghidra_dir),
            "JAVA_HOME": str(java_home),
            "GHIDRA_MCP_HOME": str(home),
            "PYTHONIOENCODING": "utf-8",
        },
    }


def register_with_cursor(
    config_path: Path,
    python: Path,
    source_root: Path,
    home: Path,
    ghidra_dir: Path,
    java_home: Path,
) -> None:
    """Add ``mcpServers.ghidra`` to the global Cursor MCP config, preserving existing servers.

    This target is plain JSON (unlike OpenCode's JSONC), so a surgical splice is
    unnecessary: we parse, merge the one key, and write back. Switching the entry for an
    existing one and leaving unrelated servers untouched is the only sensible behaviour.
    """
    out.step(f"Registering the MCP server in {config_path}")
    entry = _cursor_entry(python, source_root, home, ghidra_dir, java_home)
    config_path = Path(config_path)

    config_path.parent.mkdir(parents=True, exist_ok=True)
    original = config_path.read_text(encoding="utf-8-sig") if config_path.exists() else ""

    if original.strip():
        backup = config_path.with_name(f"{config_path.name}.backup-{time.strftime('%Y%m%d-%H%M%S')}")
        backup.write_text(original, encoding="utf-8")
        out.ok(f"backup: {backup.name}")

    try:
        data = json.loads(original) if original.strip() else {}
    except Exception as exc:
        out.warn(f"could not parse the existing {config_path} ({exc}).")
        if not confirm("Rewrite it with just this server?", default=False):
            out.warn("skipping registration; add the block yourself")
            return
        data = {}

    if not isinstance(data, dict):
        out.warn(f"the file is not a JSON object; rewriting it with just this server")
        data = {}

    servers = data.get("mcpServers")
    if servers is None:
        servers = {}
        data["mcpServers"] = servers
    if not isinstance(servers, dict):
        die("the 'mcpServers' key in the Cursor config is not an object; fix it by hand")

    replaced = MCP_SERVER_NAME in servers
    others = [name for name in servers if name != MCP_SERVER_NAME]
    servers[MCP_SERVER_NAME] = entry

    config_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    out.ok(("replaced" if replaced else "added") + f" mcpServers.{MCP_SERVER_NAME} in {config_path}")
    if others:
        out.info(f"other MCP servers left untouched: {', '.join(others)}")


def unregister_from_cursor(config_path: Path) -> bool:
    """Remove ``mcpServers.ghidra`` from the global Cursor MCP config."""
    config_path = Path(config_path)
    if not config_path.exists():
        return False
    original = config_path.read_text(encoding="utf-8-sig")
    try:
        data = json.loads(original)
    except Exception:
        out.warn(f"could not parse {config_path}; remove the 'ghidra' entry by hand")
        return False
    servers = data.get("mcpServers")
    if not isinstance(servers, dict) or MCP_SERVER_NAME not in servers:
        return False

    backup = config_path.with_name(f"{config_path.name}.backup-{time.strftime('%Y%m%d-%H%M%S')}")
    backup.write_text(original, encoding="utf-8")

    del servers[MCP_SERVER_NAME]
    if not servers:
        data.pop("mcpServers", None)
    config_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out.ok(f"removed mcpServers.{MCP_SERVER_NAME} from {config_path} (backup: {backup.name})")
    return True


def excise_mcp_entry(text: str, name: str) -> str | None:
    """Remove ``mcp.<name>`` from JSONC text, preserving comments and formatting."""
    mcp_span = _object_span_for_key(text, "mcp")
    if mcp_span is None:
        return None
    _, brace_open, brace_close = mcp_span
    entry = _object_span_for_key(text, name, object_open=brace_open)
    if entry is None:
        return None
    entry_start, _, _ = entry
    entry_stop = _entry_end(text, entry_start)
    if entry_stop < 0:
        return None

    # Take the comma with the entry: the one after it if present, otherwise the one
    # before, so the remaining object stays valid JSON either way.
    cut_start, cut_end = entry_start, entry_stop
    trailing = text.find(",", entry_stop, brace_close)
    if trailing >= 0 and not text[entry_stop:trailing].strip():
        cut_end = trailing + 1
    else:
        preceding = text.rfind(",", brace_open, entry_start)
        if preceding >= 0 and not text[preceding + 1 : entry_start].strip():
            cut_start = preceding
    # Absorb the blank line the removal would otherwise leave behind.
    while cut_start > 0 and text[cut_start - 1] in " \t":
        cut_start -= 1
    if text[cut_start - 1 : cut_start] == "\n" and text[cut_end : cut_end + 1] == "\n":
        cut_end += 1
    return text[:cut_start] + text[cut_end:]


def unregister_from_opencode(config_path: Path) -> bool:
    if not config_path.exists():
        return False
    original = config_path.read_text(encoding="utf-8-sig")
    try:
        data = json.loads(strip_jsonc(original))
    except Exception:
        out.warn(f"could not parse {config_path}; remove the 'ghidra' block by hand")
        return False
    servers = data.get("mcp")
    if not isinstance(servers, dict) or MCP_SERVER_NAME not in servers:
        return False

    backup = config_path.with_name(f"{config_path.name}.backup-{time.strftime('%Y%m%d-%H%M%S')}")
    backup.write_text(original, encoding="utf-8")

    edited = excise_mcp_entry(original, MCP_SERVER_NAME)
    if edited is not None:
        try:
            check = json.loads(strip_jsonc(edited))
            if MCP_SERVER_NAME in (check.get("mcp") or {}):
                raise ValueError("the entry is still present")
            for other in servers:
                if other != MCP_SERVER_NAME and other not in (check.get("mcp") or {}):
                    raise ValueError(f"the edit lost the '{other}' server")
        except Exception:
            edited = None

    if edited is not None:
        config_path.write_text(edited, encoding="utf-8")
    else:
        servers.pop(MCP_SERVER_NAME)
        if not servers:
            data.pop("mcp")
        config_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    out.ok(f"removed mcp.{MCP_SERVER_NAME} from {config_path} (backup: {backup.name})")
    return True



# --------------------------------------------------------------------------
# verification
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# external tools: Wireshark (tshark/dumpcap CLI)
# --------------------------------------------------------------------------
WIRESHARK_DIRS = (Path(r"C:\Program Files\Wireshark"), Path(r"C:\Program Files (x86)\Wireshark"))


def wireshark_installed() -> bool:
    return any((directory / "tshark.exe").is_file() for directory in WIRESHARK_DIRS)


def install_wireshark(offline: bool = False) -> bool:
    """Install Wireshark via winget so the ws_* tools have their CLI (optional)."""
    out.step("Installing Wireshark CLI tools (optional, for packet analysis)")
    if wireshark_installed():
        out.ok("already present: tshark.exe")
        return True
    if offline:
        out.info("offline mode: skipping Wireshark")
        return True
    winget = shutil.which("winget")
    if winget is None:
        out.warn("winget not found; install Wireshark from wireshark.org for the ws_* tools")
        return False
    try:
        result = subprocess.run(
            [winget, "install", "--id", "WiresharkFoundation.Wireshark", "--silent",
             "--accept-package-agreements", "--accept-source-agreements"],
            capture_output=True, text=True, errors="replace", timeout=1200, stdin=subprocess.DEVNULL,
        )
        if wireshark_installed():
            out.ok("Wireshark installed (tshark, dumpcap)")
            return True
        out.warn(f"winget exited {result.returncode} and tshark is not present; the ws_* tools will say what to do")
        return False
    except Exception as exc:
        out.warn(f"could not install Wireshark ({exc}); ws_* tools report the install command")
        return True


# --------------------------------------------------------------------------
# MCP client registration: Claude Code and Codex
# --------------------------------------------------------------------------
def claude_config_path() -> Path:
    return Path(os.environ.get("USERPROFILE", str(Path.home()))) / ".claude.json"


def _claude_entry(python: Path, source_root: Path, home: Path, ghidra_dir: Path, java_home: Path) -> dict:
    # Claude Code user-scope servers: ~/.claude.json -> {"mcpServers": {name: {...}}}
    return {
        "type": "stdio",
        "command": str(python),
        "args": ["-m", "ghidra_mcp.server"],
        "env": {
            "PYTHONPATH": str(source_root),
            "GHIDRA_INSTALL_DIR": str(ghidra_dir),
            "JAVA_HOME": str(java_home),
            "GHIDRA_MCP_HOME": str(home),
            "PYTHONIOENCODING": "utf-8",
        },
    }


def register_with_claude_code(python: Path, source_root: Path, home: Path,
                              ghidra_dir: Path, java_home: Path, config_path: Path | None = None) -> bool:
    """Add mcpServers.ghidra to ~/.claude.json, preserving everything else."""
    out.step("Registering the MCP server in Claude Code")
    path = config_path or claude_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    original = path.read_text(encoding="utf-8-sig") if path.is_file() else ""
    try:
        data = json.loads(original) if original.strip() else {}
    except Exception as exc:
        out.warn(f"could not parse {path} ({exc}); leave Claude Code untouched")
        return False
    if not isinstance(data, dict):
        out.warn(f"{path} is not a JSON object; leaving it untouched")
        return False
    if original.strip():
        backup = path.with_name(f"{path.name}.backup-{time.strftime('%Y%m%d-%H%M%S')}")
        backup.write_text(original, encoding="utf-8")
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
        data["mcpServers"] = servers
    servers[MCP_SERVER_NAME] = _claude_entry(python, source_root, home, ghidra_dir, java_home)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out.ok(f"mcpServers.{MCP_SERVER_NAME} in {path}")
    return True


def unregister_from_claude(config_path: Path | None = None) -> bool:
    path = config_path or claude_config_path()
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return False
    servers = data.get("mcpServers")
    if not isinstance(servers, dict) or MCP_SERVER_NAME not in servers:
        return False
    backup = path.with_name(f"{path.name}.backup-{time.strftime('%Y%m%d-%H%M%S')}")
    backup.write_text(path.read_text(encoding="utf-8-sig"), encoding="utf-8")
    del servers[MCP_SERVER_NAME]
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True


def codex_config_path() -> Path:
    return Path(os.environ.get("USERPROFILE", str(Path.home()))) / ".codex" / "config.toml"


def _toml_string(value: str) -> str:
    return json.dumps(value)


def _codex_block(python: Path, source_root: Path, home: Path, ghidra_dir: Path, java_home: Path) -> str:
    env = {
        "PYTHONPATH": str(source_root),
        "GHIDRA_INSTALL_DIR": str(ghidra_dir),
        "JAVA_HOME": str(java_home),
        "GHIDRA_MCP_HOME": str(home),
        "PYTHONIOENCODING": "utf-8",
    }
    args = ", ".join(_toml_string(a) for a in ["-m", "ghidra_mcp.server"])
    lines = [
        f"[mcp_servers.{MCP_SERVER_NAME}]",
        f"command = {_toml_string(str(python))}",
        f"args = [{args}]",
        f"[mcp_servers.{MCP_SERVER_NAME}.env]",
    ]
    lines += [f"{name} = {_toml_string(value)}" for name, value in env.items()]
    return "\n".join(lines) + "\n"


def register_with_codex(python: Path, source_root: Path, home: Path,
                        ghidra_dir: Path, java_home: Path, config_path: Path | None = None) -> bool:
    """Write the [mcp_servers.ghidra] block into ~/.codex/config.toml, keeping the rest.

    Codex config is TOML; the project keeps no TOML writer, so the block is
    located by header line and replaced, or appended - a surgical edit on plain text.
    """
    out.step("Registering the MCP server in Codex")
    path = config_path or codex_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    original = path.read_text(encoding="utf-8-sig") if path.is_file() else ""
    if original.strip():
        backup = path.with_name(f"{path.name}.backup-{time.strftime('%Y%m%d-%H%M%S')}")
        backup.write_text(original, encoding="utf-8")
    block = _codex_block(python, source_root, home, ghidra_dir, java_home)
    header = f"[mcp_servers.{MCP_SERVER_NAME}]"
    lines = original.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == header)
    except StopIteration:
        start = None
    if start is None:
        text = original
        if text and not text.endswith("\n"):
            text += "\n"
        if text.strip():
            text += "\n"
        path.write_text(text + block, encoding="utf-8")
        out.ok(f"appended {header} to {path}")
        return True
    # cut from the header to the next top-level table (line starting '[' at column 0)
    end = start + 1
    while end < len(lines) and not lines[end].startswith("["):
        end += 1
    # drop the .env subtable too
    if end < len(lines) and lines[end].strip() == f"[mcp_servers.{MCP_SERVER_NAME}.env]":
        end += 1
        while end < len(lines) and not lines[end].startswith("["):
            end += 1
    merged = lines[:start] + block.rstrip().splitlines() + lines[end:]
    path.write_text("\n".join(merged) + "\n", encoding="utf-8")
    out.ok(f"replaced {header} in {path}")
    return True


def unregister_from_codex(config_path: Path | None = None) -> bool:
    path = config_path or codex_config_path()
    if not path.is_file():
        return False
    original = path.read_text(encoding="utf-8-sig")
    lines = original.splitlines()
    header = f"[mcp_servers.{MCP_SERVER_NAME}]"
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == header)
    except StopIteration:
        return False
    end = start + 1
    while end < len(lines) and not lines[end].startswith("["):
        end += 1
    if end < len(lines) and lines[end].strip() == f"[mcp_servers.{MCP_SERVER_NAME}.env]":
        end += 1
        while end < len(lines) and not lines[end].startswith("["):
            end += 1
    backup = path.with_name(f"{path.name}.backup-{time.strftime('%Y%m%d-%H%M%S')}")
    backup.write_text(original, encoding="utf-8")
    path.write_text("\n".join(lines[:start] + lines[end:]).rstrip() + "\n", encoding="utf-8")
    return True


def detect_clients() -> dict[str, bool]:
    """Which AI clients exist on this machine, decided by binary on PATH or config dir."""
    home = Path(os.environ.get("USERPROFILE", str(Path.home())))
    return {
        "opencode": bool(shutil.which("opencode")) or (home / ".config" / "opencode").is_dir(),
        "cursor": bool(shutil.which("cursor")) or (home / ".cursor").is_dir(),
        "claude": bool(shutil.which("claude")) or claude_config_path().is_file(),
        "codex": bool(shutil.which("codex")) or (home / ".codex").is_dir(),
    }


def smoke_test(python: Path, source_root: Path, home: Path, ghidra_dir: Path, java_home: Path) -> bool:
    """Start the server over real MCP stdio and call its doctor tool.

    This is the only step that proves the install actually works: it exercises the
    transport, the tool registry, the worker subprocess, and the JVM.
    """
    out.step("Verifying the installation (starting the server and the JVM)")
    out.info("this takes 20-60 seconds the first time, while Ghidra initialises")

    script = r'''
import asyncio, json, os, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    env = os.environ.copy()
    params = StdioServerParameters(command=sys.executable, args=["-m", "ghidra_mcp.server"], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            result = await session.call_tool("doctor", {})
            report = json.loads(result.content[0].text)
            print(json.dumps({
                "tool_count": len(tools.tools),
                "verdict": report.get("verdict"),
                "problems": report.get("problems"),
                "ghidra": (report.get("worker_ready") or {}).get("ghidra"),
                "startup_seconds": (report.get("worker_ready") or {}).get("startup_seconds"),
                "operations": (report.get("worker_ready") or {}).get("operations"),
                "worker_error": report.get("worker_error"),
                "worker_log_tail": (report.get("worker_log_tail") or "")[-700:],
                "libraries": {k: v.get("available") for k, v in (report.get("python_libraries") or {}).items()},
            }))

asyncio.run(main())
'''
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": str(source_root),
            "GHIDRA_INSTALL_DIR": str(ghidra_dir),
            "JAVA_HOME": str(java_home),
            "GHIDRA_MCP_HOME": str(home),
            "PYTHONIOENCODING": "utf-8",
        }
    )
    result = subprocess.run(
        [str(python), "-c", script],
        capture_output=True,
        text=True,
        env=environment,
        timeout=600,
    )
    if result.returncode != 0:
        out.fail("the server could not be started")
        for line in (result.stderr or result.stdout).strip().splitlines()[-15:]:
            print(f"      {line}")
        return False

    try:
        report = json.loads(result.stdout.strip().splitlines()[-1])
    except Exception:
        out.fail("the verification output could not be parsed")
        print(f"      {result.stdout[-600:]}")
        return False

    out.ok(f"{report['tool_count']} tools registered")
    missing = [name for name, available in (report.get("libraries") or {}).items() if not available]
    if missing:
        out.warn(f"optional libraries missing: {', '.join(missing)} (related tools will be unavailable)")

    if report.get("verdict") == "ready":
        out.ok(f"Ghidra {report.get('ghidra')} started in {report.get('startup_seconds')}s")
        out.ok(f"{report.get('operations')} Ghidra operations available")
        return True

    out.fail(f"the server started but is not ready: {report.get('problems') or report.get('worker_error')}")
    if report.get("worker_log_tail"):
        print("      --- worker log ---")
        for line in str(report["worker_log_tail"]).strip().splitlines()[-10:]:
            print(f"      {line}")
    return False


# --------------------------------------------------------------------------
# x64dbg automation plugin
# --------------------------------------------------------------------------
X64DBG_PLUGIN_REPO = "https://api.github.com/repos/dariushoule/x64dbg-automate/releases/latest"
# Each release ships one zip per bitness; the 64-bit zip also carries the dp32 plugin,
# so installing release64 alone covers both debugger flavours.
X64DBG_PLUGIN_FILES_64 = ("x64dbg-automate.dp64", "libzmq-mt-4_3_5.dll")
X64DBG_PLUGIN_FILES_32 = ("x64dbg-automate.dp32", "libzmq-mt-4_3_5.dll")


def find_x64dbg_root() -> Path | None:
    """Locate the unpacked x64dbg 'release' folder, mirroring the server's search."""
    candidates = []
    override = os.environ.get("X64DBG_DIR")
    if override:
        candidates.append(Path(override))
    candidates += [
        Path("C:/x64dbg/release"),
        Path("C:/Program Files/x64dbg/release"),
        Path("C:/Program Files (x86)/x64dbg/release"),
        Path("D:/x64dbg/release"),
        Path("E:/x64dbg/release"),
    ]
    for candidate in candidates:
        if (candidate / "x96dbg.exe").is_file() or (candidate / "x64dbg.exe").is_file():
            return candidate
    return None


def install_x64dbg_plugin() -> bool:
    """Drop x64dbg-automate.dp64 into the debugger's plugins folder.

    The dynamic-analysis tools drive x64dbg through this plugin's ZMQ server. Without
    it, xdbg_start fails; the installer fetching it from GitHub releases spares the
    user a manual download. Failure is a warning, never a hard error - x64dbg itself is
    optional to this MCP.
    """
    out.step("Installing the x64dbg automation plugin (optional, for dynamic analysis)")
    root = find_x64dbg_root()
    if root is None:
        out.info("x64dbg not found; skipping (set X64DBG_DIR and re-run to enable)")
        return True

    plugins_dir_64 = root / "x64" / "plugins"
    plugins_dir_32 = root / "x32" / "plugins"
    marker = plugins_dir_64 / "x64dbg-automate.dp64"
    if marker.is_file():
        out.ok(f"already present: {marker}")
        return True

    try:
        import json
        import urllib.request
        import zipfile

        out.info("querying GitHub for the latest release")
        with urllib.request.urlopen(X64DBG_PLUGIN_REPO, timeout=30) as response:
            release = json.loads(response.read().decode("utf-8"))

        plugins_dir_64.mkdir(parents=True, exist_ok=True)
        plugins_dir_32.mkdir(parents=True, exist_ok=True)
        for asset_name_fragment, plugin_files, plugins_dir in (
            ("release64", X64DBG_PLUGIN_FILES_64, plugins_dir_64),
            ("release32", X64DBG_PLUGIN_FILES_32, plugins_dir_32),
        ):
            asset = next((a for a in release.get("assets", []) if asset_name_fragment in a["name"]), None)
            if asset is None:
                out.warn(f"no {asset_name_fragment} asset in {release.get('tag_name')}; install manually")
                continue
            archive = root.parent / f"x64dbg-automate-{asset_name_fragment}.zip"
            out.info(f"downloading {asset['name']}")
            urllib.request.urlretrieve(asset["browser_download_url"], archive)
            with zipfile.ZipFile(archive) as bundle:
                members = [name for name in bundle.namelist() if Path(name).name in plugin_files]
                if not members:
                    out.warn(f"{asset['name']} holds none of {plugin_files}; unexpected layout")
                    continue
                for name in members:
                    target = plugins_dir / Path(name).name
                    target.write_bytes(bundle.read(name))
                    out.ok(f"{target.name} -> {plugins_dir}")
            archive.unlink(missing_ok=True)
        out.ok("x64dbg-automate plugin installed (x64 and x32)")
        return True
    except Exception as exc:
        out.warn(f"could not install the plugin ({exc}); x64dbg tools will say how to fix it")
        out.info("manual: download release64/release32 zips from github.com/dariushoule/x64dbg-automate")
        out.info(f"        dp64 -> {plugins_dir_64}, dp32 -> {plugins_dir_32} (plus libzmq-mt-4_3_5.dll)")
        return True


SCYLLAHIDE_RELEASE = "https://github.com/x64dbg/ScyllaHide/releases/download/v1.4/ScyllaHide_2023-03-24_13-03.zip"


def install_scyllahide() -> bool:
    """Drop ScyllaHide into the debugger's plugin folders.

    Usermode anti-anti-debug: hides PEB flags, hooks NtQueryInformationProcess and
    friends inside the debuggee. Needs no kernel driver, so it works regardless of
    Secure Boot - the practical alternative to TitanHide on client machines.
    """
    out.step("Installing ScyllaHide anti-anti-debug (usermode, no driver needed)")
    root = find_x64dbg_root()
    if root is None:
        out.info("x64dbg not found; skipping")
        return True
    marker = root / "x64" / "plugins" / "ScyllaHideX64DBGPlugin.dp64"
    if marker.is_file():
        out.ok(f"already present: {marker}")
        return True
    try:
        import tempfile
        import urllib.request
        import zipfile

        archive = Path(tempfile.gettempdir()) / "scyllahide.zip"
        out.info("downloading ScyllaHide v1.4")
        urllib.request.urlretrieve(SCYLLAHIDE_RELEASE, archive)
        extract_root = Path(tempfile.gettempdir()) / "scyllahide_extract"
        if extract_root.exists():
            shutil.rmtree(extract_root, ignore_errors=True)
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(extract_root)
        copied = 0
        for bitness, plugin in (("x64", "ScyllaHideX64DBGPlugin.dp64"), ("x32", "ScyllaHideX64DBGPlugin.dp32")):
            source_dir = extract_root / "x64dbg" / bitness / "plugins"
            target_dir = root / bitness / "plugins"
            if not source_dir.is_dir():
                continue
            target_dir.mkdir(parents=True, exist_ok=True)
            for item in source_dir.iterdir():
                shutil.copy2(item, target_dir / item.name)
                copied += 1
        archive.unlink(missing_ok=True)
        shutil.rmtree(extract_root, ignore_errors=True)
        if copied:
            out.ok(f"ScyllaHide installed ({copied} files into x64\\plugins and x32\\plugins)")
        else:
            out.warn("the archive layout was unexpected; nothing copied")
        return True
    except Exception as exc:
        out.warn(f"could not install ScyllaHide ({exc}); x64dbg works without it")
        return True


def install_nuclei(offline: bool = False) -> bool:
    """Fetch the Nuclei scanner + its template repo (optional, for vuln scanning)."""
    out.step("Installing Nuclei vulnerability scanner (optional)")
    destination = Path(r"C:\Tools\nuclei")
    marker = destination / "nuclei.exe"
    if not offline and not marker.is_file():
        try:
            import json
            import tempfile
            import urllib.request
            import zipfile

            out.info("querying GitHub for the latest nuclei release")
            with urllib.request.urlopen("https://api.github.com/repos/projectdiscovery/nuclei/releases/latest", timeout=30) as response:
                release = json.loads(response.read().decode("utf-8"))
            version = release["tag_name"].lstrip("v")
            asset = next((a for a in release["assets"] if a["name"] == f"nuclei_{version}_windows_amd64.zip"), None)
            if asset is None:
                out.warn("no windows amd64 asset in the latest release; install manually")
                return False
            destination.mkdir(parents=True, exist_ok=True)
            archive = Path(tempfile.gettempdir()) / "nuclei.zip"
            out.info(f"downloading nuclei {release['tag_name']}")
            urllib.request.urlretrieve(asset["browser_download_url"], archive)
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(destination)
            archive.unlink(missing_ok=True)
            out.ok(f"nuclei {release['tag_name']} -> {destination}")
        except Exception as exc:
            out.warn(f"could not install nuclei ({exc}); the nuclei tools will say how")
            return False
    elif marker.is_file():
        out.ok(f"already present: {marker}")

    # templates: ~13k YAML files, needed before scanning; skip in offline mode
    if offline or not marker.is_file():
        return True
    templates_marker = Path(os.environ.get("USERPROFILE", "")) / "nuclei-templates"
    if templates_marker.is_dir() and any(templates_marker.rglob("*.yaml")):
        out.ok(f"templates already present: {templates_marker}")
        return True
    try:
        out.info("cloning the nuclei-templates repo (~250MB, may take a minute)")
        subprocess.run(
            [str(marker), "-update-templates", "-duc", "-no-color", "-silent"],
            capture_output=True, timeout=900,
        )
        count = sum(1 for _ in templates_marker.rglob("*.yaml"))
        out.ok(f"{count} templates in {templates_marker}")
        return True
    except Exception as exc:
        out.warn(f"template clone failed ({exc}); run: {marker} -update-templates")
        return True


PROGRESS: "Callable[[str, float], None] | None" = None


def _tick(stage: str, fraction: float) -> None:
    if PROGRESS is not None:
        try:
            PROGRESS(stage, max(0.0, min(1.0, fraction)))
        except Exception:
            pass


def do_install(arguments: argparse.Namespace) -> int:
    print("=" * 72)
    print("  Ghidra MCP server - installer")
    print("=" * 72)

    config = load_config_module()
    check_python()

    home = Path(arguments.home).expanduser() if arguments.home else config.default_home()
    check_install_path(home)
    out.info(f"install location: {home}")
    _tick("checking the environment", 0.04)

    ghidra_dir = find_ghidra(config, arguments.ghidra)
    java_home = find_java(config, arguments.java, ghidra_dir)
    _tick("Ghidra + JDK located", 0.1)

    python = build_venv(home, recreate=arguments.recreate_venv)
    _tick("virtualenv ready", 0.18)
    install_dependencies(python, offline=arguments.offline)
    _tick("python dependencies installed", 0.45)
    source_root = copy_sources(home)
    _tick("sources copied", 0.5)
    write_config(home, ghidra_dir, java_home, arguments.heap)
    _tick("config written", 0.54)
    install_x64dbg_plugin()
    _tick("x64dbg plugin step done", 0.6)
    install_scyllahide()
    _tick("ScyllaHide step done", 0.64)
    install_nuclei(offline=arguments.offline)
    _tick("nuclei step done", 0.7)
    install_wireshark(offline=arguments.offline)
    _tick("wireshark step done", 0.74)

    if arguments.skip_verify:
        out.warn("skipping verification at your request")
        verified = True
    else:
        verified = smoke_test(python, source_root, home, ghidra_dir, java_home)
        _tick("verification done", 0.84)
        if not verified and not arguments.force:
            print()
            out.fail("Verification failed, so the server was NOT registered in OpenCode.")
            out.info("Fix the problem above and re-run, or pass --force to register anyway.")
            return 2

    clients = detect_clients()
    register_flags = {
        "opencode": True,
        "cursor": bool(arguments.cursor or arguments.all_clients),
        "claude": bool(arguments.claude or arguments.all_clients),
        "codex": bool(arguments.codex or arguments.all_clients),
    }
    if arguments.all_clients:
        _tick(f"clients detected: {', '.join(n for n, yes in clients.items() if yes) or 'opencode only'}", 0.86)

    config_path = opencode_config_path(arguments.opencode_config)
    register_with_opencode(config_path, python, source_root, home, ghidra_dir, java_home)
    _tick("opencode registered", 0.9)

    if register_flags["cursor"]:
        if clients["cursor"]:
            cursor_path = cursor_config_path(arguments.cursor_config)
            register_with_cursor(cursor_path, python, source_root, home, ghidra_dir, java_home)
        else:
            out.warn("no Cursor install detected; skipping Cursor registration")
    _tick("cursor step done", 0.93)

    if register_flags["claude"]:
        if clients["claude"]:
            register_with_claude_code(python, source_root, home, ghidra_dir, java_home)
        else:
            out.warn("no Claude Code detected; skipping registration")
    if register_flags["codex"]:
        if clients["codex"]:
            register_with_codex(python, source_root, home, ghidra_dir, java_home)
        else:
            out.warn("no Codex detected; skipping registration")
    _tick("registrations done", 0.98)

    print()
    print("=" * 72)
    print("  Installed" + ("" if verified else " (with warnings)"))
    print("=" * 72)
    print(f"  Ghidra          {ghidra_dir}")
    print(f"  Java            {java_home}")
    print(f"  Install home    {home}")
    print(f"  Projects        {home / 'projects'}")
    print(f"  OpenCode config {config_path}")
    if register_flags["cursor"] and clients["cursor"]:
        print(f"  Cursor config   {cursor_config_path(arguments.cursor_config)}")
    if register_flags["claude"]:
        print(f"  Claude Code     {claude_config_path()}")
    if register_flags["codex"]:
        print(f"  Codex config    {codex_config_path()}")
    print()
    print("  Restart OpenCode, then try:")
    print('    "run doctor from the ghidra mcp"')
    print(r'    "analyse C:\Windows\System32\where.exe and show me its entry point"')
    print()
    print("  Uninstall with: uninstall.bat")
    _tick("done", 1.0)
    return 0 if verified else 1


def do_check(arguments: argparse.Namespace) -> int:
    print("=" * 72)
    print("  Ghidra MCP server - environment check (nothing will be installed)")
    print("=" * 72)

    config = load_config_module()
    check_python()

    home = Path(arguments.home).expanduser() if arguments.home else config.default_home()
    ghidra_dir = Path(arguments.ghidra) if arguments.ghidra else config.probe_ghidra()
    if ghidra_dir and config.is_ghidra_dir(ghidra_dir):
        out.ok(f"Ghidra: {ghidra_dir} (version {config.ghidra_version(ghidra_dir) or 'unknown'})")
    else:
        out.fail("Ghidra not found")
        ghidra_dir = None

    java_home = config.probe_java(min_version=MIN_JAVA, ghidra_dir=ghidra_dir)
    if java_home:
        out.ok(f"Java: {java_home} (version {config.java_version_of(java_home)})")
    else:
        out.fail(f"no JDK {MIN_JAVA}+ with a JVM shared library found")

    venv_python = home / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if venv_python.exists():
        out.ok(f"environment present: {venv_python}")
    else:
        out.info(f"not installed yet (no environment at {home / 'venv'})")

    config_path = opencode_config_path(arguments.opencode_config)
    if config_path.exists():
        try:
            data = json.loads(strip_jsonc(config_path.read_text(encoding="utf-8-sig")))
            registered = MCP_SERVER_NAME in (data.get("mcp") or {})
            out.ok(f"OpenCode config: {config_path} (ghidra registered: {registered})")
        except Exception as exc:
            out.warn(f"OpenCode config at {config_path} could not be parsed: {exc}")
    else:
        out.info(f"no OpenCode config yet; one will be created at {config_path}")

    cursor_path = cursor_config_path(arguments.cursor_config)
    if cursor_path.exists():
        try:
            data = json.loads(cursor_path.read_text(encoding="utf-8-sig"))
            registered = MCP_SERVER_NAME in (data.get("mcpServers") or {})
            out.ok(f"Cursor config: {cursor_path} (ghidra registered: {registered})")
        except Exception as exc:
            out.warn(f"Cursor config at {cursor_path} could not be parsed: {exc}")
    else:
        out.info(f"no Cursor config yet; one will be created at {cursor_path} with --cursor")

    ready = bool(ghidra_dir and java_home)
    print()
    print("  Ready to install." if ready else "  Missing prerequisites, see above.")
    return 0 if ready else 1


def do_uninstall(arguments: argparse.Namespace) -> int:
    print("=" * 72)
    print("  Ghidra MCP server - uninstaller")
    print("=" * 72)

    config = load_config_module()
    home = Path(arguments.home).expanduser() if arguments.home else config.default_home()

    out.step("Removing the OpenCode registration")
    if not unregister_from_opencode(opencode_config_path(arguments.opencode_config)):
        out.info("nothing was registered")

    if arguments.cursor:
        out.step("Removing the Cursor registration")
        if not unregister_from_cursor(cursor_config_path(arguments.cursor_config)):
            out.info("nothing was registered")

    out.step("Removing the Claude Code / Codex registrations if present")
    if unregister_from_claude():
        out.ok("removed mcpServers.ghidra from Claude Code")
    if unregister_from_codex():
        out.ok(f"removed [mcp_servers.ghidra] from Codex")
    if not (claude_config_path().is_file() or codex_config_path().is_file()):
        out.info("neither Claude Code nor Codex configs are on this machine")

    out.step("Removing the installation")
    if not home.exists():
        out.info(f"{home} does not exist")
        return 0

    projects = home / "projects"
    keep_projects = False
    if projects.exists() and any(projects.iterdir()):
        out.warn(f"{projects} holds your Ghidra projects: analysis, renames, and comments.")
        keep_projects = not confirm("Delete the analysis projects as well?", default=False)

    if keep_projects:
        for child in home.iterdir():
            if child.name in ("projects", "notes.json"):
                continue
            shutil.rmtree(child, ignore_errors=True) if child.is_dir() else child.unlink(missing_ok=True)
        out.ok(f"removed the environment and sources; kept {projects} and notes.json")
    else:
        shutil.rmtree(home, ignore_errors=True)
        out.ok(f"removed {home}")

    print()
    print("  Uninstalled. Restart OpenCode to drop the tools from the session.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Install the Ghidra MCP server for OpenCode.")
    parser.add_argument("--check", action="store_true", help="report on the environment without installing")
    parser.add_argument("--uninstall", action="store_true", help="remove the installation and the OpenCode entry")
    parser.add_argument("--ghidra", help="path to the Ghidra installation")
    parser.add_argument("--java", help="path to a JDK 21+ home")
    parser.add_argument("--home", help="install location (default: %%LOCALAPPDATA%%\\GhidraMCP)")
    parser.add_argument("--opencode-config", help="path to opencode.json / opencode.jsonc")
    parser.add_argument("--cursor", action="store_true", help="also register the server in the global Cursor ~/.cursor/mcp.json")
    parser.add_argument("--cursor-config", help="path to a Cursor mcp.json (default: ~/.cursor/mcp.json)")
    parser.add_argument("--claude", action="store_true", help="also register in Claude Code (~/.claude.json)")
    parser.add_argument("--codex", action="store_true", help="also register in Codex (~/.codex/config.toml)")
    parser.add_argument("--all-clients", action="store_true", help="register in every AI client detected on this machine (opencode, cursor, claude code, codex)")
    parser.add_argument("--heap", default="4G", help="JVM maximum heap for analysis (default 4G)")
    parser.add_argument("--recreate-venv", action="store_true", help="rebuild the virtual environment from scratch")
    parser.add_argument("--offline", action="store_true", help="do not install packages")
    parser.add_argument("--skip-verify", action="store_true", help="do not start the server to verify")
    parser.add_argument("--force", action="store_true", help="register in OpenCode even if verification fails")
    arguments = parser.parse_args()

    try:
        if arguments.uninstall:
            return do_uninstall(arguments)
        if arguments.check:
            return do_check(arguments)
        return do_install(arguments)
    except KeyboardInterrupt:
        print("\n\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
