"""Build the CTPAX single-file installer exe.

Packs the whole project into CTPAX-project.zip, embeds it in a PyInstaller one-file
build of ctpax_setup.py, and prints the result path:

    python build_release.py        -> dist\\CTPAX-Setup.exe

Then publish it as a GitHub release asset (the release tag is what version_check
compares against):

    git tag v1.0.1 && git push origin v1.0.1
    gh release create v1.0.1 dist/CTPAX-Setup.exe --title "CTPAX v1.0.1" --notes "..."

The exe needs no Python on the target machine: PyInstaller bundles the interpreter,
and the project zip inside it makes the installer self-contained.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"
DIST = ROOT / "dist"
PAYLOAD = BUILD / "CTPAX-project.zip"
EXCLUDE_DIRS = {".git", "__pycache__", "build", "dist", "node_modules", ".idea", "CTPAX"}
EXCLUDE_SUFFIX = {".pyc", ".pyo"}


def pack_payload() -> Path:
    BUILD.mkdir(exist_ok=True)
    PAYLOAD.unlink(missing_ok=True)
    count = 0
    with zipfile.ZipFile(PAYLOAD, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file() or path.suffix in EXCLUDE_SUFFIX:
                continue
            relative = path.relative_to(ROOT)
            if EXCLUDE_DIRS.intersection(relative.parts):
                continue
            archive.write(path, relative.as_posix())
            count += 1
    print(f"payload: {count} files -> {PAYLOAD} ({PAYLOAD.stat().st_size // 1024} KB)")
    return PAYLOAD


def ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401

        return
    except ImportError:
        pass
    print("installing PyInstaller into the current interpreter ...")
    subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "pyinstaller"], check=True)


def _runtime_imports() -> list[str]:
    """Top-level package names that install.py (and its config helper) import.

    install.py is loaded at runtime by the frozen exe, so PyInstaller cannot see its
    imports: without this list the exe starts, extracts the payload and then dies on
    ``ModuleNotFoundError: No module named 'json'``.
    """
    import ast

    packages: set[str] = set()
    sources = [ROOT / "install.py", ROOT / "ctpax_setup.py", ROOT / "src" / "ghidra_mcp" / "config.py"]
    for source in sources:
        if not source.is_file():
            continue
        tree = ast.parse(source.read_text(encoding="utf-8-sig"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    packages.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                packages.add(node.module.split(".")[0])
    # ghidra_mcp is a local package shipped in the payload; everything else must be bundled
    return sorted(name for name in packages if name != "ghidra_mcp")


def build() -> Path:
    ensure_pyinstaller()
    pack_payload()
    hidden = _runtime_imports()
    print(f"bundling runtime imports: {', '.join(hidden)}")
    command = [
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--noconfirm", "--clean",
        "--name", "CTPAX-Setup",
        "--add-data", f"{PAYLOAD}{';' if sys.platform == 'win32' else ':'}.",
        *[f"--hidden-import={name}" for name in hidden],
        str(ROOT / "ctpax_setup.py"),
    ]
    print("building with PyInstaller (one file, this takes a minute) ...")
    subprocess.run(command, check=True, cwd=ROOT)
    exe = DIST / "CTPAX-Setup.exe"
    if not exe.is_file():
        raise SystemExit("PyInstaller finished but dist/CTPAX-Setup.exe is missing")
    print(f"\nOK: {exe}  ({exe.stat().st_size / 1024 / 1024:.1f} MB)")
    return exe


if __name__ == "__main__":
    build()
