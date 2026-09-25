"""MCP tools wrapping the managed third-party tools: Binary Ninja headless,
dnSpy/dotPeek GUI launches, and MegaDumper process dumping."""

from __future__ import annotations

from ghidra_mcp import managed
from ghidra_mcp.runtime import fail, mcp, render


@mcp.tool()
def managed_status() -> str:
    """Availability report for every managed third-party tool (for doctor-style checks).

    Binary Ninja, ilspycmd, dnSpy, dotPeek, MegaDumper, Frida and the decompiler
    engines: which are ready now, and what installs/downloads happen on first use.
    """
    try:
        return render(managed.managed_status())
    except Exception as exc:
        return fail(exc)


# --------------------------------------------------------------------------
# Binary Ninja
# --------------------------------------------------------------------------
@mcp.tool()
def binaryninja_status() -> str:
    """Is the Binary Ninja headless Python API reachable, and from where?

    Detects the ''binaryninja'' module (BN installs add it automatically) or the
    install folder either directly or via BN_INSTALL_DIR. It is NOT installed by
    CTPAX: Binary Ninja is a commercial product.
    """
    try:
        return render(managed.binaryninja_status())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def binaryninja_open(path: str, analyze: bool = True, close_others: bool = False) -> str:
    """Open a file in headless Binary Ninja; the view is kept for later calls.

    Only one analysis at a time is practical; pass close_others to drop prior views.
    Returns architecture/platform/base/entry and function/string counts.
    """
    try:
        return render(managed.binaryninja_open(path, analyze=analyze, close_others=close_others))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def binaryninja_info(path: str | None = None) -> str:
    """Sections, functions preview, and strings for the open (or named) BN view.

    Use binaryninja_decompile at a specific address for full pseudo-source.
    """
    try:
        return render(managed.binaryninja_info(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def binaryninja_functions(path: str | None = None, filter: str | None = None, limit: int = 100) -> str:
    """List functions in the open BN view (name/address/size), optional name filter."""
    try:
        return render(managed.binaryninja_functions(path, filter=filter, limit=limit))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def binaryninja_decompile(address: str, path: str | None = None, level: str = "hlil") -> str:
    """Decompile a function to Binary Ninja pseudo-source (hlil/mlil/llil).

    High-Level IL is the Decompiler's text view - call that by default. The lower IL
    levels (``mlil``/``llil``) show the progressively less abstracted IR.
    """
    try:
        return render(managed.binaryninja_decompile(address, path, level=level))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def binaryninja_disassemble(address: str, path: str | None = None, count: int = 40) -> str:
    """Linear disassembly from an address in the open BN view (LLIL text lines)."""
    try:
        return render(managed.binaryninja_disassemble(address, path, count=count))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def binaryninja_strings(path: str | None = None, limit: int = 100, filter: str | None = None) -> str:
    """Strings in the open BN view with addresses; optional substring filter."""
    try:
        return render(managed.binaryninja_strings(path, limit=limit, filter=filter))
    except Exception as exc:
        return fail(exc)


# --------------------------------------------------------------------------
# .NET: ILSpy (headless), dnSpy and dotPeek (GUI)
# --------------------------------------------------------------------------
@mcp.tool()
def dotnet_decompile(path: str, engine: str = "ilspy", out_dir: str | None = None, project: bool = False) -> str:
    """Decompile a .NET assembly to C# with ILSpy (ilspycmd).

    Without ``out_dir`` the source returns inline; with ``out_dir`` sources are
    written there (one .cs per type when ``project``). ilspycmd installs automatically
    via ``dotnet tool`` when dotnet is present. dnspy/dotpeek engines are graphical -
    use dnspy_open/dotpeek_open for those.
    """
    try:
        return render(managed.dotnet_decompile(path, engine=engine, out_dir=out_dir, project=project))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def dnspy_open(path: str | None = None, binary: str | None = None) -> str:
    """Launch the dnSpy GUI (downloaded on first use) with an assembly.

    dnSpy also debugs assemblies - a real .NET debugger in the loop. Drive its window
    with the window_focus / input_* tools.
    """
    try:
        return render(managed.dnspy_open(path, binary=binary))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def dotpeek_open(path: str | None = None) -> str:
    """Open an assembly in the JetBrains dotPeek GUI (if installed).

    dotPeek decompiles .NET to C# and is free; CTPAX does not bundle it. Returns a
    clear error with the install hint when it is missing.
    """
    try:
        return render(managed.dotpeek_open(path))
    except Exception as exc:
        return fail(exc)


# --------------------------------------------------------------------------
# MegaDumper
# --------------------------------------------------------------------------
@mcp.tool()
def mega_dump(pid: int, out_dir: str | None = None, timeout: float = 45.0) -> str:
    """Dump a running process's loaded image with MegaDumper.

    Downloads MegaDumper on first use. Works on the target's pid (from frida_ps,
    proc_list, or tasklist). Returns fresh dump files; read them with the PE tools
    or open_binary. GUI builds dump next to the exe - check its window.
    """
    try:
        return render(managed.mega_dump(pid, out_dir=out_dir, timeout=timeout))
    except Exception as exc:
        return fail(exc)