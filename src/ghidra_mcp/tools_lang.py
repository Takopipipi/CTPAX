"""MCP tools for language-level source recovery: Java decompilation, .NET inspection,
PDB symbol resolution, and crypto-constant localization in Ghidra."""

from __future__ import annotations

from ghidra_mcp import lang_recover
from ghidra_mcp.runtime import fail, ghidra, mcp, render


@mcp.tool()
def decompile_java(path: str, extra_args: str = "") -> str:
    """Decompile a Java jar/class to (nearly) original Java source with CFR.

    CFR reconstructs control flow, generics and lambdas; most valid jars decompile
    outright. Downloads CFR once automatically; needs java on PATH or JAVA_HOME.
    The result lists per-class .java files ready to read with file tools.
    """
    try:
        return render(lang_recover.decompile_java(path, extra_args=extra_args))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def dotnet_inspect(path: str) -> str:
    """Dump a .NET assembly's types, methods, and user strings (dnfile, pure Python).

    The type/method tables are the skeleton of the original code; user_strings often
    holds license messages verbatim. For full C#: de4dot or ILSpy on the same file.
    """
    try:
        return render(lang_recover.dotnet_inspect(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def dotnet_il(path: str, type_name: str | None = None) -> str:
    """Disassemble .NET methods to IL (dncil) - the 'assembly' of managed code.

    ``type_name`` filters methods by name substring. IL is what you read when C#
    recovery tools refuse an obfuscated assembly.
    """
    try:
        return render(lang_recover.dotnet_il(path, type_name))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def pdb_path_from_binary(path: str) -> str:
    """Read the debug directory (RSDS) for the PDB name and GUID a binary was built with.

    The GUID+age+name triple is the symbol-server key; with it you can recover symbols
    for Windows binaries. Ghidra also picks a PDB up automatically when it sits next to
    the binary.
    """
    try:
        return render(lang_recover.pdb_path_from_binary(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def pdb_download(path: str, out_dir: str | None = None) -> str:
    """Fetch the matching PDB from the Microsoft symbol server.

    Works for Windows binaries (every system DLL ships symbols publicly); third-party
    PDBs rarely exist unless the developer leaked them. After download, re-run
    open_binary - Ghidra names hundreds of functions automatically.
    """
    try:
        return render(lang_recover.pdb_download(path, out_dir=out_dir))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def find_crypto_constants(program: str | None = None, limit: int = 60) -> str:
    """Locate crypto algorithm constants in the open program and name their functions.

    AES S-boxes, SHA-256 K table, MD5 T table, Blowfish P-array, ChaCha sigma, CRC32
    tables, ASN.1 OIDs - a working implementation cannot omit these, so a hit inside a
    function localizes the algorithm precisely. Call open_binary first.
    """
    try:
        return ghidra("find_crypto_constants", {"program": program, "limit": limit})
    except Exception as exc:
        return fail(exc)
