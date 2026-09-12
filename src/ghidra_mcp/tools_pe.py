"""MCP tools for deep PE inspection; every tool maps to one pe_tools function.

Docstrings are the model's guide to when each tool is worth calling, so they describe the
reverse-engineering question the tool answers rather than the pefile mechanics behind it.
"""

from __future__ import annotations

from ghidra_mcp import pe_tools
from ghidra_mcp.runtime import fail, mcp, render


@mcp.tool()
def pe_headers(path: str) -> str:
    """DOS/PE headers, entry point, DLL characteristics, and every populated data directory.

    The structural first look at a PE: machine type, subsystem, whether the checksum and
    Rich header are honest, and which data directories exist at all. Reach for it before
    pe_sections when the question is "what kind of binary is this".
    """
    try:
        return render(pe_tools.pe_headers(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def pe_sections(path: str) -> str:
    """Sections with VA/raw extents, flags, and entropy; alignment and naming oddities flagged.

    Suspicious traits are pulled out separately: writable+executable sections, raw data
    that is all zeros, virtual sizes far beyond raw sizes, and non-alphanumeric names -
    the usual fingerprints of packers and manually rebuilt files.
    """
    try:
        return render(pe_tools.pe_sections(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def pe_imports(path: str) -> str:
    """Full import table per DLL with IAT RVAs; hollowed or minimal tables flagged.

    An empty or two-function import table on a GUI binary means packed or hollowed. The
    iat_rva values are what you feed to hardware breakpoints or x64dbg to catch a
    specific API resolving.
    """
    try:
        return render(pe_tools.pe_imports(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def pe_exports(path: str) -> str:
    """Export table with names, ordinals, and RVAs - DLLs and kernel drivers."""
    try:
        return render(pe_tools.pe_exports(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def pe_resources(path: str, extract: str | None = None, out_path: str | None = None) -> str:
    """Resource tree (type/name/language), with optional extraction of one entry.

    Pass ``extract`` as a ``path`` value from the listing (``CURSOR/1/1033`` style) and
    ``out_path`` to write that resource to disk - icons, dialogs, and embedded binaries
    live here.
    """
    try:
        return render(pe_tools.pe_resources(path, extract=extract, out_path=out_path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def pe_tls(path: str) -> str:
    """TLS directory with decoded callback addresses.

    TLS callbacks execute before the entry point, which makes them the classic hiding
    spot for anti-debug checks. The callback VAs are ready to feed into a debugger.
    """
    try:
        return render(pe_tools.pe_tls(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def pe_relocations(path: str) -> str:
    """Relocation directory summary: block entry counts by type.

    Tells you whether ASLR will actually work: ``dynamic_base`` set with an empty
    relocation directory is a manual-rebuild tell. Also useful before patching - a
    relocated module's absolute addresses move at load time.
    """
    try:
        return render(pe_tools.pe_relocations(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def pe_overlay(path: str, extract_to: str | None = None) -> str:
    """Overlay: data appended after the last section, with entropy and optional extraction.

    Installers, droppers, and self-extractors hide their payload here. A several-MB
    high-entropy overlay on a small stub is the whole story in one number.
    """
    try:
        return render(pe_tools.pe_overlay(path, extract_to=extract_to))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def pe_certificates(path: str) -> str:
    """Authenticode presence: security-directory offset, size, and blob hash.

    Reports whether a signature blob exists and where, not whether the chain validates -
    use signtool for that. A stripped signature directory on a known-branded binary is a
    rebuild tell.
    """
    try:
        return render(pe_tools.pe_certificates(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def pe_heuristics(path: str) -> str:
    """Score a PE for suspicious traits: wx-sections, TLS, hollowed imports, entropy, overlay.

    The triage tool. Returns a score, a verdict (benign / suspicious /
    likely_packed_or_protected), and each finding with its severity and the exact reason.
    Reach for it before opening anything in a debugger.
    """
    try:
        return render(pe_tools.pe_heuristics(path))
    except Exception as exc:
        return fail(exc)
