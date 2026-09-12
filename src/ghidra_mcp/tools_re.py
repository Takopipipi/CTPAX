"""MCP tools for RE acceleration: license-gate correlation, patch suggestions,
build comparison, and cross-build function mapping."""

from __future__ import annotations

from ghidra_mcp import pe_tools
from ghidra_mcp.runtime import fail, ghidra, mcp, render


@mcp.tool()
def find_license_checks(program: str | None = None, top_n: int = 8) -> str:
    """Correlate license indicators into a ranked list of likely check functions.

    Scores every function touching license strings (trial/expired/premium/hwid/...),
    time APIs, registry reads, and HWID inputs (MachineGuid, disk serial, adapters);
    functions combining 2+ categories rank first, each with a decompiled snippet.
    The answer to "where is the gate" in a 57k-function binary without reading them.
    Call open_binary first.
    """
    try:
        return ghidra("find_license_checks", {"program": program, "top_n": top_n})
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def suggest_patches(program: str | None = None, address: str = "") -> str:
    """Propose paste-ready byte patches at a comparison or jump, encodings validated.

    For a jcc: force taken (JMP), never taken (NOPs), or inverted - each assembled with
    Ghidra's assembler at the exact address and length-checked. For a call: skip it.
    Apply a suggestion with patch_bytes. The automate assemble_preview round trips.
    """
    try:
        return ghidra("suggest_patches", {"program": program, "address": address})
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def function_map(program: str | None = None, program_b: str = "", prefix: int = 48, limit: int = 200) -> str:
    """Match functions between two analysed builds by code signature.

    The new build shifted every offset, but most function bodies survived: this hashes
    each function's first instruction bytes in build A and finds its twin in build B,
    so names/comments/analysis carry over instead of being redone. Pass both project
    keys (list_programs); both must be analysed first.
    """
    try:
        return ghidra("function_map", {
            "program": program, "program_b": program_b, "prefix": prefix, "limit": limit,
        })
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def pe_compare(path_a: str, path_b: str) -> str:
    """Structural + byte-level diff of two builds of the same binary.

    Header drift, section shifts, import/export deltas, per-section diff runs with
    RVA/file-offset samples, and a verdict (real code movement vs rebuild/resign).
    The "what did the update change" first look - before opening Ghidra at all.
    """
    try:
        return render(pe_tools.pe_compare(path_a, path_b))
    except Exception as exc:
        return fail(exc)
