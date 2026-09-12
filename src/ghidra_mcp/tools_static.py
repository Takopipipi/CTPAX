"""Tools that need no Ghidra: file identification, packing, strings, hexdump, disassembly, YARA.

These are the cheap first look at an unknown file. They answer in milliseconds where the
Ghidra path costs a JVM start plus an analysis pass, and on a packed binary they are often
the only thing that works at all.
"""

from __future__ import annotations

from ghidra_mcp import crypto as crypto_module
from ghidra_mcp import static_analysis as static
from ghidra_mcp.runtime import fail, mcp, render


@mcp.tool()
def file_info(path: str, section_entropy: bool = True) -> str:
    """Identify a file and dump its headers, sections, imports and exports.

    The cheap first look at anything unknown: format, hashes, section layout with
    per-section entropy, and the import table. Reach for this before ``open_binary``,
    because it costs milliseconds and often tells you what you needed to know.
    """
    try:
        return render(static.analyze_binary(path, section_entropy=section_entropy))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def detect_packing(path: str) -> str:
    """Detect packers, protectors, obfuscators, and language runtimes.

    Checks section names, marker strings, entropy, and the import count. Knowing a binary
    is UPX-packed or VMProtected before analysing it stops you reverse engineering an
    unpacking stub by mistake.
    """
    try:
        return render(static.detect_packing(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def entropy_map(path: str, blocks: int = 64) -> str:
    """Chart entropy across a file to locate encrypted or compressed regions.

    A spike in an otherwise ordinary file is usually an embedded key, certificate, or
    packed payload; the offsets it reports are where to point ``hexdump`` next.
    """
    try:
        return render(static.entropy_map(path, blocks=blocks))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def file_strings(
    path: str,
    min_length: int = 5,
    encoding: str = "both",
    pattern: str | None = None,
    regex: bool = False,
    limit: int = 200,
    offset: int = 0,
    length: int | None = None,
) -> str:
    """Extract strings from a file, tagging URLs, paths, registry keys, and secrets.

    Works on any file, packed or not, with no Ghidra needed. ``encoding`` is ``ascii``,
    ``utf16``, or ``both`` - on Windows binaries the interesting strings are usually
    UTF-16. The tags are the point: they cut a 10,000-string dump down to the handful
    worth reading.
    """
    try:
        data = static.read_file(path, offset=offset, length=length)
        return render(
            static.extract_strings(
                data,
                min_length=min_length,
                encoding=encoding,
                pattern=pattern,
                regex=regex,
                limit=limit,
            )
        )
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def hexdump(path: str, offset: int = 0, length: int = 256, width: int = 16) -> str:
    """Hexdump a file region. Use it to inspect a header or a blob another tool pointed at."""
    try:
        return render(static.hexdump(path, offset=offset, length=length, width=width))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def find_bytes_in_file(
    path: str,
    hex_pattern: str | None = None,
    text: str | None = None,
    utf16: str | None = None,
    limit: int = 50,
) -> str:
    """Search a file for a byte pattern and report file offsets.

    ``hex_pattern`` accepts ``??`` wildcards (``48 8b ?? 24``). Unlike ``search_memory``
    this reads the file on disk, needs no analysis, and gives offsets you can patch directly.
    """
    try:
        return render(static.find_pattern(path, hex_pattern=hex_pattern, text=text, utf16=utf16, limit=limit))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def disassemble_bytes(
    data: str,
    arch: str = "x86_64",
    base: int = 0,
    limit: int = 100,
    encoding: str = "auto",
) -> str:
    """Disassemble a hex byte string with capstone, no Ghidra project required.

    The tool for bytes rather than programs: shellcode, a decrypted buffer, a patch you are
    about to write. Architectures include x86, x86_64, arm, thumb, arm64, mips, ppc, riscv64.
    """
    try:
        payload = crypto_module.coerce_bytes(data, encoding)
        return render(static.disassemble_raw(payload, arch=arch, base=base, limit=limit))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def yara_scan(path: str, rules_source: str | None = None, rules_path: str | None = None) -> str:
    """Scan a file with YARA rules supplied inline or as a file.

    Useful for confirming a hypothesis across many files, or applying an existing rule set.
    """
    try:
        return render(static.yara_scan(path, rules_source=rules_source, rules_path=rules_path))
    except Exception as exc:
        return fail(
            exc,
            hint='Inline rules look like: rule r { strings: $a = "text" condition: $a }',
        )
