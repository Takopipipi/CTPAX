"""Ghidra tools: program management, reading code and data, writing findings back.

Every tool here forwards to a worker operation. Docstrings are what the model reads to
decide which tool to use, so they say when to reach for each one, not merely what it does.
"""

from __future__ import annotations

import os

from typing import Any

from ghidra_mcp.runtime import clean, ghidra, mcp


# --------------------------------------------------------------------------
# program management
# --------------------------------------------------------------------------
@mcp.tool()
def open_binary(
    path: str | None = None,
    program: str | None = None,
    analyze: bool = True,
    language: str | None = None,
    compiler: str | None = None,
    loader: str | None = None,
name: str | None = None,
    reimport: bool = False,
    pdb: bool = False,
    timeout: float = 1800.0,
) -> str:
    """Import a binary into Ghidra and analyse it. Every other Ghidra tool needs this first.

    The first call on a file is slow: it imports and runs auto-analysis, 10 seconds for a
    small utility and several minutes for a large one. Later calls on the same file are
    near-instant, because the analysis is stored in a project keyed by the file's SHA-256 -
    which is also why renames and comments from previous sessions are still there.

    Pass ``path`` for a new file, or ``program`` to reopen one already in the project (see
    ``list_programs``). ``language`` is only needed for raw images Ghidra cannot identify,
    e.g. ``ARM:LE:32:v8`` for bare firmware. ``reimport`` discards previous analysis.

    Files over ~2.5MB are imported WITHOUT auto-analysis (the analyze pass on a 4MB+
    binary can wedge the Ghidra worker and the whole machine for minutes, and the client
    call times out). The import result says so; then either run
    ``job_start('analyze_program', {...})`` and poll ``job_status``, or pass
    ``analyze=True`` anyway accepting the wait. For a large first import,
    ``job_start('open_binary', {...})`` is the non-blocking route.

    ``pdb`` (default False) re-enables the PDB Universal / PDB MSF analyzers, which fetch
    symbols from the Microsoft symbol server during the first analysis. Off by default
    because that download can stall on a slow or firewalled machine; a matching PDB next
    to the binary is picked up regardless.
    """
    downgraded = False
    if path and analyze:
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        if size > 2_500_000:
            analyze = False
            downgraded = True
    result = ghidra(
        "open",
        clean(
            {
                "path": path,
                "program": program,
                "analyze": analyze,
                "language": language,
                "compiler": compiler,
                "loader": loader,
                "name": name,
                "reimport": reimport,
                "pdb": pdb,
            }
        ),
        timeout=timeout,
    )
    if downgraded:
        result = (
            "NOTE: the file is large - auto-analysis was skipped so the worker does not "
            "wedge. Imported ready for inspection; start analysis with "
            "job_start('analyze_program', {...}) and poll job_status, then continue "
            "(decompile/xrefs work on whatever is already analyzed).\n\n"
        ) + result
    return result


@mcp.tool()
def program_info(program: str | None = None) -> str:
    """Summarise the open program: architecture, entry point, sections, function and symbol counts.

    Read this after ``open_binary`` to know what you are dealing with before spending time
    on individual functions.
    """
    return ghidra("info", clean({"program": program}))


@mcp.tool()
def list_programs() -> str:
    """List every binary in the Ghidra project, each with its analysis already saved.

    Use it to find the ``program`` identifier for something analysed in an earlier session,
    instead of re-importing and re-analysing the file.
    """
    return ghidra("project_list")


@mcp.tool()
def close_program(program: str | None = None, save: bool = True) -> str:
    """Close a program, saving analysis and edits by default.

    Worth doing when switching between several large binaries, to keep JVM memory down.
    """
    return ghidra("close", clean({"program": program, "save": save}))


@mcp.tool()
def save_program(program: str | None = None) -> str:
    """Flush pending changes to disk. Mutating tools save already, so this is rarely needed."""
    return ghidra("save", clean({"program": program}))


@mcp.tool()
def delete_program(program: str) -> str:
    """Remove a program and its analysis from the project.

    Irreversible: re-importing the file means paying for auto-analysis again.
    """
    return ghidra("delete_program", {"program": program})


@mcp.tool()
def analyze_program(
    program: str | None = None,
    options: dict[str, Any] | None = None,
    pdb: bool = False,
    timeout: float = 1800.0,
) -> str:
    """Re-run auto-analysis, optionally with different analyser options.

    Reach for this after patching bytes, defining new functions, or fixing a wrong language,
    so the rest of the analysis catches up. See ``analysis_options`` for what can be set.
    Prefer ``job_start`` on anything large.

    ``pdb`` (default False) re-enables the PDB Universal / PDB MSF analyzers for this pass.
    """
    return ghidra("analyze", clean({"program": program, "options": options, "pdb": pdb}), timeout=timeout)


@mcp.tool()
def analysis_options(program: str | None = None) -> str:
    """List Ghidra's analyser options and current values, for use with ``analyze_program``."""
    return ghidra("analysis_options", clean({"program": program}))


@mcp.tool()
def memory_blocks(program: str | None = None) -> str:
    """Section and segment layout with permissions and file offsets.

    The map to consult before patching: which addresses are writable, which are executable,
    and where each block lives in the file.
    """
    return ghidra("memory_blocks", clean({"program": program}))


@mcp.tool()
def entry_points(program: str | None = None) -> str:
    """Declared entry points, which is where to start reading an unfamiliar binary."""
    return ghidra("entry_points", clean({"program": program}))


@mcp.tool()
def list_imports(program: str | None = None, filter: str | None = None, limit: int = 300) -> str:
    """Imported functions grouped by library.

    The fastest read on what a binary can possibly do: sockets, crypto APIs, process
    injection, and file access all show up here before you read a single instruction.
    """
    return ghidra("imports", clean({"program": program, "filter": filter, "limit": limit}))


@mcp.tool()
def list_exports(program: str | None = None, limit: int = 300) -> str:
    """Exported symbols, i.e. what other modules can call. Useful on DLLs and shared objects."""
    return ghidra("exports", clean({"program": program, "limit": limit}))


@mcp.tool()
def list_relocations(program: str | None = None, limit: int = 200) -> str:
    """Relocation entries. A stripped or packed binary often has suspiciously few."""
    return ghidra("relocations", clean({"program": program, "limit": limit}))


# --------------------------------------------------------------------------
# reading code
# --------------------------------------------------------------------------
@mcp.tool()
def list_functions(
    program: str | None = None,
    filter: str | None = None,
    regex: str | None = None,
    named_only: bool = False,
    min_size: int = 0,
    sort: str = "address",
    include_thunks: bool = True,
    include_external: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> str:
    """List functions, with the filters that make a large binary tractable.

    ``named_only=true`` drops Ghidra's auto-generated ``FUN_*``, leaving the functions the
    binary told us about, which is usually the best starting point. ``sort='size'`` surfaces
    the large ones, where the logic tends to live. Page through with ``offset``.
    """
    return ghidra(
        "functions",
        clean(
            {
                "program": program,
                "filter": filter,
                "regex": regex,
                "named_only": named_only,
                "min_size": min_size,
                "sort": sort,
                "include_thunks": include_thunks,
                "include_external": include_external,
                "limit": limit,
                "offset": offset,
            }
        ),
    )


@mcp.tool()
def function_info(function: str, program: str | None = None) -> str:
    """Detail for one function: signature, parameters, locals, callers, callees.

    ``function`` accepts a name, an address, or ``entry``. Read it before decompiling to see
    whether the signature is already known and who reaches the function.
    """
    return ghidra("function", clean({"program": program, "function": function}), timeout=300.0)


@mcp.tool()
def decompile(
    function: str,
    program: str | None = None,
    timeout: int = 90,
    include_line_addresses: bool = False,
    request_timeout: float = 300.0,
) -> str:
    """Decompile a function to C. The core tool of this server.

    ``function`` accepts a name, an address, or ``entry``. If the address has no
    function yet (stripped binaries, auto-analysis missed it), one is created at that
    address automatically and the decompilation proceeds - the creation is reported in
    the response. ``include_line_addresses`` maps each line of C back to the
    instructions that produced it, which is what you need before patching something
    you spotted in the decompilation.

    If the C is hard to read, fix the prototype with ``set_signature`` and decompile again:
    wrong parameter types are the usual cause of unreadable output, not decompiler failure.
    """
    return ghidra(
        "decompile",
        clean(
            {
                "program": program,
                "function": function,
                "timeout": timeout,
                "include_line_addresses": include_line_addresses,
            }
        ),
        timeout=request_timeout,
    )


@mcp.tool()
def decompile_many(
    functions: list[str],
    program: str | None = None,
    limit: int = 12,
    timeout: int = 60,
) -> str:
    """Decompile several named functions in one call.

    Intended for a call chain or a small cluster of related handlers. To dump a whole
    binary use ``export_program(format='c')`` instead; the output cap would truncate this.
    """
    return ghidra(
        "decompile_many",
        clean({"program": program, "functions": functions, "limit": limit, "timeout": timeout}),
        timeout=600.0,
    )


@mcp.tool()
def disassemble(
    function: str | None = None,
    address: str | None = None,
    program: str | None = None,
    limit: int = 200,
    include_comments: bool = False,
) -> str:
    """Disassembly for a function, or from an address.

    Use this when the C output hides something that matters - an exact encoding, alignment,
    a jump table - or when you need the byte-level view before a patch.
    """
    return ghidra(
        "disassemble",
        clean(
            {
                "program": program,
                "function": function,
                "address": address,
                "limit": limit,
                "include_comments": include_comments,
            }
        ),
    )


@mcp.tool()
def xrefs(target: str | None = None, program: str | None = None, direction: str = "to", limit: int = 200, targets: list[str] | None = None) -> str:
    """Find references to or from addresses, functions, or symbols - one or MANY.

    The main navigation tool: "who calls this", "who reads this string", "what does this
    function touch". ``direction`` is ``to``, ``from``, or ``both``. Pass ``targets`` as
    a list for bulk call-graph work (20 functions -> one call, results keyed per target);
    a single ``target`` also works.
    """
    return ghidra("xrefs", clean({"program": program, "address": target, "targets": targets, "direction": direction, "limit": limit}))


@mcp.tool()
def callgraph(
    function: str,
    program: str | None = None,
    direction: str = "callees",
    depth: int = 2,
    max_nodes: int = 200,
) -> str:
    """Walk the call graph from a function, breadth-first.

    ``direction='callers'`` answers "how is this reached", which is how you find the path to
    a licence check or a decryption routine without reading every caller by hand.
    """
    return ghidra(
        "callgraph",
        clean(
            {
                "program": program,
                "function": function,
                "direction": direction,
                "depth": depth,
                "max_nodes": max_nodes,
            }
        ),
        timeout=300.0,
    )


@mcp.tool()
def decompile_search(
    query: str,
    program: str | None = None,
    regex: bool = False,
    case_sensitive: bool = False,
    max_functions: int = 300,
    max_hits: int = 40,
    context_lines: int = 2,
    filter: str | None = None,
    min_size: int = 0,
    time_limit: float = 240.0,
    request_timeout: float = 900.0,
) -> str:
    """Search the decompiled C of the whole binary for a pattern.

    How you find behaviour when every symbol is stripped: grep the decompilation for
    ``VirtualAlloc``, a magic constant, ``memcmp``, or a regex to locate XOR loops. It
    decompiles as it goes, making it the most expensive tool here.

    Because a full pass on a large binary (say 35k functions) can outlive any client
    timeout and end as -32001, the scan stops at a ``time_limit`` (default 240s, max
    600s) and returns what it has so far with a clear ``note`` - it never parks the
    worker on a dead socket. To scan more in the background instead of blocking:
    ``job_start('decompile_search', {...})`` and poll ``job_status``.

    Narrow an expensive binary with ``filter`` (function-name substring) or ``min_size``
    before raising the limits; ``max_functions`` caps the budget at 6000.
    """
    return ghidra(
        "decompile_grep",
        clean(
            {
                "program": program,
                "query": query,
                "regex": regex,
                "case_sensitive": case_sensitive,
                "max_functions": max_functions,
                "max_hits": max_hits,
                "context_lines": context_lines,
                "filter": filter,
                "min_size": min_size,
                "time_limit": time_limit,
            }
        ),
        timeout=request_timeout,
    )


@mcp.tool()
def pcode(function: str, program: str | None = None, high: bool = True, limit: int = 300) -> str:
    """P-code (Ghidra's intermediate representation) for a function.

    Worth reading when the C looks wrong or elides something: the IR shows the data flow the
    decompiler actually reasoned over. ``high=false`` gives raw per-instruction p-code.
    """
    return ghidra(
        "pcode",
        clean({"program": program, "function": function, "high": high, "limit": limit}),
        timeout=300.0,
    )


@mcp.tool()
def list_symbols(
    program: str | None = None,
    filter: str | None = None,
    regex: str | None = None,
    type: str | None = None,
    limit: int = 200,
    offset: int = 0,
    include_dynamic: bool = False,
) -> str:
    """Search the symbol table by name, type, or namespace.

    ``type`` filters on the symbol kind (``FUNCTION``, ``LABEL``, ``PARAMETER``, ...).
    """
    return ghidra(
        "symbols",
        clean(
            {
                "program": program,
                "filter": filter,
                "regex": regex,
                "type": type,
                "limit": limit,
                "offset": offset,
                "include_dynamic": include_dynamic,
            }
        ),
    )


# --------------------------------------------------------------------------
# data
# --------------------------------------------------------------------------
@mcp.tool()
def list_strings(
    program: str | None = None,
    filter: str | None = None,
    regex: str | None = None,
    min_length: int = 5,
    with_refs: bool = True,
    limit: int = 150,
    offset: int = 0,
) -> str:
    """Strings Ghidra found, with the functions that reference them.

    Better than a raw strings dump precisely because of ``with_refs``: knowing which function
    reads "license expired" takes you straight to the check. Follow a hit with ``xrefs`` and
    then ``decompile``.
    """
    return ghidra(
        "strings",
        clean(
            {
                "program": program,
                "filter": filter,
                "regex": regex,
                "min_length": min_length,
                "with_refs": with_refs,
                "limit": limit,
                "offset": offset,
            }
        ),
        timeout=300.0,
    )


@mcp.tool()
def read_memory(address: str, program: str | None = None, length: int = 64) -> str:
    """Read bytes at an address in the analysed program, as hex and a hexdump.

    Unlike ``hexdump`` this reads the Ghidra database, so it reflects the loaded image layout
    and any patches applied.
    """
    return ghidra("read_bytes", clean({"program": program, "address": address, "length": length}))


@mcp.tool()
def search_memory(
    hex_pattern: str | None = None,
    text: str | None = None,
    utf16: str | None = None,
    program: str | None = None,
    start: str | None = None,
    limit: int = 50,
) -> str:
    """Search the program's memory for a byte pattern, with ``??`` wildcards.

    Reports virtual addresses and the containing function, which is what you want when
    hunting a signature: ``hex_pattern='48 8b ?? 24'``. Results feed straight into
    ``disassemble`` or ``xrefs``.
    """
    return ghidra(
        "search_bytes",
        clean(
            {
                "program": program,
                "hex": hex_pattern,
                "text": text,
                "utf16": utf16,
                "start": start,
                "limit": limit,
            }
        ),
        timeout=300.0,
    )


@mcp.tool()
def data_at(address: str, program: str | None = None) -> str:
    """What lives at an address: type, value, label, containing function, and every reference to it."""
    return ghidra("data", clean({"program": program, "address": address}))


@mcp.tool()
def data_types(
    program: str | None = None,
    name: str | None = None,
    filter: str | None = None,
    limit: int = 100,
) -> str:
    """Search Ghidra's data types, or expand one structure's layout.

    Pass ``name`` to get a structure's fields and offsets, which you need before applying it
    with ``apply_type`` or naming it in a signature.
    """
    return ghidra("data_types", clean({"program": program, "name": name, "filter": filter, "limit": limit}))


@mcp.tool()
def list_labels(
    program: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 200,
) -> str:
    """Defined labels in an address range: the map of what has been named so far."""
    return ghidra("labels", clean({"program": program, "start": start, "end": end, "limit": limit}))


# --------------------------------------------------------------------------
# writing findings back
# --------------------------------------------------------------------------
@mcp.tool()
def rename(target: str, new_name: str, program: str | None = None, label_only: bool = False) -> str:
    """Rename a function, label, or data symbol; create a label if none exists.

    Do this as you work, not at the end. Names persist in the project, so they appear in
    every later decompilation and in the Ghidra GUI - turning ``FUN_140001010`` into
    ``check_license`` is what makes the surrounding code readable.
    """
    return ghidra(
        "rename",
        clean({"program": program, "target": target, "new_name": new_name, "label_only": label_only}),
    )


@mcp.tool()
def set_comment(
    address: str,
    comment: str,
    program: str | None = None,
    type: str = "EOL",
    append: bool = False,
) -> str:
    """Attach a comment at an address. Types: ``EOL``, ``PRE``, ``POST``, ``PLATE``, ``REPEATABLE``.

    Record findings here rather than only in chat: comments persist into later sessions and
    are visible to a human opening the project in Ghidra. An empty comment deletes one.
    """
    return ghidra(
        "set_comment",
        clean({"program": program, "address": address, "comment": comment, "type": type, "append": append}),
    )


@mcp.tool()
def set_function_comment(function: str, comment: str, program: str | None = None) -> str:
    """Set the function-level comment shown in the decompiler header.

    The right place for a one-paragraph summary of what a function does once you work it out.
    """
    return ghidra("set_function_comment", clean({"program": program, "function": function, "comment": comment}))


@mcp.tool()
def set_signature(function: str, signature: str, program: str | None = None) -> str:
    """Apply a C prototype to a function, e.g. ``int decrypt(char *buf, int len, char key)``.

    The highest-leverage edit available: correcting a signature usually turns unreadable
    decompiled C into something obvious, because the decompiler stops guessing at parameter
    types and stack layout. Try this before concluding a function is incomprehensible.
    """
    return ghidra("set_signature", clean({"program": program, "function": function, "signature": signature}))


@mcp.tool()
def set_variable(
    function: str,
    variable: str,
    program: str | None = None,
    new_name: str | None = None,
    type: str | None = None,
) -> str:
    """Rename or retype a local variable or parameter inside a function.

    Works on decompiler-only names too (``uVar1``, ``local_28``): those are committed to the
    database automatically. Naming locals as you understand them is how a long function
    becomes followable.
    """
    return ghidra(
        "set_variable",
        clean({"program": program, "function": function, "variable": variable, "new_name": new_name, "type": type}),
        timeout=300.0,
    )


@mcp.tool()
def apply_type(address: str, type: str, program: str | None = None, clear_existing: bool = True) -> str:
    """Apply a data type at an address, e.g. ``int``, ``char[32]``, ``IMAGE_DOS_HEADER``.

    Turns a run of undefined bytes into a typed value, which then reads properly in every
    decompilation that touches it.
    """
    return ghidra(
        "apply_data_type",
        clean({"program": program, "address": address, "type": type, "clear_existing": clear_existing}),
    )


@mcp.tool()
def create_function(
    address: str,
    program: str | None = None,
    name: str | None = None,
    recreate: bool = False,
) -> str:
    """Define a function at an address auto-analysis missed.

    Common in obfuscated or packed code where a call target was left as raw data. If it
    reports data rather than code at the address, run ``force_disassemble`` first.
    """
    return ghidra(
        "create_function",
        clean({"program": program, "address": address, "name": name, "recreate": recreate}),
    )


@mcp.tool()
def force_disassemble(address: str, program: str | None = None, follow_flow: bool = True) -> str:
    """Force disassembly at an address that analysis left as data."""
    return ghidra("disassemble_at", clean({"program": program, "address": address, "follow_flow": follow_flow}))


@mcp.tool()
def patch(
    address: str,
    hex_bytes: str | None = None,
    assembly: str | None = None,
    program: str | None = None,
    clear_instructions: bool = True,
    redisassemble: bool = True,
) -> str:
    """Patch bytes in the analysis, by hex or by assembling an instruction.

    ``assembly='NOP'`` or ``assembly='JMP 0x140001100'`` is assembled for the program's own
    architecture. This changes the Ghidra database only - to get a patched file, follow with
    ``export_program(format='binary')``. Use ``assemble_preview`` first when you only want to
    see the encoding and its length.
    """
    return ghidra(
        "patch_bytes",
        clean(
            {
                "program": program,
                "address": address,
                "hex": hex_bytes,
                "assembly": assembly,
                "clear_instructions": clear_instructions,
                "redisassemble": redisassemble,
            }
        ),
    )


@mcp.tool()
def assemble_preview(assembly: str, address: str | None = None, program: str | None = None) -> str:
    """Assemble an instruction and show its encoding without writing anything.

    Check a patch's length before applying it: an over-long instruction would clobber the
    next one.
    """
    return ghidra("assemble", clean({"program": program, "address": address, "assembly": assembly}))


@mcp.tool()
def clear_code(address: str, length: int = 16, program: str | None = None) -> str:
    """Clear code units in a range, undoing bad disassembly so it can be redone correctly."""
    return ghidra("clear", clean({"program": program, "address": address, "length": length}))


@mcp.tool()
def bookmark(address: str, comment: str = "", program: str | None = None, category: str = "MCP") -> str:
    """Leave a bookmark at an address, so a human or a later session can find the spot in Ghidra."""
    return ghidra(
        "bookmark",
        clean({"program": program, "address": address, "comment": comment, "category": category}),
    )


@mcp.tool()
def list_bookmarks(program: str | None = None, limit: int = 200) -> str:
    """List bookmarks, including the ones Ghidra's own analysers left behind."""
    return ghidra("list_bookmarks", clean({"program": program, "limit": limit}))


# --------------------------------------------------------------------------
# escape hatches
# --------------------------------------------------------------------------
@mcp.tool()
def run_ghidra_script(
    code: str | None = None,
    path: str | None = None,
    program: str | None = None,
    args: list[str] | None = None,
    request_timeout: float = 900.0,
) -> str:
    """Run a Python GhidraScript against the open program, with the full Ghidra API available.

    The escape hatch for anything these tools do not cover. ``currentProgram`` and the
    ``FlatProgramAPI`` helpers are in scope, and ``print`` output comes back. Use it for bulk
    work - applying a heuristic to every function, say - rather than issuing hundreds of
    individual tool calls.
    """
    return ghidra(
        "run_script",
        clean({"program": program, "code": code, "path": path, "args": args}),
        timeout=request_timeout,
    )


@mcp.tool()
def export_program(
    output: str,
    format: str = "c",
    program: str | None = None,
    request_timeout: float = 1800.0,
) -> str:
    """Export the program: ``c`` (full decompilation), ``binary`` (patched bytes), ``ascii`` (listing).

    ``binary`` is how a patch made with ``patch`` becomes a real file on disk. ``c`` on a large
    binary produces megabytes and takes minutes, so it writes to a file rather than returning
    text; consider running it through ``job_start``.
    """
    return ghidra("export", clean({"program": program, "output": output, "format": format}), timeout=request_timeout)


# --------------------------------------------------------------------------
# full-API access: eval bridge and API discovery
# --------------------------------------------------------------------------
@mcp.tool()
def ghidra_eval_python(
    code: str,
    program: str | None = None,
    address: str | None = None,
    request_timeout: float = 900.0,
) -> str:
    """Execute Python inside the Ghidra worker with the FULL Ghidra API in scope.

    This is the 100% escape hatch: every Ghidra class is importable, and the bindings
    include currentProgram, flat (FlatProgramAPI), decompiler (a ready DecompInterface),
    fm (FunctionManager), st (SymbolTable), listing, memory, monitor. Use for anything
    the typed tools do not cover: bulk analysis passes, decompiler internals, custom
    walkers, one-off Ghidra operations. print() output and defined variables come back.
    Check method names first with ghidra_api_explore.
    """
    return ghidra(
        "eval_python",
        clean({"code": code, "program": program, "address": address}),
        timeout=request_timeout,
    )


@mcp.tool()
def ghidra_api_explore(query: str, mode: str = "search", limit: int = 30) -> str:
    """Browse the Ghidra Java API from the live JVM: find classes, list methods, signatures.

    mode=search finds classes by regex across Ghidra's jars (e.g. 'Function.*Iterator');
    mode=members lists one class's methods with signatures (pass the fully-qualified
    name); mode=doc shows constructors and class shape. The discovery half of
    ghidra_eval_python: look up the exact call, then run it.
    """
    return ghidra("api_explore", clean({"query": query, "mode": mode, "limit": limit}))
