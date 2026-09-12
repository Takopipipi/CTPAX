"""Reverse-engineering accelerators: license-check correlation, patch suggestions,
and function mapping between builds.

These ops encode the manual workflows that eat hours on a 57k-function binary:

* ``find_license_checks`` - correlate time APIs, registry reads, HWID inputs, and
  license strings into a ranked list of likely gates, each with a decompile snippet;
* ``suggest_patches`` - for a comparison/jump, propose concrete byte patches
  (jcc -> jmp, jcc -> nops, forced return value) with validated encodings;
* ``function_map`` - match functions between two builds by code signature, so a
  renamed-and-shifted release does not have to be reanalysed from zero.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable

from ghidra_mcp.ghidra_ops import OpError, Session, clamp, op, parse_address, resolve_function

_LICENSE_STRING_RE = re.compile(
    r"(?i)("
    r"trial|expir|licen[cs]e|premium|subscri|hwid|machine.guid|activat(?:e|ion)(?! ?context)|unregister|"
    r"register(ed| your)|purchase|upgrade to|demo version|days? left|key (is|invalid)|"
    r"invalid (key|code|licen)|not activated|please (buy|purchase|enter|activat)|"
    r"only.?sub|early access|access denied|no (access|permission)|banned|blacklist|"
    r"subscription|subscription has|your subscription|renew|payment|order now|buy now|"
    r"serial|product key|activation key|cracked|pirat"
    r")"
)

_TIME_IMPORTS = {
    "GetSystemTime", "GetLocalTime", "GetSystemTimeAsFileTime", "GetTickCount",
    "GetTickCount64", "time", "_time64", "_time32", "_time", "QueryPerformanceCounter",
    "GetSystemTimePreciseAsFileTime", "clock", "NtQuerySystemTime",
}

_REGISTRY_IMPORTS = {
    "RegGetValueA", "RegGetValueW", "RegQueryValueExA", "RegQueryValueExW",
    "RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyExA", "RegCreateKeyExW",
    "RegEnumKeyExA", "RegEnumKeyExW", "SHGetValueA", "SHGetValueW", "RegCloseKey",
}

_HWID_IMPORTS = {
    "GetVolumeInformationA", "GetVolumeInformationW", "DeviceIoControl",
    "GetAdaptersInfo", "GetIfTable", "GetComputerNameA", "GetComputerNameW",
    "GetUserNameA", "GetUserNameW", "GetPhysicallyInstalledSystemMemory",
    "EnumDisplayDevicesA", "EnumDisplayDevicesW", "WlanEnumInterfaces",
}

_HWID_STRINGS_RE = re.compile(
    r"(?i)(machine.guid|cimv2|wmic|csproduct|diskdrive|bios|baseboard|"
    r"serial.?number|volume.?serial|hardware.?id|mac.?address|adapter|"
    r"software\\\\microsoft\\\\cryptography)"
)

_SCORE_WEIGHTS = {"string": 3, "time": 2, "registry": 2, "hwid_call": 3, "hwid_string": 3}


def _string_values(session: Session, entry: Any, limit: int) -> list[tuple[Any, str]]:
    """Defined string data in the program, as (data, text) pairs."""
    listing = entry.program.getListing()
    out: list[tuple[Any, str]] = []
    for data in listing.getDefinedData(True):
        session.check_cancel()
        try:
            if not data.hasStringValue():
                continue
        except Exception:
            continue
        value = str(data.getValue())
        out.append((data, value))
        if len(out) >= limit:
            break
    return out


def _external_names(program: Any) -> set[str]:
    """Names of imported functions - string matches against these are API names
    ("RegisterClassExW" matches "register"), not license indicators."""
    names: set[str] = set()
    for function in program.getFunctionManager().getFunctions(True):
        if function.isExternal():
            names.add(str(function.getName()).lower())
    return names


def _referencing_functions(session: Session, entry: Any, address: Any) -> set[Any]:
    """Functions that reach an address through any reference chain depth 1."""
    manager = entry.program.getReferenceManager()
    functions = set()
    for reference in manager.getReferencesTo(address):
        holder = entry.program.getFunctionManager().getFunctionContaining(reference.getFromAddress())
        if holder is not None:
            functions.add(holder)
    return functions


@op("find_license_checks")
def find_license_checks(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Correlate license indicators into a ranked list of likely check functions.

    Scores every function that touches license-shaped strings (trial/expired/premium/
    hwid...), time APIs, registry reads, or HWID inputs (MachineGuid, disk serial,
    adapters); functions combining 2+ indicator categories rank first. The top results
    come with a decompiled snippet, so the gate reading starts at line one.
    """
    entry = session.resolve(params)
    program = entry.program
    monitor = session.monitor()
    top_n = clamp(params.get("top_n"), 1, 20, 8)
    max_strings = clamp(params.get("max_strings"), 100, 500000, 50000)

    scores: dict[Any, dict[str, Any]] = {}

    def bump(function: Any, category: str, detail: str) -> None:
        if function is None or function.isExternal() or function.isThunk():
            return
        key = function.getEntryPoint().toString()
        record = scores.setdefault(key, {"function": function, "categories": {}, "details": []})
        record["categories"][category] = record["categories"].get(category, 0) + 1
        if detail not in record["details"]:
            record["details"].append(detail)

    progress(stage="strings")
    imported_names = _external_names(program)
    for data, text in _string_values(session, entry, max_strings):
        if text.lower() in imported_names:
            continue  # an API name, not a message
        if _LICENSE_STRING_RE.search(text):
            for function in _referencing_functions(session, entry, data.getAddress()):
                bump(function, "string", f"str: {text[:60]}")
        if _HWID_STRINGS_RE.search(text):
            for function in _referencing_functions(session, entry, data.getAddress()):
                bump(function, "hwid_string", f"hwid-str: {text[:60]}")

    progress(stage="imports")
    for function in program.getFunctionManager().getFunctions(True):
        if not function.isExternal():
            continue
        name = function.getName()
        category = None
        if name in _TIME_IMPORTS:
            category = "time"
        elif name in _REGISTRY_IMPORTS:
            category = "registry"
        elif name in _HWID_IMPORTS:
            category = "hwid_call"
        if category is None:
            continue
        try:
            callers = function.getCallingFunctions(monitor)
        except Exception:
            callers = []
        for caller in callers:
            bump(caller, category, f"call: {name}")

    progress(stage="ranking")
    ranked: list[dict[str, Any]] = []
    for key, record in scores.items():
        categories = record["categories"]
        score = sum(_SCORE_WEIGHTS.get(cat, 1) * count for cat, count in categories.items())
        if len(categories) >= 2:
            score += 10  # a function that reads time AND license strings is a gate
        function = record["function"]
        ranked.append({
            "address": str(function.getEntryPoint()),
            "name": str(function.getName()),
            "size": int(function.getBody().getNumAddresses()),
            "score": score,
            "categories": {cat: count for cat, count in sorted(categories.items())},
            "indicators": record["details"][:8],
        })
    ranked.sort(key=lambda item: (-item["score"], item["address"]))
    ranked = ranked[:top_n]

    # decompile the winners so the snippet is attached
    progress(stage="decompile")
    interface = session.decompiler(entry)
    for item in ranked:
        session.check_cancel()
        function = resolve_function(program, item["address"])
        try:
            results = interface.decompileFunction(function, 60, monitor)
            if results.decompileCompleted():
                decompiled = results.getDecompiledFunction()
                snippet = str(decompiled.getC()) if decompiled is not None else ""
                item["decompiled"] = snippet[:6000]
        except Exception as exc:
            item["decompile_error"] = str(exc)[:200]

    return {
        "program": entry.key,
        "functions_scored": len(scores),
        "returned": len(ranked),
        "candidates": ranked,
        "note": "score = weighted indicator hits; 2+ categories (+10) is a strong gate signal",
    }


_JCC_MNEMONICS = {"JZ", "JNZ", "JE", "JNE", "JA", "JNA", "JB", "JNB", "JAE", "JBE", "JG", "JGE", "JL", "JLE", "JS", "JNS", "JO", "JNO", "JP", "JNP"}


@op("suggest_patches")
def suggest_patches(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Propose concrete byte patches at an address, with validated encodings.

    For a conditional jump: force it taken (JMP), force it never taken (NOPs), or
    invert it. For a comparison feeding a jump: NOP the jump. Every suggestion is
    assembled with Ghidra's assembler at the exact address and length-checked, so what
    comes back is paste-ready for ``patch_bytes`` - no assemble_preview round trips.
    """
    entry = session.resolve(params)
    program = entry.program
    listing = program.getListing()
    address = parse_address(program, params.get("address"))
    instruction = listing.getInstructionAt(address)
    if instruction is None:
        raise OpError(f"no instruction at {address}; run disassemble_at or create_function first")

    # Ghidra 12 moved the SLEIGH assembler into ghidra.app.plugin.assembler with the
    # factory on Assemblers; older builds had Assembler.getAssembler. Try both.
    assembler = None
    try:
        from ghidra.app.plugin.assembler import Assemblers  # type: ignore

        assembler = Assemblers.getAssembler(program)
    except ImportError:
        try:
            from ghidra.app.assembler import Assembler  # type: ignore

            assembler = Assembler.getAssembler(program)
        except ImportError:
            pass
    if assembler is None:
        raise OpError("no assembler factory in this Ghidra build (ghidra.app.plugin.assembler.Assemblers missing)")
    mnemonic = str(instruction.getMnemonicString()).upper()
    length = int(instruction.getLength())
    nop_hex = "90" * length
    suggestions: list[dict[str, Any]] = []

    def encode(assembly: str) -> tuple[str, int] | None:
        try:
            assembled = assembler.assembleLine(address, assembly)
        except Exception:
            return None
        if assembled is None:
            return None
        raw = bytes(assembled)
        if len(raw) > length:
            return None  # does not fit: candidate rejected, not silently truncated
        padded = raw + b"\x90" * (length - len(raw))
        return (padded.hex(), len(raw))

    flow_target = None
    flow_refs = instruction.getFlows()
    if flow_refs:
        flow_target = str(flow_refs[0])

    if mnemonic in _JCC_MNEMONICS and flow_target:
        for label, assembly in (
            (f"always taken: JMP {flow_target}", f"JMP 0x{flow_target}"),
            (f"never taken: NOP x{length}", None),
        ):
            if assembly is None:
                suggestions.append({
                    "kind": "force_not_taken",
                    "description": "neutralise the branch: fill with NOPs (the fall-through path wins)",
                    "address": str(address),
                    "hex_bytes": nop_hex,
                    "length": length,
                })
                continue
            encoded = encode(assembly)
            if encoded:
                suggestions.append({
                    "kind": "force_taken",
                    "description": label,
                    "address": str(address),
                    "hex_bytes": encoded[0],
                    "length": encoded[1],
                })
            # inverted branch: same length as the original by construction
            inverted = {"JZ": "JNZ", "JE": "JNE", "JNZ": "JZ", "JNE": "JE"}.get(mnemonic)
            if inverted and flow_target:
                encoded_inv = encode(f"{inverted} 0x{flow_target}")
                if encoded_inv:
                    suggestions.append({
                        "kind": "invert",
                        "description": f"invert branch: {mnemonic} -> {inverted}",
                        "address": str(address),
                        "hex_bytes": encoded_inv[0],
                        "length": encoded_inv[1],
                    })
    elif mnemonic in ("CMP", "TEST"):
        # neutralise the comparison that feeds a following branch
        suggestions.append({
            "kind": "neutralise_compare",
            "description": f"{mnemonic} at the gate: NOP it and the following jcc follows flags from earlier code - usually wrong; prefer patching the jcc itself",
            "address": str(address),
            "hex_bytes": nop_hex,
            "length": length,
        })
        next_address = address.add(length)
        nxt = listing.getInstructionAt(next_address)
        if nxt is not None and str(nxt.getMnemonicString()).upper() in _JCC_MNEMONICS:
            suggestions.append({
                "kind": "patch_follower",
                "description": "the branch after this compare is the real gate - see its own suggestions",
                "address": str(next_address),
                "hex_bytes": None,
                "length": int(nxt.getLength()),
            })
    elif mnemonic in ("CALL",):
        # a check function returning bool: force the return value after the call
        suggestions.append({
            "kind": "skip_call",
            "description": "skip the call: NOP it (x64: also make sure RAX is preloaded if the caller reads it)",
            "address": str(address),
            "hex_bytes": nop_hex,
            "length": length,
        })
    elif mnemonic in ("MOV", "XOR"):
        suggestions.append({
            "kind": "note",
            "description": "data-flow instruction - patch the branch it feeds, not this",
        })
    else:
        suggestions.append({
            "kind": "generic_nop",
            "description": f"{mnemonic}: neutralise with NOPs (verify the fall-through is sensible first)",
            "address": str(address),
            "hex_bytes": nop_hex,
            "length": length,
        })

    return {
        "program": entry.key,
        "address": str(address),
        "instruction": str(instruction),
        "mnemonic": mnemonic,
        "length": length,
        "suggestions": suggestions,
        "note": "apply with patch_bytes(hex_bytes=...); every encoding was assembled for this exact address",
    }


def _function_signature_bytes(program: Any, function: Any, prefix: int = 48) -> bytes:
    """First N instruction bytes of a function body - the fingerprint for matching."""
    import jpype  # type: ignore

    listing = program.getListing()
    memory = program.getMemory()
    address = function.getEntryPoint()
    out = bytearray()
    while len(out) < prefix:
        try:
            instruction = listing.getInstructionAt(address)
            if instruction is None:
                break
            length = int(instruction.getLength())
            # Ghidra's Memory fills a caller-provided buffer (getBytes(Address, byte[])).
            buffer = jpype.JArray(jpype.JByte)(length)
            memory.getBytes(address, buffer)
            out.extend(bytes(buffer))
            address = address.add(length)
        except Exception:
            break
    return bytes(out)


@op("function_map")
def function_map(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Match functions between two analysed builds by code signature.

    The Anitype 159->160 workflow: the new build shifted everything, but most function
    bodies survived byte-identical. This hashes each function's first instruction bytes
    in build A and finds its twin in build B - exact prefix match plus similar size
    means the analysis, names, and comments carry over. Requires both programs to be
    imported (open_binary) and analysed.
    """
    entry_a = session.resolve(params)
    program_b_key = params.get("program_b")
    if not program_b_key:
        raise OpError("pass program_b: the second build's project key (see list_programs)")
    entry_b = session.open_program(str(program_b_key))
    program_a, program_b = entry_a.program, entry_b.program

    prefix = clamp(params.get("prefix"), 8, 256, 48)
    min_size = clamp(params.get("min_size"), 0, 10**9, 0)

    progress(stage="index_b")
    index_b: dict[bytes, list[Any]] = {}
    sizes_b: dict[str, int] = {}
    for function in program_b.getFunctionManager().getFunctions(True):
        session.check_cancel()
        if function.isExternal() or function.isThunk():
            continue
        if int(function.getBody().getNumAddresses()) < min_size:
            continue
        sig = _function_signature_bytes(program_b, function, prefix)
        if len(sig) < prefix // 2:
            continue
        index_b.setdefault(sig, []).append(function)
        sizes_b[str(function.getEntryPoint())] = int(function.getBody().getNumAddresses())

    progress(stage="match_a")
    matched, unmatched = [], 0
    for function in program_a.getFunctionManager().getFunctions(True):
        session.check_cancel()
        if function.isExternal() or function.isThunk():
            continue
        size_a = int(function.getBody().getNumAddresses())
        if size_a < min_size:
            continue
        sig = _function_signature_bytes(program_a, function, prefix)
        if len(sig) < prefix // 2:
            continue
        candidates = index_b.get(sig, [])
        if not candidates:
            unmatched += 1
            continue
        best = min(candidates, key=lambda f: abs(int(f.getBody().getNumAddresses()) - size_a))
        size_b = sizes_b[str(best.getEntryPoint())]
        confidence = "exact" if size_a == size_b else "prefix"
        matched.append({
            "a_address": str(function.getEntryPoint()),
            "a_name": str(function.getName()),
            "b_address": str(best.getEntryPoint()),
            "b_name": str(best.getName()),
            "size_a": size_a,
            "size_b": size_b,
            "confidence": confidence,
        })

    return {
        "program_a": entry_a.key,
        "program_b": entry_b.key,
        "matched": len(matched),
        "unmatched_in_a": unmatched,
        "functions_b_indexed": sum(len(v) for v in index_b.values()),
        "pairs": matched[:clamp(params.get("limit"), 1, 5000, 200)],
        "truncated": len(matched) > clamp(params.get("limit"), 1, 5000, 200),
        "note": "confidence=exact means identical prefix and size; rename B's functions from A in bulk with a script",
    }
