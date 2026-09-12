"""Full-Ghidra-API access: an in-process Python eval bridge and a live API browser.

The typed operations cover the daily workflow; these two operations are the 100% path:
``eval_python`` runs arbitrary Python inside the live worker process where
``currentProgram`` is bound to the open program, so every Ghidra class - analysis,
decompiler internals, type management, scripting API - is reachable directly.
``api_explore`` answers "what can I call": class listings, method signatures, and
docstrings resolved through JPype against the loaded Ghidra installation, so the model
can discover the exact call before writing the eval.
"""

from __future__ import annotations

import io
import json
import re
import time
import traceback
from contextlib import redirect_stdout
from typing import Any, Callable

from ghidra_mcp.ghidra_ops import OpError, Session, op

# Importing these from ops_code creates a cycle (ops_code -> ghidra_ops -> ops_power),
# so the two helpers are duplicated here on purpose; they are tiny and stable.
from ghidra_mcp.ghidra_ops import clamp as _shared_clamp, parse_address as _shared_parse_address

clamp = _shared_clamp
parse_address = _shared_parse_address

# --------------------------------------------------------------------------
# eval_python: arbitrary code against the live program
# --------------------------------------------------------------------------
_EVAL_NAMESPACE_EXTRA = {
    "__name__": "ghidra_eval",
    "__builtins__": __builtins__,
}


@op("eval_python")
def eval_python(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Execute Python code in the live worker with full Ghidra API access.

    Bindings: ``currentProgram`` (the open program), ``currentAddress`` (the entry of
    the 'program'/'address' params), ``flat`` (FlatProgramAPI), ``decompiler`` (a ready
    DecompInterface), ``fm`` (FunctionManager), ``st`` (SymbolTable), ``listing``,
    ``memory``, ``monitor``. Values that survive are returned as JSON; anything else
    comes back as its repr. Use for anything the typed operations do not cover - bulk
    analysis passes, decompiler internals, custom data-flow - the whole Ghidra API.
    """
    code = params.get("code")
    if not code or not str(code).strip():
        raise OpError("pass 'code' - Python executed in-process against the open program")

    entry = session.resolve(params)
    program = entry.program

    from ghidra.app.decompiler import DecompInterface  # type: ignore
    from ghidra.program.flatapi import FlatProgramAPI  # type: ignore

    decompiler = DecompInterface()
    decompiler.openProgram(program)

    namespace: dict[str, Any] = {
        **_EVAL_NAMESPACE_EXTRA,
        "currentProgram": program,
        "currentAddress": parse_address(program, params.get("address")) if params.get("address") else program.getMinAddress(),
        "flat": FlatProgramAPI(program),
        "decompiler": decompiler,
        "fm": program.getFunctionManager(),
        "st": program.getSymbolTable(),
        "listing": program.getListing(),
        "memory": program.getMemory(),
        "monitor": session.monitor(),
        "jt": _java_types_helper(),
    }
    stdout_buffer = io.StringIO()
    started = time.time()
    try:
        with redirect_stdout(stdout_buffer):
            try:
                result = eval(str(code), namespace)  # expressions: a = 1+2, fm.getFunctionCount()
            except SyntaxError:
                # Statements and multi-line blocks: exec the compiled form instead.
                block = compile(str(code), "<ghidra_eval>", "exec")
                result = exec(block, namespace)  # noqa: S102 - the whole point of the tool
    except Exception:
        raise OpError(
            "eval failed:\n"
            + traceback.format_exc(limit=6)
            + "\nUse api_explore(class_name) to check the exact method names before retrying."
        )
    finally:
        try:
            decompiler.dispose()
        except Exception:
            pass

    # Variables the code defined come back under 'locals' - that is how multi-step
    # explorations hand results back.
    interesting = {}
    for key, value in namespace.items():
        if key in _EVAL_NAMESPACE_EXTRA or key in {
            "currentProgram", "currentAddress", "flat", "decompiler", "fm", "st", "listing", "memory", "monitor", "jt",
        }:
            continue
        if key.startswith("__"):
            continue
        interesting[key] = _jsonify(value)

    return {
        "program": entry.key,
        "elapsed": round(time.time() - started, 1),
        "result": _jsonify(result),
        "stdout": stdout_buffer.getvalue()[-4000:],
        "locals": interesting,
    }


def _jsonify(value: Any, depth: int = 0) -> Any:
    """Best-effort JSON conversion; Java objects fall back to useful reprs."""
    if depth > 4:
        return "..."
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(k): _jsonify(v, depth + 1) for k, v in list(value.items())[:50]}
    if isinstance(value, (list, tuple, set)):
        return [_jsonify(v, depth + 1) for v in list(value)[:100]]
    # Java iterables and collections
    if hasattr(value, "__iter__"):
        try:
            return [_jsonify(v, depth + 1) for v in list(value)[:100]]
        except Exception:
            pass
    if hasattr(value, "size") and callable(getattr(value, "size")):
        try:
            count = int(value.size())
            if count > 100:
                return {"size": count, "note": "truncated; slice it in eval_python"}
            return [_jsonify(value[i], depth + 1) for i in range(count)]
        except Exception:
            pass
    jstring = getattr(value, "toString", None)
    if callable(jstring):
        try:
            text = str(jstring())
            return text[:2000]
        except Exception:
            pass
    return repr(value)[:2000]


# --------------------------------------------------------------------------
# api_explore: discover the Ghidra API from the live JVM
# --------------------------------------------------------------------------
@op("api_explore")
def api_explore(session: Session, params: dict[str, Any], progress: Callable[..., None]) -> dict[str, Any]:
    """Browse the Ghidra Java API from the live JVM: classes, methods, signatures.

    Modes: ``search`` (find classes by name regex across ghidra.* packages), ``members``
    (list one class's methods with full signatures - statics flagged), ``doc`` (the
    class docstring plus one method's signature). Answers 'which method do I call for
    X' before writing an eval_python snippet.
    """
    query = str(params.get("query") or "")
    mode = str(params.get("mode") or ("members" if query and "." not in query and not query.startswith("ghidra") else "search"))
    limit = clamp(params.get("limit"), 1, 100, 30)

    import jpype  # type: ignore

    if not jpype.isJVMStarted():
        raise OpError("the JVM is not running; start a Ghidra session first")

    if mode == "search":
        return _api_search(query, limit)
    if mode == "members":
        return _api_members(query, limit)
    if mode == "doc":
        return _api_doc(query)
    raise OpError(f"unknown mode {mode!r}; use search, members, or doc")


def _api_search(query: str, limit: int) -> dict[str, Any]:
    import jpype  # type: ignore

    if not query:
        query = "ghidra"
    pattern = re.compile(query, re.IGNORECASE)
    packages = ["ghidra", "generic", " docking", "resources", "db", "ghidra.app", "ghidra.program", "ghidra.util", "ghidra.script"]
    found = set()
    class_loader = jpype.java.ClassLoader.getSystemClassLoader()
    # Walk loaded classes (everything Ghidra has touched is already live here).
    for package in packages:
        try:
            pkg = jpype.java.lang.Package.getPackage(package.strip())
            if pkg is None:
                continue
        except Exception:
            continue
    # Package listing is unreliable; scan loaded classes instead.
    try:
        import pyghidra  # type: ignore

        # JPype keeps a registry of imported classes; walk Ghidra's own jars instead.
        from ghidra.framework import Application  # type: ignore

        install_dir = str(Application.getInstallationDirectory())
    except Exception:
        install_dir = None

    candidates: set[str] = set()
    if install_dir:
        jar_paths = _collect_class_names(install_dir, limit * 40)
        for class_name in jar_paths:
            if pattern.search(class_name):
                candidates.add(class_name)
                if len(candidates) >= limit:
                    break
    return {"mode": "search", "query": query, "count": len(candidates), "classes": sorted(candidates)}


def _collect_class_names(install_dir: str, max_names: int) -> list[str]:
    """Class names from Ghidra's jars, cached - the jars change once per install."""
    cache_key = f"_class_cache_{install_dir}"
    global _CLASS_CACHE
    cached = _CLASS_CACHE.get(install_dir)
    if cached is not None:
        return cached
    import zipfile
    from pathlib import Path

    names: list[str] = []
    root = Path(install_dir)
    jars = list(root.glob("Ghidra/**/lib/*.jar")) + list(root.glob("Ghidra/**/*.jar"))
    for jar in jars:
        try:
            with zipfile.ZipFile(jar) as bundle:
                for entry in bundle.namelist():
                    if entry.endswith(".class") and "$" not in entry:
                        names.append(entry[:-6].replace("/", "."))
                        if len(names) >= max_names:
                            break
        except Exception:
            continue
        if len(names) >= max_names:
            break
    _CLASS_CACHE[install_dir] = names
    return names


_CLASS_CACHE: dict[str, list[str]] = {}


def _load_class(class_name: str) -> Any:
    import jpype  # type: ignore

    try:
        return jpype.JClass(class_name)
    except Exception as exc:
        raise OpError(f"cannot load {class_name}: {exc}. Use mode=search to find the right fully-qualified name.")


def _api_members(class_name: str, limit: int) -> dict[str, Any]:
    java_class = _load_class(class_name)
    import jpype  # type: ignore

    methods = []
    for method in java_class.class_.getDeclaredMethods():
        modifiers = int(method.getModifiers())
        static = bool(modifiers & 0x0008)
        params = []
        for parameter in method.getParameterTypes():
            params.append(str(parameter).rsplit(".", 1)[-1])
        methods.append({
            "name": str(method.getName()),
            "static": static,
            "returns": str(method.getReturnType()).rsplit(".", 1)[-1],
            "params": params,
            "signature": f"{method.getName()}({', '.join(params)}) -> {str(method.getReturnType()).rsplit('.', 1)[-1]}",
        })
    methods.sort(key=lambda m: (not m["static"], m["name"]))
    fields = []
    for field in java_class.class_.getDeclaredFields():
        modifiers = int(field.getModifiers())
        fields.append({
            "name": str(field.getName()),
            "static": bool(modifiers & 0x0008),
            "type": str(field.getType()).rsplit(".", 1)[-1],
        })
    return {
        "mode": "members",
        "class": class_name,
        "method_count": len(methods),
        "methods": methods[:limit],
        "fields": fields[:limit],
        "superclass": str(java_class.class_.getSuperclass()) if java_class.class_.getSuperclass() else None,
        "note": "call via eval_python: from ghidra.x import Y; or jpype.JClass('ghidra.x.Y')",
    }


def _api_doc(class_name: str) -> dict[str, Any]:
    java_class = _load_class(class_name)
    import jpype  # type: ignore

    return {
        "mode": "doc",
        "class": class_name,
        "package": str(java_class.class_.getPackage()) if java_class.class_.getPackage() else None,
        "is_abstract": bool(java_class.class_.getModifiers() & 0x0400),
        "is_interface": java_class.class_.isInterface(),
        "constructors": [
            str(c) for c in java_class.class_.getConstructors()
        ][:10],
        "hint": "mode=members lists the methods; the Ghidra docs at ghidra.re help for semantics",
    }


def _java_types_helper() -> Any:
    """A small helper object exposed inside eval_python for Java type plumbing."""
    import jpype  # type: ignore

    class _JTypes:
        JByte = jpype.JByte
        JArray = jpype.JArray
        JInt = jpype.JInt
        JLong = jpype.JLong
        JString = jpype.JString

        @staticmethod
        def jclass(name: str) -> Any:
            return jpype.JClass(name)

    return _JTypes
