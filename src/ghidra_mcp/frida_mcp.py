"""Frida integration: spawn/attach sessions, runtime JS, module/export enumeration,
memory read/write, and export interceptor hooks. ``frida`` is imported lazily, so the
server boots fine without it; every function reports a clean error telling you how to
get it (``pip install frida``), which the installer now does by default.

A session registry keyed by pid is kept in this module: JS hooks installed by
``hook`` stay live between tool calls and their intercepted events accumulate until
read with ``events``. The MCP server is single-threaded, so a plain dict is safe.
"""

from __future__ import annotations

import importlib
import time
from typing import Any

_MIN_FRIDA = "21.0.0"


def _frida() -> tuple[bool, Any, str | None]:
    """Return (ok, module_or_None, error_or_None)."""
    try:
        frida_mod = importlib.import_module("frida")
        version = getattr(frida_mod, "__version__", None) or (frida_mod._version if hasattr(frida_mod, "_version") else None)
        return True, frida_mod, None
    except ImportError as exc:
        return False, None, f"frida is not installed in this server (pip install 'frida>={_MIN_FRIDA}'); the CTPAX installer adds it"
    except Exception as exc:
        return False, None, f"{type(exc).__name__}: {exc}"


def _min_version_ok(version: str | None) -> bool:
    if not version:
        return True
    try:
        parts = [int(p) for p in str(version).split(".")[:2]]
        want = [int(p) for p in _MIN_FRIDA.split(".")[:2]]
        return parts >= want
    except ValueError:
        return True


def status() -> dict[str, Any]:
    """Frida availability, local device, and the current session registry."""
    ok, frida_mod, error = _frida()
    if not ok:
        return {"available": False, "missing": True, "hint": error}
    if not _min_version_ok(getattr(frida_mod, "__version__", None)):
        return {
            "available": False,
            "missing": False,
            "hint": f"frida {getattr(frida_mod, '__version__', None)} is too old; pip install 'frida>={_MIN_FRIDA}'",
        }
    device = None
    try:
        device = frida_mod.get_local_device()
    except Exception as exc:
        device_error = f"{type(exc).__name__}: {exc}"
    sessions = []
    for pid, entry in list(_HUB.items()):
        sessions.append({"pid": pid, "spawned": entry.get("spawned", False), "scripts": len(entry.get("scripts", []))})
    return {
        "available": True,
        "version": getattr(frida_mod, "__version__", None),
        "device": device and getattr(device, "name", None),
        "device_id": device and getattr(device, "id", None) if device else None,
        "active_sessions": sessions,
        "note": "frida attach needs the target not to be self-debugging; anti-debug targets may resist",
    }


_HUB: dict[int, dict[str, Any]] = {}
_DEVICE = None


def _device(frida_mod: Any) -> Any:
    global _DEVICE
    if _DEVICE is None:
        _DEVICE = frida_mod.get_local_device()
    return _DEVICE


def _require_session(pid: int) -> dict[str, Any]:
    entry = _HUB.get(pid)
    if entry is None:
        return {"error": f"no Frida session for pid {pid}; call spawn or attach first"}
    return {"ok": entry}


def _handler(pid: int):
    def on_message(message: dict, data: bytes | None) -> None:
        entry = _HUB.get(pid)
        if entry is None:
            return
        item = dict(message) if isinstance(message, dict) else {"type": "message", "payload": str(message)}
        if data:
            item["payload_hex"] = data.hex()
        entry.setdefault("messages", []).append(item)
    return on_message


def ps(pattern: str | None = None) -> dict[str, Any]:
    """List local processes as Frida sees them (pid + name)."""
    ok, frida_mod, error = _frida()
    if not ok:
        return {"error": error}
    try:
        processes = _device(frida_mod).enumerate_processes()
    except Exception as exc:
        return {"error": f"could not enumerate processes: {type(exc).__name__}: {exc}"}
    rows = [{"pid": p.pid, "name": p.name, "parameters": getattr(p, "parameters", None)} for p in processes]
    if pattern:
        needle = pattern.lower()
        rows = [r for r in rows if needle in r["name"].lower()]
    return {"count": len(rows), "processes": rows[:500], "note": "same list frida-ps shows; attach to one to instrument it"}


def attach(pid: int) -> dict[str, Any]:
    """Attach to a running process and keep the session for later calls."""
    ok, frida_mod, error = _frida()
    if not ok:
        return {"error": error}
    if pid in _HUB:
        return {"attached": True, "pid": pid, "reused": True}
    try:
        session = _device(frida_mod).attach(pid)
    except Exception as exc:
        return {"error": f"attach failed: {type(exc).__name__}: {exc}", "hint": "run elevated, or the target may block debugging (anti-debug)"}
    _HUB[pid] = {"session": session, "spawned": False, "messages": [], "scripts": []}
    return {"attached": True, "pid": pid, "reused": False, "note": "use run/hook to execute JS, detach to release"}


def spawn(path: str, arguments: str = "", *, resume: bool = False) -> dict[str, Any]:
    """Spawn a program under Frida (suspended), attach, and optionally resume it."""
    ok, frida_mod, error = _frida()
    if not ok:
        return {"error": error}
    argv = [path] + (arguments.split(" ") if arguments else [])
    try:
        pid = _device(frida_mod).spawn(argv)
        session = _device(frida_mod).attach(pid)
    except Exception as exc:
        return {"error": f"spawn failed: {type(exc).__name__}: {exc}"}
    _HUB[pid] = {"session": session, "spawned": True, "messages": [], "scripts": []}
    result: dict[str, Any] = {"spawned": True, "pid": pid, "suspended": not resume}
    if resume:
        try:
            _device(frida_mod).resume(pid)
            result["resumed"] = True
        except Exception as exc:
            result["resume_error"] = f"{type(exc).__name__}: {exc}"
    result["note"] = "set hooks with run/hook BEFORE resuming to catch startup code"
    return result


def resume(pid: int) -> dict[str, Any]:
    """Resume a spawned (suspended) process."""
    entry = _HUB.get(pid)
    if entry is None:
        return {"error": f"no session for pid {pid}"}
    try:
        _device_by_entry(entry).resume(pid)
    except Exception as exc:
        return {"error": f"resume failed: {type(exc).__name__}: {exc}"}
    return {"resumed": True, "pid": pid}


def _device_by_entry(entry: dict[str, Any]) -> Any:
    ok, frida_mod, _ = _frida()
    return _device(frida_mod)


def detach(pid: int) -> dict[str, Any]:
    """Detach from a process; JS agents and hooks go with it."""
    entry = _HUB.get(pid)
    if entry is None:
        return {"error": f"no session for pid {pid}"}
    try:
        entry["session"].detach()
    except Exception as exc:
        return {"error": f"detach failed: {type(exc).__name__}: {exc}"}
    _HUB.pop(pid, None)
    return {"detached": True, "pid": pid}


def kill(pid: int) -> dict[str, Any]:
    """Kill the target process via the device (terminates spawned children too)."""
    ok, frida_mod, error = _frida()
    if not ok:
        return {"error": error}
    try:
        _device(frida_mod).kill(pid)
    except Exception as exc:
        return {"error": f"kill failed: {type(exc).__name__}: {exc}"}
    _HUB.pop(pid, None)
    return {"killed": True, "pid": pid}


def run(pid: int, javascript: str, *, wait: float = 3.0) -> dict[str, Any]:
    """Load arbitrary JavaScript into a session; messages from send() come back."""
    entry = _HUB.get(pid)
    if entry is None:
        return {"error": f"no session for pid {pid}; spawn or attach first"}
    before = len(entry.get("messages", []))
    try:
        script = entry["session"].create_script(javascript)
        script.on("message", _handler(pid))
        script.load()
    except Exception as exc:
        return {"error": f"script failed: {type(exc).__name__}: {exc}"}
    entry.setdefault("scripts", []).append(script)
    settle = time.time() + max(0.1, wait)
    time.sleep(0.15)
    # drain as long as new messages keep arriving, until the settle deadline
    while time.time() < settle:
        time.sleep(min(0.4, max(0.05, settle - time.time())))
        if len(entry.get("messages", [])) == before:
            break
        settle = time.time() + max(0.1, wait)
    new_messages = entry.get("messages", [])[before:]
    return {
        "pid": pid,
        "messages": new_messages,
        "message_count": len(new_messages),
        "script_alive": True,
        "note": "the script stays loaded; events() reads and clears its accumulated output",
    }


def events(pid: int, *, clear: bool = True) -> dict[str, Any]:
    """Read (and clear) messages accumulated by hooks and scripts since last call."""
    entry = _HUB.get(pid)
    if entry is None:
        return {"error": f"no session for pid {pid}"}
    messages = entry.get("messages", [])
    if clear:
        entry["messages"] = []
    return {"pid": pid, "events": messages, "count": len(messages)}


def modules(pid: int, *, filter: str | None = None) -> dict[str, Any]:
    """Modules loaded in the target (name, base, size, path)."""
    entry = _HUB.get(pid)
    if entry is None:
        return {"error": f"no session for pid {pid}"}
    needle = (filter or "").lower()
    try:
        listed = entry["session"].list_modules()
    except Exception as exc:
        return {"error": f"list_modules failed: {type(exc).__name__}: {exc}"}
    rows = []
    for m in listed:
        if needle and needle not in str(m.name).lower():
            continue
        rows.append(
            {
                "name": str(m.name),
                "base_address": hex(int(m.base_address)),
                "path": str(m.path),
                "size": int(m.size) if getattr(m, "size", None) else None,
            }
        )
    return {"pid": pid, "module_count": len(rows), "modules": rows[:400]}


def exports(pid: int, module: str) -> dict[str, Any]:
    """Exports (symbols) of one module - the hookable surface."""
    entry = _HUB.get(pid)
    if entry is None:
        return {"error": f"no session for pid {pid}"}
    target = None
    for m in entry["session"].list_modules():
        if str(m.name).lower() == module.lower() or module in str(m.name):
            target = m
            break
    if target is None:
        return {"error": f"module {module!r} not loaded", "loaded_modules": [str(m.name) for m in entry["session"].list_modules()][:50]}
    try:
        exported = target.enumerate_exports()
    except Exception as exc:
        return {"error": f"enumerate_exports failed: {type(exc).__name__}: {exc}"}
    rows = [{"name": str(e.name), "address": hex(int(e.address)), "type": str(e.type)} for e in exported]
    return {"pid": pid, "module": str(target.name), "export_count": len(rows), "exports": rows[:500]}


def mem_read(pid: int, address: str, size: int = 64) -> dict[str, Any]:
    """Read bytes from the target's address space via the session."""
    entry = _HUB.get(pid)
    if entry is None:
        return {"error": f"no session for pid {pid}"}
    try:
        target = int(str(address), 0)
        blob = entry["session"].read_bytes(target, size)
    except Exception as exc:
        return {"error": f"read failed: {type(exc).__name__}: {exc}"}
    return {"pid": pid, "address": hex(target), "size": len(blob), "hex": blob.hex(" "), "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in blob)}


def mem_write(pid: int, address: str, hex_data: str) -> dict[str, Any]:
    """Write bytes into the target; code pages are writable through the agent."""
    entry = _HUB.get(pid)
    if entry is None:
        return {"error": f"no session for pid {pid}"}
    try:
        target = int(str(address), 0)
        blob = bytes.fromhex(hex_data.replace(" ", ""))
    except ValueError:
        return {"error": "hex_data must be an even-length hex string"}
    try:
        entry["session"].write_bytes(target, blob)
    except Exception as exc:
        return {"error": f"write failed: {type(exc).__name__}: {exc}"}
    return {"pid": pid, "address": hex(target), "written": len(blob)}


def hook(pid: int, module: str, export: str, *, wait: float = 5.0, extra_javascript: str = "") -> dict[str, Any]:
    """Intercept an exported function; arguments and return land in ``events``.

    The interceptor stays live until the session is detached. Reports both the
    immediate install result and, when ``wait`` > 0, any events already observed.
    """
    js = f"""
rpc.exports = {{}};
(function () {{
  var target = Module.getExportByName("{module}", "{export}");
  Interceptor.attach(target, {{
    onEnter: function (args) {{
      send({{ event: "enter", export: "{export}", args: Array.prototype.slice.call(args, 0, 8).map(function (a) {{ return "0x" + a.toString(16); }}) }});
    }},
    onLeave: function (retval) {{
      send({{ event: "leave", export: "{export}", retval: "0x" + retval.toString(16) }});
    }}
  }});
  send({{ event: "hooked", export: "{export}", address: target.toString() }});
}})();
""".strip()
    if extra_javascript.strip():
        js += "\n" + extra_javascript.strip()
    result = run(pid, js, wait=min(1.0, wait))
    installed = next((m for m in result.get("messages", []) if m.get("payload", {}).get("event") == "hooked"), None)
    if installed is None and wait > 1.0:
        time.sleep(max(0.0, wait - 1.0))
    return {
        **result,
        "hooked": installed is not None,
        "hook_address": installed.get("payload", {}).get("address") if installed else None,
        "note": "the hook is active until detach; read following calls with events(pid)",
    }