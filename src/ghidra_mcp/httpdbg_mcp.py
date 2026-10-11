"""HTTP Debugger (httpdebugger.com) integration: GUI control for launch and
capture start/stop, plus an MCP bridge to the official HTTPDebuggerMcp.exe
which speaks JSON-RPC to expose all 8 HTTP Debugger tools to the MCP server.

``httpdbg_mcp`` is imported lazily where used, so the server boots cleanly
without HTTP Debugger installed. Every function reports what is missing and
how to get it, following the same pattern as frida_mcp / managed.

The official MCP bridge (HTTPDebuggerMcp.exe) ships inside the HTTP Debugger
install and must be enabled once via the GUI:
  1. Launch HTTP Debugger (httpdbg_launch).
  2. Settings -> MCP Server -> check "Enable MCP Server".
  3. The status bar indicator must read "MCP: ON".

After that the bridge serves the 8 captured-traffic tools over stdio JSON-RPC.
If the bridge isn't available, capture_start/capture_stop fall back to driving
the GUI window (httpdbg_* tools are not exposed via the fallback), and a COM
log-parsing fallback reads HTTPDebugger.Api log folders directly.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

_MCP_TOOLS = [
    "get_capture_status",
    "diagnose_capture",
    "list_endpoints",
    "list_transactions",
    "search_transactions",
    "get_transaction",
    "get_session_stats",
    "export_as_curl",
]

_HTTPS_API_METHODS = {
    "get_capture_status": {"method": "get_capture_status", "params": {}},
    "diagnose_capture": {"method": "diagnose_capture", "params": {}},
    "list_endpoints": {"method": "list_endpoints", "params": {"page": 0, "page_size": 100}},
    "list_transactions": {"method": "list_transactions", "params": {"session_id": None, "page": 0, "page_size": 100}},
    "search_transactions": {"method": "search_transactions", "params": {"query": "", "page": 0, "page_size": 50}},
    "get_transaction": {"method": "get_transaction", "params": {"transaction_id": None}},
    "get_session_stats": {"method": "get_session_stats", "params": {"session_id": None}},
    "export_as_curl": {"method": "export_as_curl", "params": {"transaction_id": None, "format": "curl"}},
}

# 32-bit only: the COM API and the GUI both run under x86 PowerShell via SysWOW64
_PS32 = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"


def _install_candidates() -> list[Path]:
    roots = []
    for base in (
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")),
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")),
    ):
        roots.append(base / "HTTP Debugger")
        roots.append(base / "HTTPDebugger")
        roots.append(base / "HTTP Debugger Pro")
        roots.append(base / "HTTPDebuggerPro")
    override = os.environ.get("HTTPDBG_HOME")
    if override:
        roots.insert(0, Path(override))
    return roots


def _mcp_exe() -> Path | None:
    """Locate HTTPDebuggerMcp.exe in any install candidate."""
    for root in _install_candidates():
        exe = root / "HTTPDebuggerMcp.exe"
        if exe.is_file():
            return exe
    return None


def _app_exe() -> Path | None:
    """Locate the HTTP Debugger GUI exe."""
    for root in _install_candidates():
        for name in ("HTTPDebuggerPro.exe", "HTTPDebugger.exe"):
            exe = root / name
            if exe.is_file():
                return exe
    return None


def _bridge_running() -> dict[str, Any]:
    """Is the MCP bridge process alive?"""
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq HTTPDebuggerMcp.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
        )
        if "HTTPDebuggerMcp.exe" in out.stdout:
            return {"running": True}
    except Exception:
        pass
    return {"running": False}


def _app_running() -> dict[str, Any]:
    """Is the HTTP Debugger GUI app alive?"""
    for name in ("HTTPDebuggerPro.exe", "HTTPDebugger.exe"):
        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
            )
            if name in out.stdout:
                return {"running": True, "process": name}
        except Exception:
            pass
    return {"running": False, "process": None}


def _enable_mcp_note() -> str:
    return (
        "One-time setup required: launch HTTP Debugger, then Settings -> MCP Server -> "
        "check 'Enable MCP Server'. The status bar indicator must read 'MCP: ON'. "
        "Then call httpdbg_mcp_get_session to establish the JSON-RPC channel."
    )


def status() -> dict[str, Any]:
    """HTTP Debugger availability: install location, MCP bridge, GUI, language."""
    app = _app_exe()
    mcp = _mcp_exe()
    install_dir = str(app.parent) if app else None
    bridge_running = _bridge_running()["running"] if mcp else False
    channel = _channel()
    session: dict[str, Any] = {"connected": channel is not None}
    if channel is not None:
        session["protocol"] = channel.mode
        if channel.protocol_version:
            session["protocol_version"] = channel.protocol_version
        session["pid"] = channel.handle.pid
    return {
        "installed": app is not None or mcp is not None,
        "install_dir": install_dir,
        "app_exe": str(app) if app else None,
        "mcp_bridge": str(mcp) if mcp else None,
        "bridge_running": bridge_running,
        "bridge_session": session,
        "app_running": _app_running()["running"],
        "mcp_tools": _MCP_TOOLS,
        "note": _enable_mcp_note() if mcp and not bridge_running else (
            "installed and MCP bridge enabled" if (mcp and bridge_running) else
            "HTTP Debugger not installed; download the MSI from https://www.httpdebugger.com/downloads/HTTPDebuggerPro.msi"
        ),
    }


def launch() -> dict[str, Any]:
    """Launch the HTTP Debugger GUI (downloads nothing; just starts the app)."""
    app = _app_exe()
    if not app:
        return {"error": "HTTP Debugger not installed", "hint": "download the MSI from https://www.httpdebugger.com/downloads/HTTPDebuggerPro.msi"}
    if _app_running()["running"]:
        return {"launched": False, "already_running": True, "exe": str(app)}
    try:
        subprocess.Popen([str(app)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
    except Exception as exc:
        return {"error": f"launch failed: {type(exc).__name__}: {exc}", "exe": str(app)}
    running = _app_running()["running"]
    return {"launched": running, "exe": str(app), "note": "enable the MCP server in Settings -> MCP Server once"}


# ---------------------------------------------------------------------------
# MCP bridge: spawn HTTPDebuggerMcp.exe as a stdio JSON-RPC (MCP) peer
# ---------------------------------------------------------------------------
_BRIDGE: dict[str, Any] = {}
_WRITE_LOCK = threading.Lock()

class _BridgeChannel:
    """Channel to the bridge subprocess.

    A dedicated reader thread owns stdout, so a request waits on a condition with a
    deadline instead of blocking on readline() - a hung bridge must not hang the whole
    MCP server. The bridge is spoken to over the MCP protocol (initialize ->
    notifications/initialized -> tools/call / tools/list); when the handshake reports
    the method is unknown the channel degrades to the legacy raw per-tool JSON-RPC
    methods used by older bridge builds.
    """

    def __init__(self, handle: subprocess.Popen, exe: str) -> None:
        self.handle = handle
        self.exe = exe
        self.cond = threading.Condition()
        self.responses: dict[str, Any] = {}
        self.mode: str | None = None  # "mcp" | "legacy"
        self.protocol_version: str | None = None
        self.handshake_error: str | None = None
        threading.Thread(target=self._read_loop, name="httpdbg-bridge-reader", daemon=True).start()

    # -- reading -----------------------------------------------------------
    def _read_loop(self) -> None:
        stream = self.handle.stdout
        while True:
            try:
                raw = stream.readline()
            except (OSError, ValueError):
                break
            if not raw:
                break  # EOF: the bridge is gone
            line = raw.strip()
            if not line:
                continue
            if line.lower().startswith(b"content-length:"):
                # LSP-style framing (defensive: MCP itself uses plain newlines)
                body = self._read_frame(line)
                if body is None:
                    break
                data = body
            else:
                data = line
            try:
                msg = json.loads(data.decode("utf-8", "replace"))
            except Exception:
                continue
            self._dispatch(msg)
        with self.cond:
            self.cond.notify_all()  # wake every waiter so it sees the dead process

    def _read_frame(self, first: bytes) -> bytes | None:
        length = 0
        header = first
        while header:
            if header.lower().startswith(b"content-length:"):
                try:
                    length = int(header.split(b":", 1)[1].strip() or 0)
                except ValueError:
                    return None
            header = self.handle.stdout.readline()
            if not header:
                return None
            if header.strip() == b"":
                break
        body = b""
        while len(body) < length:
            try:
                chunk = self.handle.stdout.read(length - len(body))
            except (OSError, ValueError):
                return None
            if not chunk:
                return None
            body += chunk
        return body

    def _dispatch(self, msg: Any) -> None:
        if not isinstance(msg, dict):
            return
        if "id" in msg and "method" in msg:
            # server -> client request (roots/list, sampling/...): politely refuse so
            # the bridge does not wait on us forever
            self._send({
                "jsonrpc": "2.0",
                "id": msg["id"],
                "error": {"code": -32601, "message": "method not supported by this client"},
            })
            return
        if "id" in msg:
            with self.cond:
                self.responses[str(msg["id"])] = msg
                self.cond.notify_all()
            return
        # notifications (progress, logging, list_changed): nothing to do

    # -- writing -----------------------------------------------------------
    def _send(self, payload: dict[str, Any]) -> str | None:
        if self.handle.poll() is not None:
            return "bridge process has exited"
        try:
            with _WRITE_LOCK:
                self.handle.stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
                self.handle.stdin.flush()
            return None
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"

    def alive(self) -> bool:
        return self.handle.poll() is None

    def request(self, method: str, params: dict[str, Any] | None = None, *, timeout: float = 15.0) -> dict[str, Any]:
        rid = str(uuid.uuid4())
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            payload["params"] = params
        error = self._send(payload)
        if error:
            return {"error": f"bridge write failed: {error}"}
        deadline = time.time() + timeout
        with self.cond:
            while rid not in self.responses:
                if self.handle.poll() is not None:
                    return {"error": "bridge exited unexpectedly; call httpdbg_mcp_get_session to restart it"}
                remaining = deadline - time.time()
                if remaining <= 0:
                    return {"error": f"timeout waiting for '{method}' response from the MCP bridge"}
                self.cond.wait(min(remaining, 0.25))
            return self.responses.pop(rid)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> str | None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        return self._send(payload)

    def close(self) -> None:
        try:
            self.handle.stdin.close()
        except Exception:
            pass
        try:
            if self.handle.poll() is None:
                self.handle.terminate()
            self.handle.wait(timeout=3)  # reap it: no zombie, no ResourceWarning
        except Exception:
            pass
        try:
            self.handle.stdout.close()
        except Exception:
            pass


def _channel() -> _BridgeChannel | None:
    channel = _BRIDGE.get("channel")
    if isinstance(channel, _BridgeChannel) and channel.alive():
        return channel
    return None


def _handshake(channel: _BridgeChannel, timeout: float) -> dict[str, Any]:
    """Negotiate MCP with the bridge; fall back to legacy raw methods if it refuses."""
    resp = channel.request(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "ghidra-mcp", "version": "httpdbg-bridge"},
        },
        timeout=timeout,
    )
    result = resp.get("result")
    if isinstance(result, dict):
        channel.mode = "mcp"
        channel.protocol_version = result.get("protocolVersion")
        channel.notify("notifications/initialized")
        return {"handshake": "mcp", "protocol_version": channel.protocol_version}
    channel.mode = "legacy"
    error = resp.get("error")
    channel.handshake_error = json.dumps(error, ensure_ascii=False, default=str) if error else str(resp)
    return {"handshake": "legacy", "note": "bridge refused the MCP handshake; using raw JSON-RPC methods"}


def _spawn_bridge(timeout: float = 8.0, command: list[str] | None = None) -> dict[str, Any]:
    """Start HTTPDebuggerMcp.exe (or an explicit command) and open the channel."""
    existing = _channel()
    if existing is not None:
        return {"already_running": True, "pid": existing.handle.pid, "mode": existing.mode}
    stale = _BRIDGE.pop("channel", None)
    if isinstance(stale, _BridgeChannel):
        stale.close()
    _BRIDGE.pop("handle", None)
    if command is None:
        exe = _mcp_exe()
        if not exe:
            return {"error": "HTTPDebuggerMcp.exe not found", "hint": _enable_mcp_note()}
        command = [str(exe)]
    try:
        handle = subprocess.Popen(
            list(command),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            bufsize=0,
        )
    except Exception as exc:
        return {"error": f"failed to spawn bridge: {type(exc).__name__}: {exc}"}
    channel = _BridgeChannel(handle, command[0])
    _BRIDGE["channel"] = channel
    _BRIDGE["handle"] = handle  # kept for backwards compatibility
    _BRIDGE["started_at"] = time.time()
    info = _handshake(channel, timeout)
    if not channel.alive() and channel.mode != "legacy":
        return {"error": "bridge exited during the handshake", **info}
    return {"started": True, "pid": handle.pid, **info}


def get_session() -> dict[str, Any]:
    """Open the MCP bridge channel. Required once before the captured-traffic tools."""
    info = _spawn_bridge()
    if info.get("error"):
        return info
    channel = _channel()
    payload: dict[str, Any] = {
        "connected": True,
        "pid": info.get("pid"),
        "protocol": channel.mode if channel else None,
        "tools": _MCP_TOOLS,
        "tool_count": len(_MCP_TOOLS),
        "hint": (
            "call httpdbg_mcp_list_tools to see the bridge's full tool set, then "
            "httpdbg_mcp_call(tool, params) for any of them"
            if not info.get("already_running")
            else "bridge already connected"
        ),
    }
    if channel and channel.protocol_version:
        payload["protocol_version"] = channel.protocol_version
    if channel and channel.mode == "mcp":
        listed = list_tools()
        if listed.get("count"):
            payload["tool_count"] = listed["count"]
            payload["tools"] = [t.get("name") for t in listed.get("tools", [])]
    return payload


def _render_call_result(result: Any) -> dict[str, Any]:
    """Turn an MCP tools/call result into a plain dict the rest of the server renders."""
    if not isinstance(result, dict):
        return {"result": result}
    texts: list[str] = []
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    texts.append(str(item.get("text", "")))
                else:
                    texts.append(json.dumps(item, ensure_ascii=False, default=str))
    joined = "\n".join(texts).strip()
    if result.get("isError"):
        return {"error": joined or "the bridge tool reported an error"}
    if joined:
        try:
            parsed = json.loads(joined)
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            return parsed
        if parsed is not None:
            return {"result": parsed}
    structured = result.get("structuredContent", result.get("structured_content"))
    if isinstance(structured, dict):
        return structured
    if joined:
        return {"text": joined}
    return {"result": result}


def call(tool: str, params: dict[str, Any] | None = None, *, timeout: float = 15.0) -> dict[str, Any]:
    """Invoke any tool the bridge exposes - the 8 official ones or anything tools/list shows."""
    if not tool or not isinstance(tool, str):
        return {"error": "tool name is required"}
    channel = _channel()
    if channel is None:
        return {"error": "MCP bridge is not running; call httpdbg_mcp_get_session first"}
    merged = dict(_HTTPS_API_METHODS.get(tool, {}).get("params") or {})
    if params:
        merged.update(params)
    if channel.mode == "mcp":
        resp = channel.request("tools/call", {"name": tool, "arguments": merged}, timeout=timeout)
        error = resp.get("error")
        if isinstance(error, dict) and error.get("code") == -32601:
            # the bridge speaks JSON-RPC but has no tools/call: raw method style
            channel.mode = "legacy"
        elif "result" in resp:
            return _render_call_result(resp["result"])
        else:
            return {"error": error} if error else {"error": f"unexpected bridge response: {resp}"}
    spec = _HTTPS_API_METHODS.get(tool) or {"method": tool, "params": {}}
    raw = channel.request(spec["method"], merged, timeout=timeout)
    if "result" in raw:
        result = raw["result"]
        return result if isinstance(result, dict) else {"result": result}
    error = raw.get("error")
    return {"error": error} if error else raw


def list_tools(timeout: float = 10.0) -> dict[str, Any]:
    """Ask the bridge for its full tool set (MCP tools/list) with parameter schemas."""
    channel = _channel()
    if channel is None:
        return {"error": "MCP bridge is not running; call httpdbg_mcp_get_session first"}
    if channel.mode != "mcp":
        return {
            "count": len(_MCP_TOOLS),
            "tools": [{"name": name} for name in _MCP_TOOLS],
            "note": "the bridge did not answer the MCP handshake; showing the documented tool set",
        }
    resp = channel.request("tools/list", {}, timeout=timeout)
    if "result" not in resp:
        error = resp.get("error")
        return {"error": error} if error else {"error": f"unexpected bridge response: {resp}"}
    entries: list[dict[str, Any]] = []
    for tool in (resp.get("result") or {}).get("tools") or []:
        if not isinstance(tool, dict):
            continue
        entry: dict[str, Any] = {"name": tool.get("name"), "description": tool.get("description") or ""}
        schema = tool.get("inputSchema")
        if isinstance(schema, dict) and isinstance(schema.get("properties"), dict):
            required = schema.get("required") or []
            entry["parameters"] = {
                key: {
                    "type": (spec or {}).get("type"),
                    "description": (spec or {}).get("description", ""),
                    "required": key in required,
                }
                for key, spec in schema["properties"].items()
            }
        entries.append(entry)
    return {"count": len(entries), "tools": entries}


def stop_session() -> dict[str, Any]:
    """Kill the bridge subprocess and forget the channel."""
    channel = _BRIDGE.pop("channel", None)
    _BRIDGE.pop("handle", None)
    if not isinstance(channel, _BridgeChannel):
        return {"stopped": False, "note": "no bridge session is open"}
    pid = channel.handle.pid
    channel.close()
    return {"stopped": True, "pid": pid}


# ---------------------------------------------------------------------------
# GUI-driving: capture start/stop and app control
# ---------------------------------------------------------------------------
def _window_handles(title_substr: str) -> list[int]:
    """Return HWNDs of top-level windows whose title contains the substring."""
    import ctypes

    found: list[int] = []

    # The callback is (HWND, LPARAM): declaring WINFUNCTYPE with 13 argument
    # types made ctypes call enum_proc with 14 arguments - TypeError per window,
    # so the enumeration returned nothing.
    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    def enum_proc(hwnd, _lparam):
        buf = ctypes.create_unicode_buffer(512)
        if ctypes.windll.user32.GetWindowTextW(hwnd, buf, 512) > 0:
            title = buf.value
            if title_substr.lower() in title.lower():
                found.append(int(hwnd))
        return True

    ctypes.windll.user32.EnumWindows(WNDENUMPROC(enum_proc), 0)
    return found


def _send_keys(hwnd: int, text: str) -> bool:
    import ctypes

    for ch in text:
        vkey = ctypes.windll.user32.VkKeyScanW(ord(ch))
        ctypes.windll.user32.PostMessageW(hwnd, 0x0100, vkey & 0xFF, 0)  # WM_KEYDOWN
        ctypes.windll.user32.PostMessageW(hwnd, 0x0101, vkey & 0xFF, 0)  # WM_KEYUP
    return True


def _toggle_capture(expected: str) -> dict[str, Any]:
    """Send the HTTP Debugger capture toggle and report what was requested.

    F9 only toggles the GUI capture control; it does not report the resulting
    state. Callers must verify the status bar instead of treating a successful
    key press as proof that capture started or stopped.
    """
    app = _app_exe()
    if not app:
        return {"error": "HTTP Debugger not installed", "hint": "download the MSI from https://www.httpdebugger.com/downloads/HTTPDebuggerPro.msi"}
    if not _app_running()["running"]:
        launched = launch()
        if launched.get("error"):
            return launched
        time.sleep(2.0)
    try:
        import pyautogui  # type: ignore
    except Exception:
        return {"error": "pyautogui not importable; GUI capture control unavailable", "hint": "pip install pyautogui, or use the MCP bridge (httpdbg_mcp_get_session) for full tool access"}
    # The capture toggle is the F9 key in the HTTP Debugger GUI.
    try:
        pyautogui.press("f9")
        return {
            "capture_toggle_sent": True,
            "requested": expected,
            "via": "keyboard F9",
            "note": "verify the status bar; the toggle request was sent, but the resulting capture state was not independently confirmed",
        }
    except Exception as exc:
        return {"error": f"capture toggle failed: {type(exc).__name__}: {exc}"}


def capture_start() -> dict[str, Any]:
    """Request the HTTP Debugger global capture hook on (GUI fallback)."""
    return _toggle_capture("start")


def capture_stop() -> dict[str, Any]:
    """Request the HTTP Debugger global capture hook off (GUI fallback)."""
    return _toggle_capture("stop")


# ---------------------------------------------------------------------------
# COM API fallback: parse HTTPDebugger.Api log folders for captured traffic.
# 32-bit only: requires the 32-bit PowerShell (SysWOW64). The COM API and the
# GUI application cannot run at the same time.
# ---------------------------------------------------------------------------
def _com_available() -> dict[str, Any]:
    import platform

    if platform.architecture()[0] != "x86" and not os.path.exists(_PS32):
        return {"ok": False, "error": "COM API requires 32-bit PowerShell (SysWOW64); the server itself runs 64-bit", "hint": "use the MCP bridge or GUI control instead"}
    return {"ok": True, "powershell": _PS32}


def _parse_com_log(log_dir: str | Path) -> list[dict[str, Any]]:
    """Walk a Root\\Date\\Hour structure produced by HTTPDebugger.Api StartLogger.

    Each subfolder holds up to 1000 requests as
        [id]_details.txt
        [id]_request_header.txt
        [id]_request_content.dat
        [id]_response_header.txt
        [id]_response_content.dat
    """
    root = Path(log_dir)
    if not root.is_dir():
        return []
    requests: list[dict[str, Any]] = []
    for details in root.rglob("*_details.txt"):
        try:
            text = details.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        entry: dict[str, Any] = {"id": details.stem.removesuffix("_details"), "path": str(details.parent)}
        for line in text.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                entry[key.strip().lower()] = value.strip()
        requests.append(entry)
    return requests


def com_capture_start(log_dir: str | Path = r"C:\Temp\HTTPDebuggerLogs") -> dict[str, Any]:
    """Start HTTPDebugger.Api logging (COM, 32-bit only)."""
    check = _com_available()
    if not check["ok"]:
        return check
    target = Path(log_dir)
    target.mkdir(parents=True, exist_ok=True)
    script = f"""
try {{
    $api = New-Object -ComObject HttpDebugger.Api
    [void]$api.LoadSettings('')
    [void]$api.StartLogger('{target}')
    Write-Output 'COM logger started'
}} catch {{
    Write-Error $_
    exit 1
}}
"""
    try:
        result = subprocess.run([_PS32, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        if result.returncode != 0:
            return {"error": f"COM start failed: {result.stderr.strip() or result.stdout.strip()}"}
        return {"com_logger_started": True, "log_dir": str(target)}
    except Exception as exc:
        return {"error": f"COM start failed: {type(exc).__name__}: {exc}"}


def com_capture_stop() -> dict[str, Any]:
    """Stop HTTPDebugger.Api logging (COM, 32-bit only)."""
    check = _com_available()
    if not check["ok"]:
        return check
    script = """
try {
    $api = New-Object -ComObject HttpDebugger.Api
    [void]$api.StopLogger()
    Write-Output 'COM logger stopped'
} catch {
    Write-Error $_
    exit 1
}
"""
    try:
        result = subprocess.run([_PS32, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        if result.returncode != 0:
            return {"error": f"COM stop failed: {result.stderr.strip() or result.stdout.strip()}"}
        return {"com_logger_stopped": True}
    except Exception as exc:
        return {"error": f"COM stop failed: {type(exc).__name__}: {exc}"}


def com_log_summary(log_dir: str | Path = r"C:\Temp\HTTPDebuggerLogs") -> dict[str, Any]:
    """Parse a COM log folder and return the captured request entries."""
    parsed = _parse_com_log(log_dir)
    return {"log_dir": str(log_dir), "captured": len(parsed), "entries": parsed[:200]}
