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
    return {
        "installed": app is not None or mcp is not None,
        "install_dir": install_dir,
        "app_exe": str(app) if app else None,
        "mcp_bridge": str(mcp) if mcp else None,
        "bridge_running": _bridge_running()["running"] if mcp else False,
        "app_running": _app_running()["running"],
        "mcp_tools": _MCP_TOOLS,
        "note": _enable_mcp_note() if mcp and not _bridge_running()["running"] else (
            "installed and MCP bridge enabled" if (mcp and _bridge_running()["running"]) else
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
# MCP bridge: spawn HTTPDebuggerMcp.exe as a stdio JSON-RPC peer
# ---------------------------------------------------------------------------
_BRIDGE: dict[str, Any] = {}


def _spawn_bridge(timeout: float = 8.0) -> dict[str, Any]:
    """Start HTTPDebuggerMcp.exe and establish a JSON-RPC channel."""
    if _BRIDGE.get("handle"):
        return {"already_running": True, **{"handle": _BRIDGE.get("handle")}}
    mcp = _mcp_exe()
    if not mcp:
        return {"error": "HTTPDebuggerMcp.exe not found", "hint": _enable_mcp_note()}
    try:
        handle = subprocess.Popen(
            [str(mcp)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            bufsize=0,
        )
    except Exception as exc:
        return {"error": f"failed to spawn bridge: {type(exc).__name__}: {exc}"}
    _BRIDGE["handle"] = handle
    _BRIDGE["started_at"] = time.time()
    return {"started": True, "pid": handle.pid, "hint": _enable_mcp_note()}


def _bridge_call(method: str, params: dict[str, Any] | None, timeout: float = 15.0) -> dict[str, Any]:
    """Send one JSON-RPC request to the bridge and read the response."""
    handle = _BRIDGE.get("handle")
    if handle is None or handle.poll() is not None:
        return {"error": "MCP bridge is not running; call httpdbg_mcp_get_session first"}
    request = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method}
    if params is not None:
        request["params"] = params
    line = (json.dumps(request) + "\n").encode("utf-8")
    try:
        handle.stdin.write(line)
        handle.stdin.flush()
    except Exception as exc:
        return {"error": f"write failed: {type(exc).__name__}: {exc}"}
    deadline = time.time() + timeout
    while time.time() < deadline:
        if handle.poll() is not None:
            return {"error": "bridge exited unexpectedly"}
        # the bridge writes newline-delimited JSON
        try:
            raw = handle.stdout.readline()
            if raw:
                text = raw.decode("utf-8", "replace").strip()
                if text:
                    msg = json.loads(text)
                    if msg.get("jsonrpc") == "2.0" and "result" in msg:
                        return msg["result"] if isinstance(msg.get("result"), dict) else {"result": msg["result"]}
                    if "error" in msg:
                        return {"error": msg["error"]}
        except Exception:
            pass
        time.sleep(0.1)
    return {"error": "timeout waiting for MCP bridge response"}


def get_session() -> dict[str, Any]:
    """Open the MCP bridge channel. Required once before the 8 captured-traffic tools."""
    info = _spawn_bridge()
    if info.get("error"):
        return info
    return {
        "connected": True,
        "tools": _MCP_TOOLS,
        "pid": info.get("pid"),
        "hint": "call httpdbg_mcp_get_capture_status to inspect the live capture" if not info.get("already_running") else "bridge already connected",
    }


def call(tool: str, params: dict[str, Any] | None = None, *, timeout: float = 15.0) -> dict[str, Any]:
    """Invoke any of the 8 official HTTP Debugger MCP tools by name."""
    if tool not in _MCP_TOOLS:
        return {"error": f"unknown tool {tool!r}; one of {_MCP_TOOLS}"}
    spec = _HTTPS_API_METHODS[tool]
    method = spec["method"]
    merged = dict(spec["params"] or {})
    if params:
        merged.update(params)
    return _bridge_call(method, merged, timeout=timeout)


# ---------------------------------------------------------------------------
# GUI-driving: capture start/stop and app control
# ---------------------------------------------------------------------------
def _window_handles(title_substr: str) -> list[int]:
    """Return HWNDs of top-level windows whose title contains the substring."""
    import ctypes

    found: list[int] = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_int)
    def enum_proc(hwnd, _lparam):
        buf = ctypes.create_unicode_buffer(512)
        if ctypes.windll.user32.GetWindowTextW(hwnd, buf, 512) > 0:
            title = buf.value
            if title_substr.lower() in title.lower():
                found.append(int(hwnd))
        return True

    ctypes.windll.user32.EnumWindows(enum_proc, 0)
    return found


def _send_keys(hwnd: int, text: str) -> bool:
    import ctypes

    for ch in text:
        vkey = ctypes.windll.user32.VkKeyScanW(ord(ch))
        ctypes.windll.user32.PostMessageW(hwnd, 0x0100, vkey & 0xFF, 0)  # WM_KEYDOWN
        ctypes.windll.user32.PostMessageW(hwnd, 0x0101, vkey & 0xFF, 0)  # WM_KEYUP
    return True


def capture_start() -> dict[str, Any]:
    """Toggle the HTTP Debugger global capture hook on (GUI fallback)."""
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
        return {"capture_started": True, "via": "keyboard F9", "note": "verify the status bar shows 'Capturing'"}
    except Exception as exc:
        return {"error": f"capture toggle failed: {type(exc).__name__}: {exc}"}


def capture_stop() -> dict[str, Any]:
    """Toggle the HTTP Debugger global capture hook off (GUI fallback)."""
    return capture_start()


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
            return {"error": f"COM start failed: {result.stderr.strip() or result.stdout.strip()}", "com_available": False}
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
            return {"error": f"COM stop failed: {result.stderr.strip() or result.stdout.strip()}", "com_available": False}
        return {"com_logger_stopped": True}
    except Exception as exc:
        return {"error": f"COM stop failed: {type(exc).__name__}: {exc}"}


def com_log_summary(log_dir: str | Path = r"C:\Temp\HTTPDebuggerLogs") -> dict[str, Any]:
    """Parse a COM log folder and return the captured request entries."""
    parsed = _parse_com_log(log_dir)
    return {"log_dir": str(log_dir), "captured": len(parsed), "entries": parsed[:200]}
