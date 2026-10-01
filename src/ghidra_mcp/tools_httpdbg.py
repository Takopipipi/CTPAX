"""MCP tools wrapping the HTTP Debugger integration: install status, GUI
launch, capture start/stop, the MCP bridge channel, the 8 official
captured-traffic tools, and the 32-bit COM log-parsing fallback."""

from __future__ import annotations

from ghidra_mcp import httpdbg_mcp
from ghidra_mcp.runtime import fail, mcp, render


@mcp.tool()
def httpdbg_status() -> str:
    """HTTP Debugger availability: install dir, MCP bridge state, running GUI.

    One-time setup: launch HTTP Debugger, then Settings -> MCP Server -> check
    'Enable MCP Server'. The status bar must read 'MCP: ON' before the captured-
    traffic tools work.
    """
    try:
        return render(httpdbg_mcp.status())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def httpdbg_launch() -> str:
    """Launch the HTTP Debugger GUI (it downloads nothing; just starts the app).

    After it opens, enable the MCP server once in Settings -> MCP Server, then call
    httpdbg_mcp_get_session to open the JSON-RPC channel the captured-traffic tools use.
    """
    try:
        return render(httpdbg_mcp.launch())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def httpdbg_mcp_get_session() -> str:
    """Open the MCP bridge channel by spawning HTTPDebuggerMcp.exe.

    Spawn the official HTTP Debugger MCP bridge (stdio JSON-RPC) and keep it
    running between calls. Required once before the 8 captured-traffic tools
    (httpdbg_mcp_call and friends). If the bridge exe is missing, the result tells
    you how to enable the MCP server in the GUI first.
    """
    try:
        return render(httpdbg_mcp.get_session())
    except Exception as exc:
        return fail(exc)


# one generic pass-through for any of the 8 official tools
_MCP_TOOL_DESCRIPTIONS = {
    "get_capture_status": "Live capture status: capturing on, active sessions, current stats.",
    "diagnose_capture": "Diagnostic report on the capture pipeline and what may be filtering traffic.",
    "list_endpoints": "Endpoints seen in the current capture, paginated.",
    "list_transactions": "Captured HTTP transactions for a session, paginated.",
    "search_transactions": "Search captured transactions by query; paginated.",
    "get_transaction": "Full detail of one captured transaction (headers + bodies).",
    "get_session_stats": "Aggregate stats (request count, bytes, timing) for a session.",
    "export_as_curl": "Export a transaction as a runnable curl command.",
}


for _tool, _doc in _MCP_TOOL_DESCRIPTIONS.items():
    def _make(tool: str, doc: str):
        @mcp.tool()
        def _wrapped(params: str | None = None) -> str:
            """Pass-through to the HTTP Debugger MCP tool.

            ``params`` is an optional JSON object of tool-specific arguments
            (e.g. {"transaction_id": "42"}, {"query": "api"}, {"page": 1}).
            Call httpdbg_mcp_get_session first to open the bridge channel.
            """
            try:
                parsed = None
                if params:
                    import json
                    parsed = json.loads(params)
                return render(httpdbg_mcp.call(tool, parsed))
            except Exception as exc:
                return fail(exc)
        _wrapped.__name__ = f"httpdbg_mcp_{_tool}"
        _wrapped.__doc__ = doc
        return _wrapped

    _make(_tool, _doc)


@mcp.tool()
def httpdbg_capture_start() -> str:
    """Toggle the HTTP Debugger global capture hook on (GUI fallback).

    Drives the GUI window: the capture toggle is the F9 key. Requires the app
    to be running (launches it first if needed). For full captured-traffic
    inspection use the MCP bridge (httpdbg_mcp_get_session + the 8 tools) instead.
    """
    try:
        return render(httpdbg_mcp.capture_start())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def httpdbg_capture_stop() -> str:
    """Toggle the HTTP Debugger global capture hook off (GUI fallback)."""
    try:
        return render(httpdbg_mcp.capture_stop())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def httpdbg_com_start(log_dir: str = r"C:\Temp\HTTPDebuggerLogs") -> str:
    """Start the HTTPDebugger.Api COM logger (32-bit PowerShell / SysWOW64).

    The COM API and the GUI application cannot run at the same time. Logs land
    in log_dir as Root\\Date\\Hour\\ folders with per-request detail/header/dat files.
    """
    try:
        return render(httpdbg_mcp.com_capture_start(log_dir))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def httpdbg_com_stop() -> str:
    """Stop the HTTPDebugger.Api COM logger (32-bit PowerShell / SysWOW64)."""
    try:
        return render(httpdbg_mcp.com_capture_stop())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def httpdbg_com_summary(log_dir: str = r"C:\Temp\HTTPDebuggerLogs") -> str:
    """Parse a COM log folder and return the captured request entries.

    Walks the Root\\Date\\Hour structure produced by StartLogger and returns
    the per-request details parsed from the _details.txt files.
    """
    try:
        return render(httpdbg_mcp.com_log_summary(log_dir))
    except Exception as exc:
        return fail(exc)
