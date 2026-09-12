"""MCP tools for the server's own version lifecycle: check and self-update."""

from __future__ import annotations

from ghidra_mcp import version
from ghidra_mcp.runtime import fail, mcp, render


@mcp.tool()
def version_check(force: bool = False) -> str:
    """Report installed vs latest CTPAX version (GitHub releases, cached 24h).

    Call this at session start. If ``outdated`` is true: tell the user you tried to
    use an outdated MCP version, run version_update, and after it succeeds tell the
    user to restart OpenCode / Claude Code / Cursor / Codex to load the new version.
    Network failures are cached briefly and reported as ``error`` without blocking.
    """
    try:
        info = version.check(force=force)
        info["outdated"] = version.outdated() is not None
        return render(info)
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def version_update() -> str:
    """Update the installed MCP from the latest GitHub release, sources in place.

    Downloads the tagged archive and overwrites the install's sources; the running
    server keeps serving old code until the client restarts. The response always says
    whether a restart is required - after a successful update, tell the user to
    restart their AI client and retry the task.
    """
    try:
        return render(version.update())
    except Exception as exc:
        return fail(exc)
