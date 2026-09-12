"""Entry point: ``python -m ghidra_mcp.server``.

Importing the tool modules is what registers the tools on the shared FastMCP instance,
so the imports below are load-bearing despite looking unused.

Nothing may write to stdout: that is the MCP transport. Diagnostics go to stderr.
"""

from __future__ import annotations

import sys

from ghidra_mcp.runtime import SETTINGS, mcp

# Registration by import. Order only affects the order tools are listed in.
from ghidra_mcp import tools_session  # noqa: F401
from ghidra_mcp import tools_static  # noqa: F401
from ghidra_mcp import tools_pe  # noqa: F401
from ghidra_mcp import tools_crypto  # noqa: F401
from ghidra_mcp import tools_system  # noqa: F401
from ghidra_mcp import tools_net  # noqa: F401
from ghidra_mcp import tools_forge  # noqa: F401
from ghidra_mcp import tools_maxi  # noqa: F401
from ghidra_mcp import tools_lang  # noqa: F401
from ghidra_mcp import tools_re  # noqa: F401
from ghidra_mcp import tools_forensic  # noqa: F401
from ghidra_mcp import tools_cdb  # noqa: F401
from ghidra_mcp import tools_dynamic  # noqa: F401
from ghidra_mcp import tools_x64dbg  # noqa: F401
from ghidra_mcp import tools_ghidra  # noqa: F401
from ghidra_mcp import tools_pentest  # noqa: F401
from ghidra_mcp import tools_nuclei  # noqa: F401
from ghidra_mcp import tools_version  # noqa: F401


def main() -> None:
    from ghidra_mcp import version

    version.prefetch()  # background GitHub check so the first tool call is not delayed
    problems = SETTINGS.problems()
    for problem in problems:
        # Warn but start anyway: the static and crypto tools work without Ghidra, and the
        # doctor tool has to be reachable to explain what is missing.
        print(f"[ghidra-mcp] warning: {problem}", file=sys.stderr)
    print(
        "[ghidra-mcp] ready"
        f" v{version.__version__}"
        f" ghidra={SETTINGS.ghidra_dir}"
        f" java={SETTINGS.java_home}"
        f" home={SETTINGS.home}",
        file=sys.stderr,
    )
    mcp.run()


if __name__ == "__main__":
    main()
