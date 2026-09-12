"""MCP tools for server-response forgery, GUI automation, and binary file patching."""

from __future__ import annotations

from ghidra_mcp import gui_automation as gui
from ghidra_mcp import net_mock
from ghidra_mcp import static_analysis
from ghidra_mcp.runtime import fail, mcp, render

_ADMIN = "needs an elevated session (hosts file, listening ports below 1024)"


# --------------------------------------------------------------------------
# mock server
# --------------------------------------------------------------------------
@mcp.tool()
def net_mock_start(
    port: int = 8443,
    https: bool = False,
    upstream_host: str | None = None,
    upstream_port: int | None = None,
    record: bool = False,
) -> str:
    """Start the forged-response server: routes answer whatever the target asks.

    The heart of server-response forgery: redirect the target's API host here
    (net_hosts_add), add answers (net_mock_route), and its license check reads your
    JSON instead of the real server's. Hybrid mode: with ``upstream_host``/``upstream_port``,
    unmatched requests pass through to the real server transparently while matched
    routes serve your forgeries. ``record=True`` stores every exchange - feed the
    recording to mock_generate to replay it without the real server.
    """
    try:
        return render(net_mock.mock_start(
            port, https=https, upstream_host=upstream_host, upstream_port=upstream_port, record=record,
        ))
    except Exception as exc:
        return fail(exc, hint=_ADMIN)


@mcp.tool()
def net_mock_stop(port: int) -> str:
    """Stop a mock server on a port."""
    try:
        return render(net_mock.mock_stop(port))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def net_mock_route(
    method: str,
    path_pattern: str,
    status: int = 200,
    body: str = "",
    body_hex: str | None = None,
    content_type: str = "application/json",
    headers: dict[str, str] | None = None,
    delay: float = 0.0,
    query: dict[str, str] | None = None,
) -> str:
    """Forge one answer: GET/POST + path (regex allowed) -> status, body, headers.

    Examples: ``net_mock_route("POST", "/api/v1/license", body='{"valid":true,"plan":"premium"}')``
    or ``net_mock_route("GET", "/api/v1/user/\\\\d+", status=403)``. Path matching ignores
    the query string; ``query`` narrows by parameter regex (``{"key": ".*"}``).
    ``body_hex`` carries binary answers; ``delay`` fakes latency.
    """
    try:
        return render(net_mock.mock_route(method, path_pattern, status=status, body=body, body_hex=body_hex, content_type=content_type, headers=headers, delay=delay, query=query))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def net_mock_routes() -> str:
    """List the forged routes the mock server currently serves."""
    try:
        return render(net_mock.mock_routes())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def net_mock_requests(clear: bool = False, limit: int = 50) -> str:
    """See what the target sent to the mock server: paths, headers, body hex.

    The reconnaissance half: run the target once, read its real requests, forge
    exactly those routes, rerun.
    """
    try:
        return render(net_mock.mock_requests(clear=clear, limit=limit))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def net_mock_certificate() -> str:
    """Generate the self-signed mock-server certificate for HTTPS forgery.

    After generating, install it into the Windows trust store (the result prints the
    exact certutil command) - TLS-pinning-free apps will then accept forged HTTPS
    responses without noticing.
    """
    try:
        return render(net_mock.mock_certificate())
    except Exception as exc:
        return fail(exc)


# --------------------------------------------------------------------------
# tcp proxy
# --------------------------------------------------------------------------
@mcp.tool()
def tcp_proxy_start(listen_port: int, upstream_host: str, upstream_port: int, tls_terminate: bool = False) -> str:
    """Start a transparent logging proxy: target -> listen_port -> real server.

    Redirect the target to 127.0.0.1:listen_port and its whole conversation flows
    through here, recorded in both directions - the protocol-reverse-engineering
    workhorse. ``tls_terminate=True`` wraps the client side with the mock certificate
    (install it via net_mock_certificate first): the target speaks HTTPS, you read
    plaintext, upstream re-encrypts. Works on TLS-pinning-free targets.
    """
    try:
        return render(net_mock.tcp_proxy_start(listen_port, upstream_host, upstream_port, tls_terminate=tls_terminate))
    except Exception as exc:
        return fail(exc, hint=_ADMIN)


@mcp.tool()
def tcp_proxy_stop(listen_port: int) -> str:
    """Stop a TCP proxy."""
    try:
        return render(net_mock.tcp_proxy_stop(listen_port))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def tcp_proxy_rule(listen_port: int, find_hex: str, replace_hex: str, direction: str = "server->client") -> str:
    """Rewrite bytes flowing through a proxy: forged responses without touching the server.

    In-place substitution (find/replace must be the same length). Classic use: the
    server answers ``"license":"expired"`` -> find that substring's hex, replace with
    ``"license":"valid"`` padded to length - the target sees the forged version.
    """
    try:
        return render(net_mock.tcp_proxy_rule(listen_port, find_hex, replace_hex, direction))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def tcp_proxy_traffic(listen_port: int, limit: int = 100, clear: bool = False) -> str:
    """Read what flowed through a proxy (both directions, hex and text, rewrite events)."""
    try:
        return render(net_mock.tcp_proxy_traffic(listen_port, limit=limit, clear=clear))
    except Exception as exc:
        return fail(exc)


# --------------------------------------------------------------------------
# hosts
# --------------------------------------------------------------------------
@mcp.tool()
def net_hosts_add(hostname: str, ip: str = "127.0.0.1") -> str:
    """Redirect a hostname to an ip via the hosts file (api.vendor.com -> 127.0.0.1).

    Routes the target's API calls at your mock server or proxy. Only ghidra-mcp-marked
    entries are touched; net_hosts_remove takes them back. Restart the target - DNS is
    cached per process.
    """
    try:
        return render(net_mock.hosts_add(hostname, ip))
    except Exception as exc:
        return fail(exc, hint=_ADMIN)


@mcp.tool()
def net_hosts_remove(hostname: str) -> str:
    """Remove a ghidra-mcp hosts redirection, restoring real DNS."""
    try:
        return render(net_mock.hosts_remove(hostname))
    except Exception as exc:
        return fail(exc, hint=_ADMIN)


@mcp.tool()
def net_hosts_list() -> str:
    """List the active ghidra-mcp hosts redirections."""
    try:
        return render(net_mock.hosts_list())
    except Exception as exc:
        return fail(exc)


# --------------------------------------------------------------------------
# gui automation
# --------------------------------------------------------------------------
@mcp.tool()
def input_click(x: int, y: int, right: bool = False, double: bool = False) -> str:
    """Click at screen coordinates (SendInput - real input, works on stubborn dialogs)."""
    try:
        return render(gui.click(x, y, right=right, double=double))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def input_type(text: str) -> str:
    """Type unicode text through the keyboard stack into whatever has focus."""
    try:
        return render(gui.type_text(text))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def input_key(key: str, times: int = 1) -> str:
    """Press a key or combo: enter, tab, esc, ctrl+s, ctrl+shift+esc, f5, arrows..."""
    try:
        return render(gui.press_key(key, times=times))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def window_focus(title_or_class: str) -> str:
    """Bring a window to the foreground (by title or class) so input lands in it."""
    try:
        return render(gui.focus_window(title_or_class))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def window_rect(title_or_class: str) -> str:
    """Screen rectangle of a window - the coordinate space for input_click inside it."""
    try:
        return render(gui.window_rect(title_or_class))
    except Exception as exc:
        return fail(exc)


# --------------------------------------------------------------------------
# file patching
# --------------------------------------------------------------------------
@mcp.tool()
def file_patch(path: str, find_hex: str, replace_hex: str, offset: int | None = None, occurrence: int | None = None, replace_all: bool = False, backup: bool = True) -> str:
    """Replace bytes in a binary file - static crack, saved in place with a .bak backup.

    find/replace must be the same length. Ambiguous patterns are refused unless you
    disambiguate: ``occurrence=1`` patches the first match, ``offset`` starts the
    search there, ``replace_all=true`` patches every match. Pair with
    find_bytes_in_file to locate the bytes and disassemble_bytes to verify the patch
    decodes correctly.
    """
    try:
        return render(static_analysis.patch_file(path, find_hex, replace_hex, offset=offset, occurrence=occurrence, replace_all=replace_all, backup=backup))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def file_diff(path_a: str, path_b: str, limit: int = 100) -> str:
    """Byte-level diff of two same-size binaries: what did the crack actually change.

    Original vs patched, clean vs unpacked - every differing run with offset and hex.
    """
    try:
        return render(static_analysis.diff_files(path_a, path_b, limit=limit))
    except Exception as exc:
        return fail(exc)
