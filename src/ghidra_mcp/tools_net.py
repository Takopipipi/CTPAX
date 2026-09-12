"""MCP tools for request forgery and raw network I/O, plus JWT analysis."""

from __future__ import annotations

from ghidra_mcp import net_forge, net_mock
from ghidra_mcp.crypto_jwt import jwt_decode as _jwt_decode_impl
from ghidra_mcp.crypto_jwt import jwt_forge as _jwt_forge_impl
from ghidra_mcp.runtime import fail, mcp, render


@mcp.tool()
def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    body_encoding: str = "text",
    verify: bool = True,
    timeout: float = 10.0,
    session: str | None = None,
) -> str:
    """Send a crafted HTTP/HTTPS request: any method, exact headers, any body.

    The Repeater equivalent. Nothing automatic: no redirect following (Location comes
    back for you to replay), no added User-Agent or Content-Type behind your back.
    ``verify=false`` accepts self-signed certificates for MITM interception. Headers is
    a dict; body_encoding is text/hex/base64. ``session`` names a cookie jar: Set-Cookie
    is stored and replayed on later calls with the same name - login flows become two
    calls; session_cookies inspects or clears a jar.
    """
    try:
        return render(net_forge.http_request(url, method, headers, body, body_encoding, verify=verify, timeout=timeout, session=session))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def session_cookies(session: str, clear: bool = False) -> str:
    """Inspect (or clear) a named http_request cookie jar."""
    try:
        return render(net_forge.session_cookies(session, clear=clear))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def tcp_send(host: str, port: int, data: str | None = None, data_encoding: str = "text", read_banner_first: bool = False, wait: float = 3.0) -> str:
    """Raw TCP: optional banner read, send bytes (text/hex/base64), capture the reply.

    For custom protocols and game traffic. Pair with netstat to find the port, then
    replay what the client sent.
    """
    try:
        return render(net_forge.tcp_send(host, port, data, data_encoding, read_banner_first=read_banner_first, wait=wait))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def udp_send(host: str, port: int, data: str, data_encoding: str = "text", wait: float = 3.0) -> str:
    """Send one UDP datagram and wait briefly for a reply (discovery, game protocols)."""
    try:
        return render(net_forge.udp_send(host, port, data, data_encoding, wait=wait))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def dns_resolve(host: str, include_txt: bool = False) -> str:
    """Resolve a host to A/AAAA (optionally TXT) - where does this binary actually connect."""
    try:
        return render(net_forge.dns_resolve(host, include_txt=include_txt))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def proxy_get() -> str:
    """Read the system WinINET proxy settings."""
    try:
        return render(net_forge.proxy_get())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def proxy_set(server: str | None = None, bypass: str = "localhost;127.*;*.local") -> str:
    """Point the system proxy at host:port (127.0.0.1:8080 for Burp/Fiddler), or null to disable.

    Routes WinINET-obeying apps through your interception proxy. New processes pick it
    up; running ones need a restart.
    """
    try:
        return render(net_forge.proxy_set(server, bypass=bypass))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def jwt_decode(token: str) -> str:
    """Decode a JWT: header, payload, and which algorithm the header claims.

    Verify nothing yet - first look at alg (none/HS256/RS256?) and the payload claims
    (role, exp, sub) to see what is worth forging.
    """
    try:
        return render(_jwt_decode_impl(token))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def jwt_forge(
    header_payload_claims: dict,
    algorithm: str = "HS256",
    key: str = "",
    secret_candidates: list[str] | None = None,
) -> str:
    """Forge a JWT or test weak HMAC secrets against an existing one.

    ``algorithm``: HS256/HS384/HS512 with ``key``, or ``none`` for the unverified-signature
    attack (empty signature). ``secret_candidates`` tests a list of weak secrets - pass
    the original token's signature via ``verify_token``-style workflow: give claims of the
    original token plus candidates, and any candidate whose forged signature matches the
    original is the server's secret. Brute-forcing beyond the candidate list is your job
    (hashcat mode 16500).
    """
    try:
        return render(_jwt_forge_impl(header_payload_claims, algorithm, key, secret_candidates))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def mock_record(port: int, stop: bool = False) -> str:
    """Show (or stop) the upstream exchanges a hybrid mock is recording.

    Works with net_mock_start(record=True): every unmatched request is forwarded to
    the real upstream and its request+response stored - the raw material for
    mock_generate.
    """
    try:
        return render(net_mock.mock_record(int(port), stop=stop))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def mock_generate(port: int, transforms: dict | None = None, clear_existing: bool = False) -> str:
    """Generate mock routes from a recording: replay real responses, transform on serve.

    Every recorded exchange becomes a route (method + path -> recorded status/body), so
    the mock replays the real server conversation without the real server. ``transforms``
    maps paths to serve-time regex substitutions: {"/api/handshake": [{"find":
    "nonce\\":\\"[0-9a-f]+\\"", "replace": "nonce\\":\\"0000"}]} - nonces, timestamps and
    signatures rewritten at every response, so freshness checks see a consistent world.
    """
    try:
        return render(net_mock.mock_generate(int(port), transforms or {}, clear_existing=clear_existing))
    except Exception as exc:
        return fail(exc)
