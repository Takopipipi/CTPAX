"""Request forgery and raw network I/O: crafted HTTP(S) requests, raw TCP/UDP, DNS,
and the system proxy switch.

The HTTP tool is the Burp-Repeater equivalent: any method, any headers, any body, no
automatic behavior. Redirects are reported, not followed. Certificate verification is
on by default and off on request, which is the whole point when the target uses a
self-signed cert or sits behind a MITM proxy.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlsplit


def _coerce_body(body: str | None, encoding: str) -> bytes:
    if body is None:
        return b""
    if encoding == "hex":
        return bytes.fromhex(body)
    if encoding in ("base64", "b64"):
        return base64.b64decode(body)
    return body.encode("utf-8")


# Session jars: named cookie stores that survive between http_request calls.
_COOKIE_JARS: dict[str, dict[str, str]] = {}


def _merge_cookies(headers: dict[str, str], jar_name: str | None) -> dict[str, str]:
    if not jar_name:
        return headers
    jar = _COOKIE_JARS.setdefault(jar_name, {})
    stored = "; ".join(f"{k}={v}" for k, v in jar.items())
    if not stored:
        return headers
    merged = dict(headers or {})
    existing = next((k for k in merged if k.lower() == "cookie"), None)
    if existing:
        merged[existing] = merged[existing] + "; " + stored
    else:
        merged["Cookie"] = stored
    return merged


def _store_cookies(response_headers: dict[str, str], jar_name: str | None) -> list[str]:
    if not jar_name:
        return []
    jar = _COOKIE_JARS.setdefault(jar_name, {})
    saved = []
    for header, value in response_headers.items():
        if header.lower() != "set-cookie":
            continue
        pair = value.split(";", 1)[0]
        if "=" in pair:
            name, _, cookie_value = pair.partition("=")
            jar[name.strip()] = cookie_value.strip()
            saved.append(name.strip())
    return saved


def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    body_encoding: str = "text",
    *,
    verify: bool = True,
    timeout: float = 10.0,
    session: str | None = None,
) -> dict[str, Any]:
    """Send a crafted HTTP/HTTPS request and return the raw response.

    Nothing is automatic: the method is whatever you pass (GET/POST/PUT/PATCH/DELETE or
    made-up verbs), headers go out verbatim in the given order, redirects are reported
    as Location instead of followed, and no User-Agent or Content-Type is added behind
    your back. Pass ``verify=false`` for self-signed targets and MITM interception.
    Body: ``body_encoding`` is text, hex, or base64.

    ``session`` names a cookie jar: Set-Cookie responses are stored under it and
    Cookie headers are injected on later calls with the same name - login flows and
    token handoffs become two calls instead of header plumbing.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return {"error": f"scheme must be http or https, got {parts.scheme!r}"}
    host = parts.hostname
    if not host:
        return {"error": f"could not parse host from {url!r}"}
    port = parts.port or (443 if parts.scheme == "https" else 80)

    payload = _coerce_body(body, body_encoding)
    sent_headers = _merge_cookies(dict(headers or {}), session)
    if payload and "Content-Length" not in {k.title() for k in sent_headers}:
        sent_headers.setdefault("Content-Length", str(len(payload)))

    started = time.time()
    try:
        if parts.scheme == "https":
            context = ssl.create_default_context()
            if not verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
        full_path = parts.path or "/"
        if parts.query:
            full_path += "?" + parts.query
        connection.request(method.upper(), full_path, body=payload if payload else None, headers=sent_headers)
        response = connection.getresponse()
        data = response.read()
        elapsed = round(time.time() - started, 3)
        response_headers = [(k, v) for k, v in response.getheaders()]
        header_map = dict(response_headers)
        cookies_saved = _store_cookies(header_map, session)
        printable = all(32 <= b <= 126 or b in (9, 10, 13) for b in data[:4096])
        connection.close()
        result = {
            "status": response.status,
            "reason": response.reason,
            "http_version": response.version,
            "elapsed": elapsed,
            "size": len(data),
            "headers": header_map,
            "body_text": data.decode("utf-8", "replace") if printable else None,
            "body_hex": None if printable else data[:2048].hex(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "location": header_map.get("Location") or header_map.get("location"),
            "note": "redirects are not followed; replay against the Location with adjusted Host when needed",
        }
        if session:
            result["session"] = {"name": session, "cookies_saved": cookies_saved, "cookies_now": dict(_COOKIE_JARS.get(session, {}))}
        return result
    except (http.client.HTTPException, OSError, ssl.SSLError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "elapsed": round(time.time() - started, 3)}


def session_cookies(session: str, *, clear: bool = False) -> dict[str, Any]:
    """Inspect (or clear) a named http_request cookie jar."""
    jar = _COOKIE_JARS.get(session)
    if jar is None:
        return {"session": session, "cookies": {}, "note": "no jar yet; pass session=<name> to http_request"}
    if clear:
        _COOKIE_JARS.pop(session, None)
        return {"session": session, "cleared": True}
    return {"session": session, "cookies": dict(jar)}


def tcp_send(
    host: str,
    port: int,
    data: str | None = None,
    data_encoding: str = "text",
    *,
    read_banner_first: bool = False,
    wait: float = 3.0,
) -> dict[str, Any]:
    """Raw TCP client: optionally read a banner, send bytes, capture everything back.

    For custom protocols, game packet poking, and banner grabbing. ``data_encoding`` is
    text, hex, or base64. The socket closes after ``wait`` seconds of silence.
    """
    payload = _coerce_body(data, data_encoding) if data is not None else b""
    started = time.time()
    try:
        with socket.create_connection((host, port), timeout=wait) as sock:
            sock.settimeout(wait)
            received: bytes = b""
            if read_banner_first:
                try:
                    received += sock.recv(65536)
                except socket.timeout:
                    pass
            if payload:
                sock.sendall(payload)
            deadline = time.time() + wait
            while time.time() < deadline:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                received += chunk
            printable = all(32 <= b <= 126 or b in (9, 10, 13) for b in received[:4096])
            return {
                "connected": True,
                "host": host,
                "port": port,
                "sent": len(payload),
                "received": len(received),
                "elapsed": round(time.time() - started, 3),
                "text": received.decode("utf-8", "replace") if printable else None,
                "hex": received.hex() if not printable else received.hex()[:512],
            }
    except OSError as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "host": host, "port": port}


def udp_send(host: str, port: int, data: str, data_encoding: str = "text", *, wait: float = 3.0) -> dict[str, Any]:
    """Send one UDP datagram and wait briefly for a reply (game protocols, discovery)."""
    payload = _coerce_body(data, data_encoding)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(wait)
            sock.sendto(payload, (host, port))
            try:
                reply, source = sock.recvfrom(65536)
            except socket.timeout:
                return {"sent": len(payload), "reply": None, "note": f"no reply within {wait}s (UDP is lossy; resend or check the port)"}
            printable = all(32 <= b <= 126 or b in (9, 10, 13) for b in reply[:4096])
            return {
                "sent": len(payload),
                "reply_size": len(reply),
                "from": f"{source[0]}:{source[1]}",
                "text": reply.decode("utf-8", "replace") if printable else None,
                "hex": reply.hex(),
            }
    except OSError as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


def dns_resolve(host: str, *, include_txt: bool = False) -> dict[str, Any]:
    """Resolve A/AAAA/CNAME for a host; optionally TXT via nslookup."""
    result: dict[str, Any] = {"host": host}
    try:
        infos = socket.getaddrinfo(host, None)
        result["answers"] = sorted({f"{info[4][0]}" for info in infos})
        result["families"] = sorted({socket.AddressFamily(info[0]).name for info in infos})
    except socket.gaierror as exc:
        return {"error": f"resolution failed: {exc}", "host": host}
    if include_txt:
        try:
            proc_result = __import__("subprocess").run(
                ["nslookup", "-type=TXT", host], capture_output=True, text=True, errors="replace", timeout=15
            )
            result["txt_raw"] = proc_result.stdout
        except Exception as exc:
            result["txt_raw"] = f"error: {exc}"
    return result


# --------------------------------------------------------------------------
# system proxy (WinINET) - point a target app at a MITM proxy and back
# --------------------------------------------------------------------------
_PROXY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def proxy_get() -> dict[str, Any]:
    """Read the current WinINET proxy settings (what most Windows apps obey)."""
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _PROXY_KEY) as key:
        enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
        try:
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
        except FileNotFoundError:
            server = ""
        try:
            override, _ = winreg.QueryValueEx(key, "ProxyOverride")
        except FileNotFoundError:
            override = ""
    return {"proxy_enabled": bool(enabled), "proxy_server": server, "bypass_list": override}


def proxy_set(server: str | None = None, *, bypass: str = "localhost;127.*;*.local") -> dict[str, Any]:
    """Point the system WinINET proxy at ``host:port`` (e.g. 127.0.0.1:8080 for Burp).

    Pass ``server=null`` to switch the proxy off and restore direct connections.
    Takes effect for new processes; running apps may need a restart to notice.
    """
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _PROXY_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if server:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, bypass)
            action = f"proxy on -> {server}"
        else:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            action = "proxy off"
    return {"applied": True, "action": action, "bypass": bypass if server else None}
