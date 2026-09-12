"""Server-response forgery: a mock HTTP(S) server, a logging TCP proxy with byte-level
rewrite rules, and hosts-file redirection.

The workflow this enables: point the target at us (hosts entry or system proxy), then
answer its API calls however we like - a license check becomes {"premium": true}, a
failed update becomes 404. For non-HTTP protocols the TCP proxy forwards to the real
server while logging and optionally rewriting bytes in either direction, which is
response forgery for protocols there is no schema for.

Everything runs as threads inside the MCP server process; sessions survive across tool
calls until explicitly stopped.
"""

from __future__ import annotations

import datetime
import json
import re as _re
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ghidra_mcp.runtime import SETTINGS

# --------------------------------------------------------------------------
# mock HTTP(S) server
# --------------------------------------------------------------------------
_ROUTES: dict[str, dict[str, Any]] = {}
_ROUTE_LOCK = threading.Lock()
_REQUEST_LOG: list[dict[str, Any]] = []
_SERVERS: dict[int, dict[str, Any]] = {}
_RECORDINGS: dict[int, list[dict[str, Any]]] = {}

_DEFAULT_BODY = b'{"error": "no route matched; add one with net_mock_route"}'


def _cert_paths() -> tuple[Path, Path]:
    cert_dir = SETTINGS.home / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    return cert_dir / "mock_cert.pem", cert_dir / "mock_key.pem"


def mock_certificate() -> dict[str, Any]:
    """Generate (once) the self-signed certificate the HTTPS mock server uses.

    Install it into the Windows trust store (certutil -addstore root, or double-click ->
    Install) and TLS-pinning-free HTTPS targets will accept forged responses happily.
    """
    cert_path, key_path = _cert_paths()
    if cert_path.is_file() and key_path.is_file():
        return {"cert": str(cert_path), "key": str(key_path), "created": "already existed"}
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GhidraMCP Mock Server")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("*")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    return {
        "cert": str(cert_path),
        "key": str(key_path),
        "created": "new self-signed cert (CN=GhidraMCP Mock Server, SAN localhost + *)",
        "trust_hint": "certutil -addstore -f root <cert> to make HTTPS targets accept it",
    }


class _MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _match(self, method: str, path: str) -> dict[str, Any] | None:
        import re as _re
        from urllib.parse import parse_qs, urlsplit

        split = urlsplit(path)
        path_only = split.path
        query_params = {k: v[0] for k, v in parse_qs(split.query).items()}
        with _ROUTE_LOCK:
            candidates = [key for key in _ROUTES if key.startswith(f"{method} ")]
            fallback = None
            for key in candidates:
                pattern = key.split(" ", 1)[1]
                for route in _ROUTES[key]:  # bucket: query-specific first, fallback last
                    if not (pattern == path_only or _re.fullmatch(pattern, path_only)):
                        continue
                    required = route.get("query") or {}
                    if not required:
                        fallback = fallback or route
                        continue
                    if all(name in query_params and _re.fullmatch(value, query_params[name]) for name, value in required.items()):
                        return route
            return fallback

    def _handle(self, method: str) -> None:
        body = b""
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            body = self.rfile.read(length)
        route = self._match(method, self.path)
        with _ROUTE_LOCK:
            server = _SERVERS.get(self.server.server_address[1], {})
            upstream = server.get("upstream")
            recording = _RECORDINGS.get(self.server.server_address[1])
            _REQUEST_LOG.append({
                "at": round(time.time(), 3),
                "method": method,
                "path": self.path,
                "headers": dict(self.headers),
                "body_hex": body.hex()[:2048],
                "matched": bool(route),
                "from": self.client_address[0],
            })
            del _REQUEST_LOG[:-500]

        if route is None and upstream is not None:
            # Hybrid mode: no route matched, so transparently forward to the real
            # upstream and log the exchange. This is the 'control test against the
            # real server' the tester had to hand-roll.
            status, headers, payload = self._proxy_to_upstream(method, upstream, body)
            if recording is not None:
                with _ROUTE_LOCK:
                    recording.append({
                        "method": method, "path": self.path, "request_body_hex": body.hex()[:4096],
                        "status": status, "response_headers": {k: v for k, v in headers.items() if k.lower() not in ("transfer-encoding", "content-length", "connection")},
                        "response_body_hex": payload.hex()[:20000],
                        "at": round(time.time(), 3),
                    })
        elif route is None:
            payload, status, headers = _DEFAULT_BODY, 404, {"Content-Type": "application/json"}
            if recording is not None:
                # no upstream configured: still record what was asked for, with the
                # default answer - mock_generate can turn this into a replayable route
                with _ROUTE_LOCK:
                    recording.append({
                        "method": method, "path": self.path, "request_body_hex": body.hex()[:4096],
                        "status": status, "response_headers": dict(headers),
                        "response_body_hex": payload.hex()[:20000],
                        "at": round(time.time(), 3),
                    })
        else:
            status = int(route.get("status", 200))
            headers = dict(route.get("headers") or {})
            raw = route.get("body_hex")
            payload = bytes.fromhex(raw) if raw else str(route.get("body", "")).encode("utf-8")
            headers.setdefault("Content-Type", route.get("content_type", "application/json"))
            # Per-route transforms run at serve time: substitute nonces, timestamps,
            # and signatures freshly on every response (replay with dynamic fields).
            for rule in route.get("transform") or []:
                payload = _re.sub(rule["find"].encode(), rule["replace"].encode(), payload)
            delay = float(route.get("delay", 0))
            if delay:
                time.sleep(delay)
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _proxy_to_upstream(self, method: str, upstream: dict[str, Any], body: bytes) -> tuple[int, dict[str, str], bytes]:
        """Transparent forward to the real upstream: known routes are ours, the rest is real."""
        import http.client as _hc
        import ssl as _ssl

        host, port = upstream["host"], int(upstream.get("port", 443 if upstream.get("tls") else 80))
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection")}
        try:
            if upstream.get("tls"):
                context = _ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = _ssl.CERT_NONE
                connection = _hc.HTTPSConnection(host, port, timeout=15, context=context)
            else:
                connection = _hc.HTTPConnection(host, port, timeout=15)
            connection.request(method, self.path, body=body if body else None, headers=headers)
            response = connection.getresponse()
            data = response.read()
            response_headers = {k: v for k, v in response.getheaders()}
            connection.close()
            return response.status, response_headers, data
        except Exception as exc:
            return 502, {"Content-Type": "application/json"}, json.dumps({"error": f"upstream {host}:{port} failed: {exc}"}).encode()

    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._handle("PUT")

    def do_PATCH(self) -> None:  # noqa: N802
        self._handle("PATCH")

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle("DELETE")

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle("HEAD")

    def log_message(self, *args: Any) -> None:
        pass  # request log lives in _REQUEST_LOG, not stderr


def mock_start(
    port: int = 8443,
    *,
    https: bool = False,
    upstream_host: str | None = None,
    upstream_port: int | None = None,
    upstream_tls: bool = True,
    record: bool = False,
) -> dict[str, Any]:
    """Start the forged-response server on a port (HTTP, or HTTPS with the mock cert).

    Hybrid mode: pass ``upstream_host``/``upstream_port`` and unmatched requests pass
    through to the real server (transparently, and logged) while matched routes answer
    with your forgeries - one port, both behaviours. ``record=True`` stores every
    upstream exchange for mock_generate to replay later.
    """
    with _ROUTE_LOCK:
        if port in _SERVERS:
            return {"error": f"a server is already listening on {port}; stop it first"}
        handler_server = ThreadingHTTPServer(("0.0.0.0", port), _MockHandler)
        daemon = threading.Thread(target=handler_server.serve_forever, daemon=True)
        daemon.start()
        if https:
            info = mock_certificate()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(info["cert"], info["key"])
            handler_server.socket = context.wrap_socket(handler_server.socket, server_side=True)
        _SERVERS[port] = {
            "server": handler_server, "thread": daemon, "https": https,
            "upstream": {"host": upstream_host, "port": upstream_port, "tls": upstream_tls} if upstream_host else None,
        }
        if record:
            _RECORDINGS[port] = []
        return {
            "listening": True,
            "port": port,
            "transport": "https" if https else "http",
            "upstream": f"{upstream_host}:{upstream_port}" if upstream_host else None,
            "hybrid": bool(upstream_host),
            "recording": record,
            "cert_note": "net_mock_certificate to generate/install the mock cert" if https else None,
        }


def mock_stop(port: int) -> dict[str, Any]:
    """Stop the mock server on a port."""
    with _ROUTE_LOCK:
        entry = _SERVERS.pop(port, None)
    if entry is None:
        return {"error": f"nothing listening on {port}"}
    entry["server"].shutdown()
    entry["server"].server_close()
    return {"stopped": True, "port": port}


def mock_route(
    method: str,
    path_pattern: str,
    *,
    status: int = 200,
    body: str = "",
    body_hex: str | None = None,
    content_type: str = "application/json",
    headers: dict[str, str] | None = None,
    delay: float = 0.0,
    query: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Add or replace a forged answer: GET/POST + path (regex allowed) -> response.

    ``path_pattern`` is matched against the path (query string excluded). Several routes
    may share one path: the one whose ``query`` requirements match wins, and a query-less
    route is the fallback when no query-specific one does. ``query``: every listed
    parameter must exist and its regex must match (``{"key": "\\\\d+"}``).
    ``body_hex`` overrides ``body`` for binary answers; ``delay`` fakes latency.
    """
    key = f"{method.upper()} {path_pattern}"
    with _ROUTE_LOCK:
        route = {
            "status": status, "body": body, "body_hex": body_hex,
            "content_type": content_type, "headers": headers or {}, "delay": delay,
            "query": query or {},
        }
        bucket = _ROUTES.setdefault(key, [])
        # Replace an existing route with the identical query requirements.
        replaced = False
        for index, existing in enumerate(bucket):
            if (existing.get("query") or {}) == (query or {}):
                bucket[index] = route
                replaced = True
                break
        if not replaced:
            bucket.append(route)
        # Query-specific routes are tried before the fallback.
        bucket.sort(key=lambda r: not bool(r.get("query")))
        return {"routed": True, "replaced": replaced, "route": key, "status": status, "query": query or {}}


def mock_routes() -> dict[str, Any]:
    """List the forged routes currently configured."""
    with _ROUTE_LOCK:
        return {"count": sum(len(v) for v in _ROUTES.values()), "routes": {k: [{**r, "body_hex": None} for r in v] for k, v in _ROUTES.items()}}


def mock_requests(*, clear: bool = False, limit: int = 50) -> dict[str, Any]:
    """See what the target actually sent to the mock server: paths, headers, bodies.

    This is the record half of the forgery: run the target once, read what it asked
    for, then forge exactly those routes.
    """
    with _ROUTE_LOCK:
        log = list(_REQUEST_LOG[-limit:])
        if clear:
            _REQUEST_LOG.clear()
        return {"count": len(_REQUEST_LOG), "requests": log, "cleared": clear}


# --------------------------------------------------------------------------
# TCP proxy with logging and byte rewriting
# --------------------------------------------------------------------------
class _TcpProxy:
    def __init__(self, listen_port: int, upstream_host: str, upstream_port: int, *, tls_terminate: bool = False,
                 upstream_map: dict[str, str] | None = None, upstream_tls: bool = False, log_file: str | None = None) -> None:
        self.listen_port = listen_port
        self.default_upstream = (upstream_host, upstream_port)
        self.upstream_map = upstream_map or {}
        self.upstream_tls = upstream_tls
        self.tls_terminate = tls_terminate
        self.log_file = Path(log_file) if log_file else None
        self.traffic: list[dict[str, Any]] = []
        self.rules: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.server_socket: socket.socket | None = None
        self.thread = threading.Thread(target=self._serve, daemon=True)

    @staticmethod
    def _sni_from_client_hello(data: bytes) -> str | None:
        """Parse the SNI hostname out of a TLS ClientHello (no crypto involved)."""
        try:
            if len(data) < 5 or data[0] != 0x16:  # not a TLS handshake record
                return None
            record_length = int.from_bytes(data[3:5], "big")
            if 5 + record_length > len(data):
                return None
            handshake = data[5 : 5 + record_length]
            if not handshake or handshake[0] != 0x01:  # not ClientHello
                return None
            hello_length = int.from_bytes(handshake[1:4], "big")
            hello = handshake[4 : 4 + hello_length]
            offset = 2 + 32  # client version + random
            sid_len = hello[offset]
            offset += 1 + sid_len
            cipher_len = int.from_bytes(hello[offset : offset + 2], "big")
            offset += 2 + cipher_len
            comp_len = hello[offset]
            offset += 1 + comp_len
            ext_len = int.from_bytes(hello[offset : offset + 2], "big")
            offset += 2
            extensions = hello[offset : offset + ext_len]
            cursor = 0
            while cursor + 4 <= len(extensions):
                ext_type = int.from_bytes(extensions[cursor : cursor + 2], "big")
                ext_size = int.from_bytes(extensions[cursor + 2 : cursor + 4], "big")
                payload = extensions[cursor + 4 : cursor + 4 + ext_size]
                cursor += 4 + ext_size
                if ext_type == 0x0000 and len(payload) >= 5:  # server_name
                    name_len = int.from_bytes(payload[3:5], "big")
                    return payload[5 : 5 + name_len].decode("latin-1", "replace")
            return None
        except Exception:
            return None

    @staticmethod
    def _host_from_http(data: bytes) -> str | None:
        """Pull the Host header out of a plaintext HTTP request head."""
        try:
            head = data[:2048].decode("latin-1", "replace")
            for line in head.split("\r\n"):
                if line.lower().startswith("host:"):
                    return line.split(":", 1)[1].strip().split(":")[0]
        except Exception:
            pass
        return None

    def _route_upstream(self, client_socket: socket.socket) -> tuple[str, int]:
        """Decide the upstream for this connection by SNI (TLS) or Host header (HTTP)."""
        if not self.upstream_map:
            return self.default_upstream
        try:
            client_socket.settimeout(5)
            first = client_socket.recv(4096, socket.MSG_PEEK)
            client_socket.settimeout(None)
            host = self._sni_from_client_hello(first) if first[:1] == b"\x16" else self._host_from_http(first)
            if host and host in self.upstream_map:
                target = self.upstream_map[host]
                host_part, _, port_part = target.partition(":")
                return host_part, int(port_part or (443 if self.upstream_tls else 80))
        except OSError:
            pass
        return self.default_upstream

    def _apply_rules(self, data: bytes, direction: str) -> bytes:
        for rule in self.rules:
            if rule["direction"] not in (direction, "both"):
                continue
            if rule["find"] in data:
                data = data.replace(rule["find"], rule["replace"])
        return data

    def _pump(self, source: socket.socket, destination: socket.socket, direction: str, session: int) -> None:
        try:
            while not self._stop.is_set():
                chunk = source.recv(65536)
                if not chunk:
                    break
                forwarded = self._apply_rules(chunk, direction)
                if forwarded != chunk:
                    with self._lock:
                        self.traffic.append({
                            "session": session, "direction": direction, "rewritten": True,
                            "original_hex": chunk.hex()[:512], "rewritten_hex": forwarded.hex()[:512],
                            "at": round(time.time(), 3),
                        })
                try:
                    destination.sendall(forwarded)
                except OSError:
                    break
                with self._lock:
                    printable = all(32 <= b <= 126 or b in (9, 10, 13) for b in chunk[:256])
                    entry = {
                        "session": session, "direction": direction, "bytes": len(chunk),
                        "text": chunk[:512].decode("utf-8", "replace") if printable else None,
                        "hex": None if printable else chunk[:256].hex(),
                        "at": round(time.time(), 3),
                    }
                    self.traffic.append(entry)
                    del self.traffic[:-2000]
                    if self.log_file:
                        # JSONL with the FULL body (base64): the record half of
                        # record->replay, post-termination so bodies are plaintext.
                        try:
                            line = json.dumps({**entry, "body_b64": __import__("base64").b64encode(chunk).decode()}, ensure_ascii=False)
                            with open(self.log_file, "a", encoding="utf-8") as handle:
                                handle.write(line + "\n")
                        except OSError:
                            pass
        except OSError:
            pass
        finally:
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _serve(self) -> None:
        session = 0
        while not self._stop.is_set():
            try:
                client, address = self.server_socket.accept()
            except OSError:
                break
            session += 1
            # TLS termination: the client side is wrapped with the mock certificate, so
            # the target sees a normal HTTPS endpoint while we read plaintext both ways.
            if self.tls_terminate:
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    cert_info = mock_certificate()
                    context.load_cert_chain(cert_info["cert"], cert_info["key"])
                    client = context.wrap_socket(client, server_side=True)
                except (OSError, ssl.SSLError) as exc:
                    with self._lock:
                        self.traffic.append({"session": session, "error": f"TLS handshake failed: {exc}", "at": round(time.time(), 3)})
                    client.close()
                    continue
            # SNI (TLS ClientHello) or Host header (plain HTTP) decides the upstream:
            # three domains on one listen port, three different real servers behind it.
            upstream_addr = self._route_upstream(client)
            try:
                upstream = socket.create_connection(upstream_addr, timeout=8)
                if self.upstream_tls:
                    upstream_context = ssl.create_default_context()
                    upstream_context.check_hostname = False
                    upstream_context.verify_mode = ssl.CERT_NONE
                    upstream = upstream_context.wrap_socket(upstream, server_hostname=upstream_addr[0])
            except OSError as exc:
                with self._lock:
                    self.traffic.append({"session": session, "error": f"upstream connect failed: {exc}", "at": round(time.time(), 3)})
                client.close()
                continue

            threading.Thread(target=self._pump, args=(client, upstream, "client->server", session), daemon=True).start()
            threading.Thread(target=self._pump, args=(upstream, client, "server->client", session), daemon=True).start()

    def start(self) -> None:
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("0.0.0.0", self.listen_port))
        self.server_socket.listen(16)
        self.server_socket.settimeout(0.5)
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.server_socket.close()
        except OSError:
            pass
        self.thread.join(timeout=3)

    def add_rule(self, find_hex: str, replace_hex: str, direction: str) -> None:
        self.rules.append({
            "find": bytes.fromhex(find_hex), "replace": bytes.fromhex(replace_hex), "direction": direction,
        })


_PROXIES: dict[int, _TcpProxy] = {}
_PROXY_LOCK = threading.Lock()


def tcp_proxy_start(
    listen_port: int,
    upstream_host: str,
    upstream_port: int,
    *,
    tls_terminate: bool = False,
    upstream_map: dict[str, str] | None = None,
    upstream_tls: bool = False,
    log_file: str | None = None,
) -> dict[str, Any]:
    """Start a transparent logging proxy: target -> us -> real server.

    Redirect the target to 127.0.0.1:listen_port (hosts entry or config), and the real
    conversation flows through here - recorded both ways, with optional byte rewriting.
    ``tls_terminate=True`` wraps the client side with the mock certificate: the target
    speaks HTTPS to us, we see plaintext, and upstream re-encrypts. Install
    ``net_mock_certificate`` into the trust store first for pinning-free targets.

    ``upstream_map`` routes one listen port to many upstreams: ``{"api.vendor.gg":
    "203.0.113.5:443", "download.vendor.live": "203.0.113.9:443"}`` - the upstream is
    chosen per connection by TLS SNI or HTTP Host header (the case where three domains
    share one hosts-redirected address). ``upstream_tls=True`` re-encrypts the upstream
    side. ``log_file`` records every chunk as JSONL with full base64 bodies - the
    record half of record->replay.
    """
    with _PROXY_LOCK:
        if listen_port in _PROXIES:
            return {"error": f"a proxy already listens on {listen_port}"}
        proxy = _TcpProxy(
            listen_port, upstream_host, upstream_port,
            tls_terminate=tls_terminate, upstream_map=upstream_map,
            upstream_tls=upstream_tls, log_file=log_file,
        )
        try:
            proxy.start()
        except OSError as exc:
            return {"error": f"could not bind {listen_port}: {exc}"}
        _PROXIES[listen_port] = proxy
        return {
            "listening": True,
            "listen_port": listen_port,
            "upstream": f"{upstream_host}:{upstream_port}",
            "upstream_map": upstream_map or {},
            "tls_terminate": tls_terminate,
            "log_file": log_file,
            "note": (
                "traffic flows and is logged; add rewrite rules with tcp_proxy_rule"
                if not tls_terminate
                else "TLS is terminated with the mock cert; traffic is logged as plaintext"
            ),
        }


def tcp_proxy_stop(listen_port: int) -> dict[str, Any]:
    """Stop a TCP proxy."""
    with _PROXY_LOCK:
        proxy = _PROXIES.pop(listen_port, None)
    if proxy is None:
        return {"error": f"no proxy on {listen_port}"}
    proxy.stop()
    return {"stopped": True, "port": listen_port, "sessions_logged": len(proxy.traffic)}


def tcp_proxy_rule(listen_port: int, find_hex: str, replace_hex: str, direction: str = "server->client") -> dict[str, Any]:
    """Add a byte-level rewrite rule to a running proxy - forged responses, no server touched.

    ``find_hex``/``replace_hex`` must have equal byte length (in-place substitution).
    ``direction``: server->client (forging responses), client->server (forging requests),
    or both.
    """
    if len(find_hex) != len(replace_hex):
        return {"error": "find and replace hex must have the same byte length (in-place rewrite)"}
    if direction not in ("server->client", "client->server", "both"):
        return {"error": f"direction must be server->client, client->server, or both, got {direction!r}"}
    with _PROXY_LOCK:
        proxy = _PROXIES.get(listen_port)
    if proxy is None:
        return {"error": f"no proxy on {listen_port}"}
    proxy.add_rule(find_hex, replace_hex, direction)
    return {"rule_added": True, "find": find_hex, "replace": replace_hex, "direction": direction}


def tcp_proxy_traffic(listen_port: int, *, limit: int = 100, clear: bool = False) -> dict[str, Any]:
    """Read (and optionally clear) what flowed through a proxy, newest last."""
    with _PROXY_LOCK:
        proxy = _PROXIES.get(listen_port)
    if proxy is None:
        return {"error": f"no proxy on {listen_port}"}
    with proxy._lock:
        entries = proxy.traffic[-limit:]
        if clear:
            proxy.traffic.clear()
        rewritten = sum(1 for e in proxy.traffic if e.get("rewritten"))
    return {"count": len(entries), "total": len(proxy.traffic), "rewritten_events": rewritten, "traffic": entries}


# --------------------------------------------------------------------------
# hosts file redirection
# --------------------------------------------------------------------------
_HOSTS = Path(r"C:\Windows\System32\drivers\etc\hosts")
_HOSTS_MARKER = "# ghidra-mcp"


def hosts_add(hostname: str, ip: str = "127.0.0.1") -> dict[str, Any]:
    """Redirect a hostname to an ip via the hosts file (e.g. api.vendor.com -> 127.0.0.1).

    The forge half of pointing a target's API calls at the mock server. Entries are
    marked, so hosts_remove takes back only ours. Takes effect immediately for new
    connections; running apps cache DNS - restart them.
    """
    if not _HOSTS.exists():
        return {"error": f"hosts file not found at {_HOSTS}"}
    text = _HOSTS.read_text(encoding="utf-8", errors="replace")
    if f"{_HOSTS_MARKER} {hostname}" in text:
        return {"added": False, "note": f"{hostname} is already redirected; remove it first"}
    line = f"{ip}\t{hostname}\t{_HOSTS_MARKER} {hostname}"
    _HOSTS.write_text(text.rstrip("\r\n") + "\n" + line + "\n", encoding="utf-8")
    import subprocess as _sp

    _sp.run(["ipconfig", "/flushdns"], capture_output=True, timeout=15)
    return {"added": True, "entry": line}


def hosts_remove(hostname: str) -> dict[str, Any]:
    """Remove a ghidra-mcp hosts entry, restoring normal DNS."""
    if not _HOSTS.exists():
        return {"error": f"hosts file not found at {_HOSTS}"}
    lines = _HOSTS.read_text(encoding="utf-8", errors="replace").splitlines()
    kept = [line for line in lines if not line.endswith(f"{_HOSTS_MARKER} {hostname}")]
    if len(kept) == len(lines):
        return {"removed": False, "note": f"no ghidra-mcp entry for {hostname}"}
    _HOSTS.write_text("\n".join(kept) + "\n", encoding="utf-8")
    import subprocess as _sp

    _sp.run(["ipconfig", "/flushdns"], capture_output=True, timeout=15)
    return {"removed": True, "hostname": hostname}


def hosts_list() -> dict[str, Any]:
    """List the ghidra-mcp hosts redirections currently active."""
    if not _HOSTS.exists():
        return {"entries": []}
    entries = [
        line for line in _HOSTS.read_text(encoding="utf-8", errors="replace").splitlines()
        if _HOSTS_MARKER in line
    ]
    return {"count": len(entries), "entries": entries}


# --------------------------------------------------------------------------
# record -> replay: capture real upstream exchanges, turn them into routes
# --------------------------------------------------------------------------
def mock_record(port: int, *, stop: bool = False) -> dict[str, Any]:
    """Show (or stop) the recording of upstream exchanges on a hybrid mock server.

    Works with mock_start(record=True): every unmatched request is forwarded to the
    real upstream and its request+response stored here - the raw material for
    mock_generate.
    """
    with _ROUTE_LOCK:
        recording = _RECORDINGS.get(port)
        if recording is None:
            return {"error": f"no recording on {port}; mock_start(record=True) first"}
        result = {"port": port, "recorded": len(recording), "exchanges": list(recording)}
        if stop:
            _RECORDINGS.pop(port, None)
            result["stopped"] = True
        return result


def mock_generate(port: int, transforms: dict[str, list[dict[str, str]]] | None = None, *, clear_existing: bool = False) -> dict[str, Any]:
    """Generate mock routes from a recording: replay real responses, transform on serve.

    For every recorded exchange this creates a route (method + exact path -> recorded
    status/body), so the mock replays the real server conversation without the real
    server. ``transforms`` maps path patterns to serve-time regex substitutions for
    dynamic fields: ``{"/api/handshake": [{"find": "nonce\":\"[0-9a-f]+\"", "replace":
    "nonce\":\"0000"}]}`` - nonces, timestamps, and signature blobs rewritten at every
    response, so the client's freshness checks see a consistent forged world.
    """
    with _ROUTE_LOCK:
        recording = _RECORDINGS.get(port)
        if recording is None:
            return {"error": f"no recording on {port}; mock_start(record=True) first"}
        if clear_existing:
            _ROUTES.clear()
        created = 0
        for exchange in recording:
            pattern = _re.escape(exchange["path"].split("?")[0])
            key = f"{exchange['method']} {pattern}"
            bucket = _ROUTES.setdefault(key, [])
            route = {
                "status": exchange["status"],
                "body_hex": bytes.fromhex(exchange["response_body_hex"]).hex(),
                "content_type": exchange["response_headers"].get("Content-Type", "application/octet-stream"),
                "headers": {k: v for k, v in exchange["response_headers"].items() if k.lower() in ("content-type", "cache-control", "server")},
                "delay": 0.0,
                "query": {},
            }
            for path_re, rules in (transforms or {}).items():
                if _re.fullmatch(path_re, exchange["path"].split("?")[0]):
                    route["transform"] = rules
            if not any(r.get("body_hex") == route["body_hex"] and r.get("query") == route["query"] for r in bucket):
                bucket.append(route)
                created += 1
        # Query-specific routes first, fallbacks last - same ordering mock_route uses.
        for bucket in _ROUTES.values():
            bucket.sort(key=lambda r: not bool(r.get("query")))
        return {
            "generated": created,
            "routes_total": sum(len(v) for v in _ROUTES.values()),
            "recorded_exchanges": len(recording),
            "note": "responses replay verbatim; transforms substitute dynamic fields at serve time",
        }
