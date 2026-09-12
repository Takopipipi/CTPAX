"""Wireshark bridge: capture (dumpcap), analysis (tshark), and a minimal pcap writer
that turns the MCP's own tcp_proxy recordings into files Wireshark opens natively.

Windows installs ship the CLI tools in ``C:\\Program Files\\Wireshark\\``; they are the
whole interface - the GUI is for humans. dumpcap needs elevation for most interfaces
(Windows packet capture is a protected operation), so capture errors come back with
that hint instead of failing silently.

The pcap writer here exists for one job: the forgeries and MITM traffic this toolkit
produces should be viewable in Wireshark's follow-stream view without the tester
hand-writing hex dumps for text2pcap. It emits a classic Ethernet/IPv4/TCP pcap with
per-direction sequence tracking per session - good enough for content analysis, not a
forensics-grade reproduction.
"""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

_WIRESHARK_DIRS = (
    r"C:\Program Files\Wireshark",
    r"C:\Program Files (x86)\Wireshark",
)

_ACTIVE_CAPTURES: dict[str, dict[str, Any]] = {}


def _find_tool(name: str) -> str | None:
    """PATH, then the standard install dirs, then WSL."""
    from shutil import which

    found = which(name)
    if found:
        return found
    for directory in _WIRESHARK_DIRS:
        candidate = Path(directory) / f"{name}.exe"
        if candidate.is_file():
            return str(candidate)
    try:
        result = subprocess.run(["wsl.exe", "which", name], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def _run(tool: str, args: list[str], *, timeout: float = 120.0) -> dict[str, Any]:
    executable = _find_tool(tool)
    if executable is None:
        return {
            "error": f"{tool} not found. Install Wireshark (winget install WiresharkFoundation.Wireshark "
            f"or the installer from wireshark.org) - the CLI tools are what these tools drive.",
        }
    try:
        result = subprocess.run(
            [executable, *args], capture_output=True, text=True, errors="replace", timeout=timeout,
        stdin=subprocess.DEVNULL,
        )
        return {"code": result.returncode, "stdout": result.stdout or "", "stderr": result.stderr or ""}
    except subprocess.TimeoutExpired:
        return {"error": f"{tool} exceeded {timeout}s"}
    except OSError as exc:
        return {"error": f"{tool} failed to run: {exc}"}


def ws_status() -> dict[str, Any]:
    """Detect tshark/dumpcap/text2pcap and list capture interfaces."""
    status: dict[str, Any] = {"tools": {}, "interfaces": None, "install_hint": None}
    for tool in ("tshark", "dumpcap", "text2pcap", "editcap"):
        executable = _find_tool(tool)
        status["tools"][tool] = executable
        if executable and tool == "tshark":
            version = _run(tool, ["--version"])
            if "stdout" in version:
                status["tshark_version"] = version["stdout"].splitlines()[0]
    if status["tools"].get("dumpcap"):
        listing = _run("dumpcap", ["-D"])
        if "stdout" in listing and listing["stdout"].strip():
            status["interfaces"] = listing["stdout"].strip().splitlines()
    if not status["tools"].get("tshark"):
        status["install_hint"] = "winget install WiresharkFoundation.Wireshark  (or wireshark.org installer)"
    return status


def ws_capture_start(name: str, interface: str = "1", *, capture_filter: str | None = None,
                     snaplen: int = 65535, out_dir: str | None = None) -> dict[str, Any]:
    """Start a background dumpcap capture on an interface (see ws_status for the list).

    Interface is the number or name from dumpcap -D. Windows requires elevation for
    capture - run the MCP elevated or grant dumpcap the SeCaptureNetworkSecurity
    right. ``capture_filter`` is a BPF (tcp port 443 and host 203.0.113.5).
    """
    if name in _ACTIVE_CAPTURES:
        return {"error": f"capture {name!r} is already running"}
    executable = _find_tool("dumpcap")
    if executable is None:
        return {"error": "dumpcap not found - install Wireshark first (see ws_status)"}
    destination = Path(out_dir) if out_dir else Path(tempfile.gettempdir())
    pcap = destination / f"capture_{name}.pcap"
    if pcap.exists():
        pcap.unlink()
    command = [executable, "-i", interface, "-s", str(snaplen), "-w", str(pcap)]
    if capture_filter:
        command += ["-f", capture_filter]
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
    except OSError as exc:
        return {"error": f"dumpcap failed to start: {exc}"}
    time.sleep(0.5)
    if process.poll() is not None:
        return {"error": "dumpcap exited immediately - capture needs elevation (run elevated) or the interface is wrong"}
    _ACTIVE_CAPTURES[name] = {"process": process, "pcap": str(pcap), "interface": interface}
    return {"capturing": True, "name": name, "pcap": str(pcap), "interface": interface,
            "note": "ws_capture_read reads it live, ws_capture_stop ends it"}


def ws_capture_stop(name: str) -> dict[str, Any]:
    """Stop a named capture; the pcap stays for analysis."""
    capture = _ACTIVE_CAPTURES.pop(name, None)
    if capture is None:
        return {"error": f"no capture named {name!r}"}
    try:
        capture["process"].terminate()
        capture["process"].wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        try:
            capture["process"].kill()
        except OSError:
            pass
    pcap = Path(capture["pcap"])
    return {"stopped": True, "name": name, "pcap": str(pcap),
            "size_bytes": pcap.stat().st_size if pcap.exists() else 0}


def ws_capture_read(name: str, *, display_filter: str | None = None, limit: int = 50) -> dict[str, Any]:
    """Read frames from a live/finished capture: time, endpoints, protocol, summary."""
    capture = _ACTIVE_CAPTURES.get(name)
    if capture is None:
        return {"error": f"no capture named {name!r}"}
    return ws_read_pcap(capture["pcap"], display_filter=display_filter, limit=limit)


def ws_read_pcap(path: str, *, display_filter: str | None = None, limit: int = 50,
                 fields: list[str] | None = None) -> dict[str, Any]:
    """Parse a pcap/pcapng with tshark: summary rows or specific ``fields`` per frame.

    ``display_filter`` is Wireshark's own syntax (http.request, ip.addr == 1.2.3.4,
    tcp.stream eq 3). Default columns: frame.time_epoch, ip.src, ip.dst, protocol,
    info. With ``fields``, output is one row per frame with exactly those columns.
    """
    pcap = Path(path)
    if not pcap.is_file():
        return {"error": f"no such capture: {pcap}"}
    columns = fields or ["frame.time_epoch", "ip.src", "ip.dst", "_ws.col.protocol", "_ws.col.info"]
    args = ["-r", str(pcap), "-c", str(limit)]
    if display_filter:
        args += ["-Y", display_filter]
    args += ["-T", "fields", "-E", "header=y", "-E", "separator=|", "-E", "quote=n"]
    for column in columns:
        args += ["-e", column]
    result = _run("tshark", args, timeout=180)
    if "error" in result:
        return result
    rows = [line for line in result["stdout"].splitlines() if line.strip()]
    header = rows[0].split("|") if rows else []
    frames = [dict(zip(header, row.split("|"))) for row in rows[1:]]
    return {"pcap": str(pcap), "frames": frames, "count": len(frames),
            "stderr": result["stderr"][-400:] if result["stderr"] else None}


def ws_streams(path: str, *, protocol: str = "tcp", limit: int = 20) -> dict[str, Any]:
    """Conversation table: who talked to whom, bytes both ways - the triage view."""
    pcap = Path(path)
    if not pcap.is_file():
        return {"error": f"no such capture: {pcap}"}
    result = _run("tshark", ["-r", str(pcap), "-q", "-z", f"conv,{protocol}"], timeout=120)
    if "error" in result:
        return result
    table = result["stdout"].strip().splitlines()
    return {"pcap": str(pcap), "protocol": protocol, "table": table[: limit + 3]}


def ws_follow_stream(path: str, stream_index: int, *, format: str = "ascii") -> dict[str, Any]:
    """Follow one TCP stream (index from ws_read_pcap's tcp.stream column) as ASCII."""
    pcap = Path(path)
    if not pcap.is_file():
        return {"error": f"no such capture: {pcap}"}
    result = _run("tshark", ["-r", str(pcap), "-q", "-z", f"follow,tcp,{format},{stream_index}"], timeout=120)
    if "error" in result:
        return result
    return {"pcap": str(pcap), "stream": stream_index, "conversation": result["stdout"][:30000]}


def ws_export_objects(path: str, protocol: str = "http", out_dir: str | None = None) -> dict[str, Any]:
    """Export files transferred in the capture (http/dicom/tftp...) to a directory."""
    pcap = Path(path)
    if not pcap.is_file():
        return {"error": f"no such capture: {pcap}"}
    destination = Path(out_dir) if out_dir else pcap.parent / f"{pcap.stem}_objects"
    destination.mkdir(parents=True, exist_ok=True)
    result = _run("tshark", ["-r", str(pcap), "--export-objects", f"{protocol},{destination}"], timeout=300)
    if "error" in result:
        return result
    files = [entry.name for entry in destination.iterdir()]
    return {"pcap": str(pcap), "protocol": protocol, "out_dir": str(destination), "files": files[:100],
            "stderr": result["stderr"][-300:] if result["stderr"] else None}


# --------------------------------------------------------------------------
# pcap writer: tcp_proxy recordings -> Wireshark
# --------------------------------------------------------------------------
_PCAP_GLOBAL = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # Ethernet linktype


def _ipv4(text: str) -> bytes:
    return bytes(int(part) for part in text.split("."))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack_from(f">{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes, at: float) -> bytes:
    tcp_header = struct.pack(
        ">HHIIBBHHH", src_port, dst_port, seq, ack, 0x50, flags, 0xFFFF, 0, 0,
    )
    pseudo = _ipv4(src_ip) + _ipv4(dst_ip) + struct.pack(">BBH", 0, 6, len(tcp_header) + len(payload))
    tcp_header = tcp_header[:16] + struct.pack(">H", _checksum(pseudo + tcp_header + payload)) + tcp_header[18:]
    total_length = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(">BBHHHBBH", 0x45, 0, total_length, 0, 0x4000, 64, 6, 0) + _ipv4(src_ip) + _ipv4(dst_ip)
    ip_header = ip_header[:10] + struct.pack(">H", _checksum(ip_header)) + ip_header[12:]
    ethernet = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    frame = ethernet + ip_header + tcp_header + payload
    ts_sec = int(at)
    ts_usec = int((at - ts_sec) * 1_000_000) % 1_000_000
    return struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame


def ws_pcap_from_proxy(log_file: str, *, out_file: str | None = None) -> dict[str, Any]:
    """Turn a tcp_proxy session's JSONL traffic into a pcap for Wireshark.

    Source: the proxy's JSONL log - tcp_proxy_start(log_file=...) writes full bodies
    (base64) for every chunk both directions. Each session becomes one TCP
    conversation 127.0.0.1:4xxxx <-> 10.0.0.1:8443 with per-direction sequence
    numbers, so follow-stream shows the whole MITM conversation - including the
    rewrites the proxy applied.
    """
    import base64
    import json

    log = Path(log_file)
    if not log.is_file():
        return {"error": f"no such proxy log: {log}"}
    entries: list[dict[str, Any]] = []
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "body_b64" in entry:
                entries.append(entry)

    destination = Path(out_file) if out_file else Path(tempfile.gettempdir()) / f"proxy_{int(time.time())}.pcap"
    sessions: set[int] = set()
    with open(destination, "wb") as handle:
        handle.write(_PCAP_GLOBAL)
        for entry in entries:
            session = int(entry["session"])
            sessions.add(session)
            direction = entry["direction"]
            body = base64.b64decode(entry.get("body_b64") or "")
            if direction == "client->server":
                src_ip, dst_ip, src_port, dst_port = "127.0.0.1", "10.0.0.1", 40000 + session % 20000, 8443
            else:
                src_ip, dst_ip, src_port, dst_port = "10.0.0.1", "127.0.0.1", 8443, 40000 + session % 20000
            key = f"{src_port}>{dst_port}"
            if key not in _SEQ_STATE:
                _SEQ_STATE[key] = {"seq": 1000, "ack": 1000}
            flow = _SEQ_STATE[key]
            handle.write(_packet(src_ip, dst_ip, src_port, dst_port, flow["seq"], flow["ack"], 0x18, body, float(entry.get("at") or time.time())))
            flow["seq"] += max(1, len(body))
    return {
        "pcap": str(destination),
        "frames": len(entries),
        "sessions": len(sessions),
        "size_bytes": destination.stat().st_size,
        "note": "open in Wireshark or parse with ws_read_pcap / ws_follow_stream; per-session conversations",
    }


_SEQ_STATE: dict[str, dict[str, int]] = {}
