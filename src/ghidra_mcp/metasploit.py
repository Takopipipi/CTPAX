"""Metasploit bridge: discovery, payload generation (msfvenom), console scripting, and
the msgpack RPC API (msfrpcd) for module execution and session control.

Metasploit does not ship with Windows tooling: the honest layouts are a native
framework install (rare), or WSL/Kali (the normal route). Every entry point resolves
the binary in this order - PATH, C:\\metasploit-framework\\bin, WSL - and returns an
actionable install hint when nothing is found. The RPC client speaks msgrpc v1.1
directly (msgpack over HTTP, no pymetasploit dependency).

Authorization boundary: these tools are for labs and targets you are permitted to
test. Nothing here makes that judgement for you.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import msgpack

_MSF_DIR = r"C:\metasploit-framework\bin"
_RPC_PORT_DEFAULT = 55553
_INSTALL_HINT = (
    "Metasploit not found. Options: (a) WSL/Kali: `sudo apt update && sudo apt install -y "
    "metasploit-framework`, (b) the official Windows installer from docs.rapid7.com "
    "(installs to C:\\metasploit-framework). msf_status re-detects after install."
)

_RPC_STATE: dict[str, Any] = {"url": None, "token": None}


def _resolve(binary: str) -> str | None:
    """PATH scan, then the standard Windows install dir."""
    from shutil import which

    found = which(binary)
    if found:
        return found
    candidate = Path(_MSF_DIR) / f"{binary}.bat"
    if candidate.is_file():
        return str(candidate)
    candidate = Path(_MSF_DIR) / f"{binary}"
    if candidate.is_file():
        return str(candidate)
    return None


def _wsl_which(binary: str) -> bool:
    try:
        result = subprocess.run(
            ["wsl.exe", "which", binary], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
        )
        return result.returncode == 0 and result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return False


def _prefix() -> list[str]:
    """Command prefix: native run, or through WSL when only WSL has the tool."""
    return [] if _resolve("msfconsole") else (["wsl.exe", "-e"] if _wsl_which("msfconsole") else [])


def msf_status() -> dict[str, Any]:
    """Detect the framework: native install, WSL, and a live RPC daemon."""
    status: dict[str, Any] = {"native": {}, "wsl": {}, "rpc": {}}
    for binary in ("msfconsole", "msfvenom", "msfrpcd"):
        status["native"][binary] = _resolve(binary)
    status["wsl"]["available"] = _wsl_which("msfconsole")
    version = None
    console = _resolve("msfconsole")
    if console:
        try:
            result = subprocess.run([console, "--version"], capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
            version = (result.stdout or result.stderr).strip().splitlines()[0]
        except (OSError, subprocess.TimeoutExpired):
            pass
    if version is None and status["wsl"]["available"]:
        try:
            result = subprocess.run(
                ["wsl.exe", "-e", "msfconsole", "--version"], capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL,
            )
            version = (result.stdout or result.stderr).strip().splitlines()[0]
        except (OSError, subprocess.TimeoutExpired):
            pass
    status["version"] = version
    status["rpc"] = _rpc_ping()
    status["install_hint"] = None if (version or status["rpc"].get("alive")) else _INSTALL_HINT
    return status


def msf_console(script: str, *, timeout: float = 300.0) -> dict[str, Any]:
    """Run a resource script through msfconsole -q -r: the universal escape hatch.

    Anything msfconsole can do (db_nmap, auxiliary modules, custom flows) is reachable
    here: the script is written to a temp .rc and its full console output comes back.
    For interactive-style work prefer the RPC tools; for one-shot batches this wins.
    """
    console = _resolve("msfconsole")
    if console is None and _wsl_which("msfconsole") is False:
        return {"error": _INSTALL_HINT}
    rc_path = Path(tempfile.gettempdir()) / f"msf_rc_{int(time.time())}.rc"
    rc_path.write_text(script, encoding="utf-8")
    prefix = _prefix()
    command = [*prefix, console if not prefix else "msfconsole", "-q", "-r", _wsl_path(rc_path) if prefix else str(rc_path)]
    try:
        started = time.time()
        result = subprocess.run(
            command, capture_output=True, text=True, errors="replace", timeout=timeout,
            input="y\n",
        )
        return {
            "script": script,
            "elapsed": round(time.time() - started, 1),
            "output": (result.stdout or "")[-30000:],
            "stderr": (result.stderr or "")[-2000:],
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"msfconsole exceeded {timeout}s - break the work into smaller scripts"}
    finally:
        try:
            rc_path.unlink()
        except OSError:
            pass


def _wsl_path(path: Path) -> str:
    """Windows path -> WSL path (/mnt/c/...)."""
    drive = path.drive.rstrip(":").lower()
    return f"/mnt/{drive}{path.as_posix()[2:]}"


# --------------------------------------------------------------------------
# msfvenom: payload generation
# --------------------------------------------------------------------------
def msf_venom(
    payload: str,
    *,
    format: str = "exe",
    output_file: str | None = None,
    options: dict[str, str] | None = None,
    encoder: str | None = None,
    iterations: int | None = None,
) -> dict[str, Any]:
    """Generate a payload with msfvenom (LHOST/LPORT etc. via ``options``).

    ``options`` are plain msfvenom VAR=value pairs: {"LHOST": "127.0.0.1", "LPORT":
    "4444"}. Output lands in the temp dir unless ``output_file`` names an absolute
    path. For lab use against your own targets - the point in this toolkit is
    testing the MCP's own mock/forgery infrastructure end to end.
    """
    venom = _resolve("msfvenom")
    prefix = _prefix()
    if venom is None and not prefix:
        return {"error": _INSTALL_HINT}
    destination = Path(output_file) if output_file else Path(tempfile.gettempdir()) / f"payload_{int(time.time())}.{format}"
    if not destination.is_absolute():
        return {"error": "output_file must be absolute"}
    command = [*prefix, (venom if not prefix else "msfvenom"), "-p", payload, "-f", format, "-o", _wsl_path(destination) if prefix else str(destination)]
    for key, value in (options or {}).items():
        command.append(f"{key}={value}")
    if encoder:
        command += ["-e", encoder]
    if iterations:
        command += ["-i", str(iterations)]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, errors="replace", timeout=600, stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0 or not destination.is_file():
            return {
                "error": "msfvenom failed",
                "stderr": (result.stderr or "")[-2000:],
                "stdout": (result.stdout or "")[-2000:],
            }
        return {
            "payload": payload,
            "format": format,
            "file": str(destination),
            "size_bytes": destination.stat().st_size,
            "sha256_first16": __import__("hashlib").sha256(destination.read_bytes()).hexdigest()[:16],
        }
    except subprocess.TimeoutExpired:
        return {"error": "msfvenom exceeded 600s"}


# --------------------------------------------------------------------------
# msgpack RPC client (msgrpc v1.1)
# --------------------------------------------------------------------------
def _rpc_call(method: str, *args: Any, timeout: float = 300.0) -> dict[str, Any]:
    """One msgrpc v1.1 call: msgpack array over HTTP POST."""
    import urllib.request

    url = _RPC_STATE.get("url")
    if not url:
        return {"error": "RPC not connected - call msf_rpc_start first (or msf_rpc_connect to an existing daemon)"}
    body = msgpack.packb([method, _RPC_STATE.get("token"), *args], use_bin_type=True)
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "binary/message-pack"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read()
    except OSError as exc:
        return {"error": f"RPC call failed: {exc}"}
    try:
        return msgpack.unpackb(payload, raw=False)
    except Exception as exc:
        return {"error": f"bad RPC response: {exc}", "raw": payload[:200].hex()}


def _rpc_ping(port: int = _RPC_PORT_DEFAULT) -> dict[str, Any]:
    import urllib.request

    url = f"http://127.0.0.1:{port}/api/1.1/"
    body = msgpack.packb(["core.version", ""], use_bin_type=True)
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "binary/message-pack"})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            data = msgpack.unpackb(response.read(), raw=False)
        return {"alive": True, "version": data.get("version"), "ruby": data.get("ruby")}
    except (OSError, Exception):
        return {"alive": False}


def msf_rpc_start(password: str, *, port: int = _RPC_PORT_DEFAULT, user: str = "msf") -> dict[str, Any]:
    """Start msfrpcd (native or WSL) and log in; later RPC tools reuse this session.

    The daemon listens on 127.0.0.1 only. First start takes ~30-60s (framework boot).
    """
    rpc = _resolve("msfrpcd")
    prefix = _prefix()
    if rpc is None and not prefix:
        if _rpc_ping(port).get("alive"):
            return msf_rpc_connect(password, port=port, user=user)
        return {"error": _INSTALL_HINT}
    alive = _rpc_ping(port)
    if not alive.get("alive"):
        command = [*prefix, (rpc if not prefix else "msfrpcd"), "-P", password, "-S", "-a", "127.0.0.1", "-p", str(port), "-u", user]
        subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 120
        while time.time() < deadline:
            time.sleep(3)
            if _rpc_ping(port).get("alive"):
                break
    return msf_rpc_connect(password, port=port, user=user)


def msf_rpc_connect(password: str, *, port: int = _RPC_PORT_DEFAULT, user: str = "msf") -> dict[str, Any]:
    """Log into an already-running msfrpcd and cache the token."""
    _RPC_STATE["url"] = f"http://127.0.0.1:{port}/api/1.1/"
    _RPC_STATE["token"] = None
    response = _rpc_call("auth.login", user, password)
    if response.get("error_class"):
        return {"error": f"login failed: {response.get('error_message')}"}
    token = response.get("token")
    if not token:
        return {"error": f"no token in response: {response}"}
    _RPC_STATE["token"] = token
    version = _rpc_call("core.version")
    return {"connected": True, "port": port, "version": version.get("version")}


# --------------------------------------------------------------------------
# RPC-backed work: search, run, sessions
# --------------------------------------------------------------------------
def msf_search(query: str, *, limit: int = 20) -> dict[str, Any]:
    """Search modules by name/type/rank (same index msfconsole's `search` uses)."""
    results = _rpc_call("module.search", query)
    if isinstance(results, dict) and results.get("error_class"):
        return results
    return {"query": query, "count": len(results or []), "modules": (results or [])[:limit]}


def msf_module_info(module_type: str, name: str) -> dict[str, Any]:
    """Full module detail: options, targets, references (type: exploit|auxiliary|payload|encoder|post|nop)."""
    info = _rpc_call("module.info", module_type, name)
    if isinstance(info, dict) and info.get("error_class"):
        return info
    options = _rpc_call("module.options", module_type, name)
    return {"info": info, "options": options}


def msf_module_run(module_type: str, name: str, options: dict[str, Any], *, run_as_job: bool = True) -> dict[str, Any]:
    """Execute a module with options; returns job id (and session when immediate).

    Options are the module's own: RHOSTS, RPORT, LHOST, LPORT, PAYLOAD, TARGET...
    Read them with msf_module_info first. Sessions appear in msf_sessions.
    """
    response = _rpc_call("module.execute", module_type, name, options, timeout=900)
    if isinstance(response, dict) and response.get("error_class"):
        return response
    return {"job_id": response.get("job_id"), "uuid": response.get("uuid"), "started": True}


def msf_sessions() -> dict[str, Any]:
    """List open sessions: id, type (meterpreter/shell), target host, tunnel."""
    response = _rpc_call("session.list")
    if isinstance(response, dict) and response.get("error_class"):
        return response
    sessions = []
    for session_id, meta in (response or {}).items():
        sessions.append({
            "id": session_id,
            "type": meta.get("type"),
            "tunnel_host": meta.get("tunnel_host"),
            "tunnel_peer": meta.get("tunnel_peer"),
            "via_exploit": meta.get("via_exploit"),
            "arch": meta.get("arch"),
        })
    return {"count": len(sessions), "sessions": sessions}


def msf_session_cmd(session_id: int, command: str, *, timeout: float = 30.0) -> dict[str, Any]:
    """Run a command inside a session: meterpreter commands or shell commands.

    For meterpreter sessions the command runs through session.meterpreter_run_write;
    for plain shells through session.shell_write + a read poll. Output capped at the
    tail - long listings belong in files on the target.
    """
    kind = _rpc_call("session.list")
    meta = (kind or {}).get(int(session_id))
    session_type = (meta or {}).get("type", "shell")
    if session_type == "meterpreter":
        result = _rpc_call("session.meterpreter_run_write", int(session_id), command, timeout=timeout)
        if isinstance(result, dict) and result.get("error_class"):
            return result
        return {"session": session_id, "type": "meterpreter", "output": (result.get("data") or "")[-20000:]}
    _rpc_call("session.shell_write", int(session_id), command + "\n")
    time.sleep(min(timeout, 3.0))
    result = _rpc_call("session.shell_read", int(session_id), 20000)
    if isinstance(result, dict) and result.get("error_class"):
        return result
    return {"session": session_id, "type": "shell", "output": (result.get("data") or "")[-20000:]}

