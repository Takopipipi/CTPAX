"""Cheat Engine integration: launch/attach control plus a Lua mailbox bridge.

Cheat Engine executes every ``*.lua`` file in its ``autorun\\`` folder at startup
- the exact mechanism the community CEAutoAttach tool uses to attach CE to a pid
from the command line. The bridge installed there owns a persistent timer: it
polls a mailbox under ``%TEMP%\\ctpax-ce-bridge``, runs the Lua chunk from
``request.lua`` inside Cheat Engine's own Lua state, and answers with
``response_<nonce>.json``.

Because the chunk executes in-process, every Cheat Engine Lua API is reachable -
openProcess, read/write, autoAssemble, createMemScan (the value scanner), the
debugger, the address list, forms and timers - which is the "100% of the
program" channel. When CE is missing, or the autorun script has not been loaded
yet, every function reports what is missing and how to fix it, following the
same pattern as httpdbg_mcp / frida_mcp.

Protocol (both sides agree, no directory listing needed on CE's side):
  1. MCP writes request.lua as ``--ctpax-nonce: <id>\\n<script>`` via an atomic
     rename, so the bridge never reads a half-written file.
  2. The bridge timer (200ms) reads+deletes request.lua, pcall()s the chunk,
     JSON-encodes ``{ok, result|error}`` and renames it to response_<id>.json.
  3. MCP polls for that file until its timeout, then cleans up.
A heartbeat file is rewritten on every tick; its age is the liveness check.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

_STATE_DIR_NAME = "ctpax-ce-bridge"
_AUTORUN_DIR = "autorun"
_BRIDGE_FILENAME = "ctpax_mcp_bridge.lua"
_EXE_NAME = "Cheat Engine.exe"
_DOWNLOAD_URL = "https://cheatengine.org/"
_HEARTBEAT_MAX_AGE = 10.0  # the bridge timer ticks every 0.2s
_SWEEP_AGE = 300.0  # responses left behind by timed-out calls
_CE_LOCK = threading.Lock()

# The autorun script. Pure ASCII on purpose: CE reads autorun files with the
# default codepage and a BOM/UTF-8 quirk must not break the bridge.
_BRIDGE_LUA = r"""-- CTPAX MCP bridge for Cheat Engine.
-- Installed into the autorun\ folder: Cheat Engine runs every *.lua file there
-- at startup (the mechanism CEAutoAttach uses). Protocol: request.lua (atomic
-- rename) -> execute chunk -> response_<nonce>.json; heartbeat proves liveness.
local dir = os.getenv('CTPAX_CE_STATE_DIR')
if not dir or dir == '' then
  dir = (os.getenv('TEMP') or os.getenv('TMP') or '.') .. '/ctpax-ce-bridge'
end

-- attach target chosen by ce_launch (CEAutoAttach pattern: env -> autorun)
local target = os.getenv('CTPAX_CE_TARGET')
if target and target ~= '' then
  local n = tonumber(target)
  pcall(openProcess, n or target)
end

local function json_escape(s)
  local out = {}
  for i = 1, #s do
    local b = s:byte(i)
    local c = s:sub(i, i)
    if c == '"' then out[#out + 1] = '\"'
    elseif c == '\\' then out[#out + 1] = '\\\\'
    elseif b == 10 then out[#out + 1] = '\\n'
    elseif b == 13 then out[#out + 1] = '\\r'
    elseif b == 9 then out[#out + 1] = '\\t'
    elseif b < 32 then out[#out + 1] = string.format('\\u%04x', b)
    else out[#out + 1] = c end
  end
  return table.concat(out)
end

local function encode(v, depth, seen)
  depth = depth or 0
  seen = seen or {}
  if v == nil then return 'null' end
  local tv = type(v)
  if tv == 'boolean' then return v and 'true' or 'false' end
  if tv == 'number' then
    if v ~= v or v == math.huge or v == -math.huge then return 'null' end
    return tostring(v)
  end
  if tv == 'string' then return '"' .. json_escape(v) .. '"' end
  if tv ~= 'table' then
    local ok, s = pcall(tostring, v)
    return '"' .. json_escape(ok and s or tv) .. '"'
  end
  if depth > 8 then return '"<max-depth>"' end
  if seen[v] then return '"<cycle>"' end
  seen[v] = true
  local count, seq = 0, 0
  for k in pairs(v) do
    count = count + 1
    if type(k) == 'number' and k >= 1 and k == math.floor(k) then seq = seq + 1 end
  end
  local parts = {}
  if count > 0 and seq == count and #v == count then
    for i = 1, #v do parts[#parts + 1] = encode(v[i], depth + 1, seen) end
    seen[v] = nil
    return '[' .. table.concat(parts, ',') .. ']'
  end
  for k, val in pairs(v) do
    parts[#parts + 1] = '"' .. json_escape(tostring(k)) .. '":' .. encode(val, depth + 1, seen)
  end
  seen[v] = nil
  return '{' .. table.concat(parts, ',') .. '}'
end

local function write_file(path, content)
  local f = io.open(path, 'w')
  if not f then return false end
  f:write(content)
  f:close()
  return true
end

local function tick()
  write_file(dir .. '/heartbeat', tostring(os.time()))
  local f = io.open(dir .. '/request.lua', 'r')
  if not f then return end
  local src = f:read('*a')
  f:close()
  local nonce = tostring(src):match('^%-%-ctpax%-nonce:%s*([%w%-%_]+)')
  if not nonce or nonce == '' then
    os.remove(dir .. '/request.lua')
    return
  end
  local resp = dir .. '/response_' .. nonce .. '.json'
  local done = io.open(resp, 'r')
  if done then
    done:close()
    os.remove(dir .. '/request.lua')
    return
  end
  os.remove(dir .. '/request.lua')
  local out
  local loader = loadstring or load
  local chunk, lerr = loader(src, '=ctpax-mcp')
  if not chunk then
    out = encode({ ok = false, error = 'load error: ' .. tostring(lerr) })
  else
    local results = { pcall(chunk) }
    if results[1] then
      out = encode({ ok = true, result = results[2] })
    else
      out = encode({ ok = false, error = tostring(results[2]) })
    end
  end
  write_file(resp .. '.tmp', out)
  os.rename(resp .. '.tmp', resp)
end

-- persistent timer: the documented signature is createTimer(owner, enabled)
local ok1 = pcall(function()
  local timer = createTimer(nil, false)
  timer.Interval = 200
  timer.OnTimer = function(sender) pcall(tick) end
  timer.Enabled = true
end)
if not ok1 then
  -- older builds only accept createTimer(nil) plus property assignment
  pcall(function()
    local timer = createTimer(nil)
    timer.Interval = 200
    timer.OnTimer = function(sender) pcall(tick) end
    timer.Enabled = true
  end)
end
pcall(tick)  -- heartbeat immediately, before the first timer fire
"""

def _state_dir() -> Path:
    override = os.environ.get("CTPAX_CE_STATE_DIR")
    if override:
        return Path(override)
    temp = os.environ.get("TEMP") or os.environ.get("TMP") or "."
    return Path(temp) / _STATE_DIR_NAME


def _registry_dirs() -> list[Path]:
    """Install locations from the Uninstall keys (HKLM, WOW6432, HKCU)."""
    found: list[Path] = []
    try:
        import winreg
    except ImportError:
        return found
    hives = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, path in hives:
        try:
            root = winreg.OpenKey(hive, path)
        except OSError:
            continue
        with root:
            try:
                subkey_count = winreg.QueryInfoKey(root)[0]
            except OSError:
                continue
            for i in range(subkey_count):
                try:
                    name = winreg.EnumKey(root, i)
                    with winreg.OpenKey(root, name) as sub:
                        display = str(winreg.QueryValueEx(sub, "DisplayName")[0])
                        if "cheat engine" not in display.lower():
                            continue
                        location = str(winreg.QueryValueEx(sub, "InstallLocation")[0] or "")
                        if location:
                            found.append(Path(location))
                except OSError:
                    continue
    return found


def _install_candidates() -> list[Path]:
    roots: list[Path] = []
    override = os.environ.get("CHEAT_ENGINE_HOME")
    if override:
        roots.append(Path(override))
    for base in (
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")),
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")),
        Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))) / "Programs",
    ):
        roots.append(base / "Cheat Engine")
    for drive in ("C", "D", "E"):
        roots.append(Path(f"{drive}:\\") / "Cheat Engine")
    roots.extend(_registry_dirs())
    unique: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = str(root).lower()
        if key not in seen:
            seen.add(key)
            unique.append(root)
    return unique


def _find_exe() -> Path | None:
    for root in _install_candidates():
        try:
            if root.is_file() and root.name.lower().endswith(".exe"):
                return root
        except OSError:
            continue
        for name in (_EXE_NAME, "CheatEngine.exe", "cheatengine-x86_64.exe"):
            exe = root / name
            if exe.is_file():
                return exe
    return None


def _exe_version(path: Path) -> str | None:
    """FileVersion from the VS_VERSION_INFO resource; cosmetic, never raises."""
    try:
        import ctypes
        import ctypes.wintypes as wt

        class VS_FIXEDFILEINFO(ctypes.Structure):
            _fields_ = [
                ("dwSignature", wt.DWORD), ("dwStrucVersion", wt.DWORD),
                ("dwFileVersionMS", wt.DWORD), ("dwFileVersionLS", wt.DWORD),
                ("dwProductVersionMS", wt.DWORD), ("dwProductVersionLS", wt.DWORD),
                ("dwFileFlagsMask", wt.DWORD), ("dwFileFlags", wt.DWORD),
                ("dwFileOS", wt.DWORD), ("dwFileType", wt.DWORD),
                ("dwFileSubtype", wt.DWORD), ("dwFileDateMS", wt.DWORD),
                ("dwFileDateLS", wt.DWORD),
            ]

        version = ctypes.WinDLL("version")
        size = version.GetFileVersionInfoSizeW(str(path), None)
        if not size:
            return None
        data = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(str(path), 0, size, data):
            return None
        info = ctypes.c_void_p()
        length = wt.UINT()
        if not version.VerQueryValueW(data, "\\", ctypes.byref(info), ctypes.byref(length)):
            return None
        ffi = ctypes.cast(info, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
        return (
            f"{ffi.dwFileVersionMS >> 16}.{ffi.dwFileVersionMS & 0xFFFF}."
            f"{ffi.dwFileVersionLS >> 16}.{ffi.dwFileVersionLS & 0xFFFF}"
        )
    except Exception:
        return None


def _running() -> dict[str, Any]:
    """Detect the CE process under any of its image names.

    ``Cheat Engine.exe`` is a launcher stub: it starts a CPU-variant binary such
    as ``cheatengine-x86_64-SSE4-AVX2.exe`` and often exits, so filtering on the
    launcher name alone reports a running CE as absent. Parse the full CSV list
    instead of using tasklist's IMAGENAME filter.
    """
    try:
        import csv
        import io

        out = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
        )
        for row in csv.reader(io.StringIO(out.stdout)):
            if not row:
                continue
            name = row[0].strip().lower()
            if name in ("cheat engine.exe", "cheatengine.exe") or name.startswith("cheatengine"):
                return {"running": True, "process": row[0].strip()}
    except Exception:
        pass
    return {"running": False, "process": None}


def _windows() -> list[dict[str, Any]]:
    """Top-level windows whose title contains 'Cheat Engine' (main form, memory view...)."""
    import ctypes

    found: list[dict[str, Any]] = []

    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    def enum_proc(hwnd, _lparam):
        buf = ctypes.create_unicode_buffer(512)
        if ctypes.windll.user32.GetWindowTextW(hwnd, buf, 512) > 0 and buf.value:
            title = buf.value
            if "cheat engine" in title.lower():
                found.append({"hwnd": int(hwnd), "title": title})
        return True

    try:
        ctypes.windll.user32.EnumWindows(WNDENUMPROC(enum_proc), 0)
    except Exception:
        pass
    return found


def _heartbeat() -> dict[str, Any]:
    path = _state_dir() / "heartbeat"
    try:
        age = time.time() - path.stat().st_mtime
        return {"path": str(path), "age_s": round(age, 2), "alive": age <= _HEARTBEAT_MAX_AGE}
    except OSError:
        return {"path": str(path), "age_s": None, "alive": False}


def _autorun_path() -> Path | None:
    exe = _find_exe()
    if not exe:
        return None
    return exe.parent / _AUTORUN_DIR / _BRIDGE_FILENAME


def _lua_quote(text: str) -> str:
    """A Lua-compatible double-quoted literal for arbitrary text."""
    out = ['"']
    for ch in str(text):
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 32:
            out.append(f"\\{ord(ch):03d}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _lua_arg(value: Any) -> str:
    """Numbers become Lua numbers (decimal pids); everything else is quoted verbatim.

    For addresses use ``_lua_address`` instead - plain digit strings mean
    different things for pids (decimal) and CEAddressString (hex).
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value).strip()
    if re.fullmatch(r"-?\d+", text):
        return text
    return _lua_quote(text)


def _lua_address(value: Any) -> str:
    """Turn an address argument into something Cheat Engine parses unambiguously.

    - int / '0x...' hex  -> a decimal Lua number (CEAddressString rejects 0x)
    - anything else      -> quoted verbatim, so CE's own parser applies: plain
      digits are hex addresses ('00400000'), 'module+ofs', '[[ptr]+ofs]+n',
      '$symbol' and math all work exactly as typed into CE's address field.
    """
    if isinstance(value, bool):
        return _lua_quote(str(value))
    if isinstance(value, int):
        return str(value)
    text = str(value).strip()
    if re.fullmatch(r"-?\d+", text):
        return _lua_quote(text)  # CEAddressString: plain digits are hex
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", text):
        return str(int(text, 16))  # pass the real address as a Lua number
    return _lua_quote(text)


def status() -> dict[str, Any]:
    """Install location, version, window, autorun bridge and heartbeat state."""
    exe = _find_exe()
    installed = exe is not None
    running = _running()["running"] if installed else False
    windows = _windows() if running else []
    script = _autorun_path()
    script_present = bool(script and script.is_file())
    heartbeat = _heartbeat()
    payload: dict[str, Any] = {
        "installed": installed,
        "install_dir": str(exe.parent) if exe else None,
        "exe": str(exe) if exe else None,
        "version": _exe_version(exe) if exe else None,
        "running": running,
        "window": windows[0] if windows else None,
        "autorun_bridge": {"path": str(script) if script else None, "installed": script_present},
        "state_dir": str(_state_dir()),
        "bridge": heartbeat,
    }
    if not installed:
        payload["note"] = f"Cheat Engine not installed; download it from {_DOWNLOAD_URL}"
    elif not running:
        payload["note"] = "call ce_launch to start Cheat Engine (it installs/reloads the Lua bridge)"
    elif not script_present:
        payload["note"] = "the Lua bridge is not in autorun\\ yet: call ce_bridge_install, then restart Cheat Engine"
    elif not heartbeat["alive"]:
        payload["note"] = "CE is running but the autorun bridge did not load (heartbeat missing/stale): restart Cheat Engine so autorun\\*.lua scripts run"
    else:
        payload["note"] = "ready: ce_lua executes any Cheat Engine Lua; ce_attach/ce_read/ce_write/ce_assemble cover the common cases"
    return payload


def bridge_install(*, force: bool = False) -> dict[str, Any]:
    """Write the mailbox bridge into Cheat Engine's autorun\\ folder (idempotent)."""
    exe = _find_exe()
    if not exe:
        return {"error": "Cheat Engine not installed", "hint": f"download it from {_DOWNLOAD_URL}"}
    target = exe.parent / _AUTORUN_DIR / _BRIDGE_FILENAME
    writability_hint = (
        "install Cheat Engine to a writable folder, or run this MCP elevated - "
        "Program Files only accepts writes from an administrator"
    )
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"error": f"cannot create {target.parent}: {exc}", "hint": writability_hint}
    existing = None
    if target.is_file():
        try:
            existing = target.read_text(encoding="utf-8")
        except OSError:
            existing = None
    changed = False
    if force or existing != _BRIDGE_LUA:
        try:
            target.write_text(_BRIDGE_LUA, encoding="utf-8", newline="\n")
        except OSError as exc:
            return {"error": f"cannot write {target}: {exc}", "hint": writability_hint}
        changed = True
    state = _state_dir()
    try:
        state.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"error": f"cannot create state dir {state}: {exc}"}
    return {
        "installed": True,
        "changed": changed,
        "path": str(target),
        "state_dir": str(state),
        "note": "Cheat Engine runs autorun\\*.lua at startup - restart it (ce_launch) to load the bridge",
    }


def bridge_status() -> dict[str, Any]:
    """Is the autorun script in place and is its heartbeat fresh?"""
    script = _autorun_path()
    heartbeat = _heartbeat()
    running = _running()["running"]
    payload: dict[str, Any] = {
        "autorun_script": str(script) if script else None,
        "installed": bool(script and script.is_file()),
        "state_dir": str(_state_dir()),
        "running": running,
        "heartbeat": heartbeat,
    }
    if not script:
        payload["note"] = "Cheat Engine not installed"
    elif not payload["installed"]:
        payload["note"] = "call ce_bridge_install, then restart Cheat Engine"
    elif not running:
        payload["note"] = "Cheat Engine is not running - start it with ce_launch"
    elif not heartbeat["alive"]:
        payload["note"] = "CE runs but the bridge heartbeat is missing/stale - restart CE so autorun scripts load (CE must run as the same user as this MCP)"
    else:
        payload["note"] = f"bridge alive, last tick {heartbeat['age_s']}s ago"
    return payload


def _sweep(state: Path) -> None:
    """Drop responses left behind by calls that timed out (and stale tmp files)."""
    now = time.time()
    for path in list(state.glob("response_*.json")) + list(state.glob("response_*.tmp")):
        try:
            if now - path.stat().st_mtime > _SWEEP_AGE:
                path.unlink()
        except OSError:
            pass
    tmp = state / "request.tmp"
    try:
        if now - tmp.stat().st_mtime > _SWEEP_AGE:
            tmp.unlink()
    except OSError:
        pass


def lua(script: str, *, timeout: float = 15.0) -> dict[str, Any]:
    """Execute a Lua chunk inside Cheat Engine and return its first return value.

    This is the full-program channel: openProcess, read/write*, autoAssemble,
    createMemScan, the debugger, the address list, forms - every CE Lua API.
    """
    if not script or not str(script).strip():
        return {"error": "script is empty"}
    state = _state_dir()
    try:
        state.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"error": f"cannot create state dir {state}: {exc}"}
    if not (state / "heartbeat").exists():
        return {
            "error": "Cheat Engine bridge is not running (no heartbeat)",
            "hint": (
                "call ce_bridge_install, then start/restart Cheat Engine with ce_launch - "
                "autorun\\*.lua scripts only run at CE startup, and CE must run under the "
                "same user as this MCP"
            ),
        }
    _sweep(state)
    nonce = uuid.uuid4().hex
    request = state / "request.lua"
    tmp = state / "request.tmp"
    response = state / f"response_{nonce}.json"
    with _CE_LOCK:
        try:
            tmp.write_text(f"--ctpax-nonce: {nonce}\n{script}", encoding="utf-8")
        except OSError as exc:
            return {"error": f"cannot write the request file: {exc}"}
        publish_error: Exception | None = None
        for _ in range(10):
            try:
                os.replace(tmp, request)  # atomic: the bridge never sees a partial chunk
                publish_error = None
                break
            except OSError as exc:
                publish_error = exc  # usually the bridge still holds the previous request
                time.sleep(0.1)
        if publish_error is not None:
            return {"error": f"cannot publish the request: {publish_error}"}
        deadline = time.time() + max(0.1, float(timeout))
        while time.time() < deadline:
            if response.is_file():
                try:
                    text = response.read_text(encoding="utf-8")
                except OSError:
                    time.sleep(0.05)
                    continue
                try:
                    response.unlink()
                except OSError:
                    pass
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    return {"error": f"bridge sent invalid JSON: {text[:300]}"}
                if not isinstance(payload, dict):
                    return {"error": f"unexpected bridge payload: {payload!r}"}
                if payload.get("ok"):
                    return {"ok": True, "result": payload.get("result")}
                return {"error": str(payload.get("error") or "unknown bridge error")}
            time.sleep(0.05)
        for stale in (request, tmp, response):
            try:
                stale.unlink()
            except OSError:
                pass
        return {
            "error": f"timeout after {timeout}s waiting for the Cheat Engine bridge",
            "hint": "check ce_bridge_status - CE busy, stopped, or the bridge timer did not load",
        }


def attach(target: str | int) -> dict[str, Any]:
    """openProcess in CE: attach by pid or by process name (e.g. 'game.exe')."""
    if target is None or str(target).strip() == "":
        return {"error": "target pid or process name is required"}
    return lua(f"return openProcess({_lua_arg(target)})")


def read(address: str | int, size: int = 8, *, timeout: float = 15.0) -> dict[str, Any]:
    """readBytes(address, size, true) - bytes of the attached process, plus hex."""
    try:
        size = int(size)
    except (TypeError, ValueError):
        return {"error": "size must be an integer"}
    if not 1 <= size <= 4096:
        return {"error": "size must be between 1 and 4096"}
    result = lua(f"return readBytes({_lua_address(address)}, {size}, true)", timeout=timeout)
    if result.get("ok") and result.get("result") is None:
        return {
            "error": "readBytes returned nil - address unreadable, or no process is open",
            "hint": "call ce_attach first",
        }
    data = result.get("result")
    if isinstance(data, list):
        try:
            result["hex"] = bytes(int(b) & 0xFF for b in data).hex()
        except Exception:
            pass
    return result


def write(address: str | int, data: str, *, timeout: float = 15.0) -> dict[str, Any]:
    """writeBytes(address, bytes...) with a hex payload: '90 90' or '0x90,0x90'."""
    cleaned = re.sub(r"0x", "", str(data), flags=re.IGNORECASE)
    cleaned = re.sub(r"[\s,]", "", cleaned)
    if not cleaned or len(cleaned) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return {"error": "data must be hex bytes, e.g. '90 90' or '0x90,0x90'"}
    if len(cleaned) > 8192:
        return {"error": "payload too large (max 4096 bytes)"}
    numbers = ",".join(str(int(cleaned[i:i + 2], 16)) for i in range(0, len(cleaned), 2))
    return lua(f"return writeBytes({_lua_address(address)}, {numbers})", timeout=timeout)


def assemble(code: str, *, timeout: float = 15.0) -> dict[str, Any]:
    """Run a full Cheat Engine Auto Assembler script verbatim (autoAssemble)."""
    if not code or not code.strip():
        return {"error": "code is empty"}
    return lua(f"return autoAssemble({_lua_quote(code)})", timeout=timeout)


def focus() -> dict[str, Any]:
    """Bring the Cheat Engine window to the foreground (for manual follow-up)."""
    import ctypes

    windows = _windows()
    if not windows:
        return {"error": "no Cheat Engine window found", "hint": "start it with ce_launch"}
    hwnd = windows[0]["hwnd"]
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32

    def foreground_ok() -> bool:
        return user32.GetForegroundWindow() == hwnd

    try:
        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        time.sleep(0.05)
        user32.SetForegroundWindow(hwnd)
        time.sleep(0.1)
        if not foreground_ok():
            # Windows' foreground lock refuses SetForegroundWindow from a background
            # process. The classic ALT-key trick releases the lock; attaching to the
            # foreground thread's input queue is the last resort.
            user32.keybd_event(0x12, 0, 0, 0)  # ALT down
            user32.keybd_event(0x12, 0, 2, 0)  # ALT up
            time.sleep(0.05)
            user32.SetForegroundWindow(hwnd)
            time.sleep(0.2)
        if not foreground_ok():
            current = user32.GetForegroundWindow()
            target_thread = user32.GetWindowThreadProcessId(current, None) if current else 0
            my_thread = kernel32.GetCurrentThreadId()
            attached = bool(target_thread and user32.AttachThreadInput(my_thread, target_thread, True))
            try:
                user32.BringWindowToTop(hwnd)
                user32.SetForegroundWindow(hwnd)
                time.sleep(0.1)
            finally:
                if attached:
                    user32.AttachThreadInput(my_thread, target_thread, False)
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    return {"focused": foreground_ok(), "title": windows[0]["title"], "hwnd": hex(hwnd)}


def launch(target: str | int | None = None, *, install_bridge: bool = True) -> dict[str, Any]:
    """Start Cheat Engine (installing the autorun bridge), optionally with a target.

    ``target`` is a pid or a process name passed to CE via the environment and
    picked up by the autorun script with openProcess - the CEAutoAttach pattern.
    """
    exe = _find_exe()
    if not exe:
        return {"error": "Cheat Engine not installed", "hint": f"download it from {_DOWNLOAD_URL}"}
    payload: dict[str, Any] = {"exe": str(exe)}
    warning = None
    if install_bridge:
        info = bridge_install()
        if info.get("error"):
            warning = info  # still launch: the GUI is usable even without the bridge
    if _running()["running"]:
        payload.update({"launched": False, "already_running": True})
        if target is not None and str(target).strip() != "":
            if _heartbeat()["alive"]:
                payload["attach"] = attach(target)
            else:
                payload["note"] = (
                    "CE is already running without the live bridge: the startup target "
                    "applies to a fresh launch only. ce_bridge_install + restart CE, then "
                    "ce_attach"
                )
        if warning:
            payload["bridge_error"] = warning
        return payload
    env = os.environ.copy()
    env["CTPAX_CE_STATE_DIR"] = str(_state_dir())
    if target is not None and str(target).strip() != "":
        env["CTPAX_CE_TARGET"] = str(target).strip()
    try:
        subprocess.Popen(
            [str(exe)],
            cwd=str(exe.parent),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        return {"error": f"launch failed: {type(exc).__name__}: {exc}", "exe": str(exe)}
    time.sleep(2.0)
    payload.update({
        "launched": _running()["running"],
        "target": str(target).strip() if target is not None and str(target).strip() else None,
        "bridge_ready": _heartbeat()["alive"],
        "note": "autorun\\*.lua runs at CE startup; ce_bridge_status shows when the heartbeat appears",
    })
    if warning:
        payload["bridge_error"] = warning
    return payload
