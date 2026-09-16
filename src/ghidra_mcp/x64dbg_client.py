"""Managed x64dbg automation sessions on top of the x64dbg-automate client.

One live session at a time, guarded by a lock because the underlying ZMQ client is not
thread-safe and every MCP tool call arrives on a worker thread. The manager owns the
debugger process: starting it (the client launches x64dbg itself), attaching, running
commands, breakpoints, stepping, memory, registers, and teardown.

The x64dbg-automate plugin must be present in the debugger's plugins folder; the
installer puts it there. Every failure names the missing piece.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from x64dbg_automate import X64DbgClient

from ghidra_mcp.dynamic import find_x64dbg


class X64DbgSession:
    """One active x64dbg automation session with serialised access."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.client: X64DbgClient | None = None
        self.target: str | None = None
        self.started_at: float | None = None

    # -- session lifecycle -------------------------------------------------
    def _require_client(self) -> X64DbgClient:
        if self.client is None:
            raise RuntimeError(
                "no x64dbg session is running; call xdbg_start (or xdbg_attach) first"
            )
        return self.client

    def _debugger_path(self) -> str:
        """The native debugger exe the automation client must launch.

        x96dbg.exe is a bitness chooser: launching it does not load plugins, so the
        client has to receive x64\\x64dbg.exe (or x32) directly.
        """
        from pathlib import Path

        found = find_x64dbg()
        if found.get("found"):
            root = Path(found["root"])
            for candidate in (root / "x64" / "x64dbg.exe", root / "x32" / "x32dbg.exe"):
                if candidate.is_file():
                    return str(candidate)
            if Path(found["launcher"]).name.lower() != "x96dbg.exe":
                return found["launcher"]
        raise FileNotFoundError(found.get("hint", "x64dbg not found") if found else "x64dbg not found")

    def start(self, target: str | None = None, cmdline: str = "", current_dir: str = "") -> dict[str, Any]:
        with self._lock:
            self.stop_if_any()
            client = X64DbgClient(x64dbg_path=self._debugger_path())
            # The automate plugin occasionally loses the very first load of a session
            # (it reports "Failed to load executable" once, then works) - retry with a
            # short pause and keep the plugin's own message if every attempt fails.
            last_error: Exception | None = None
            session_pid = None
            for attempt in range(3):
                try:
                    session_pid = client.start_session(target_exe=target or "", cmdline=cmdline, current_dir=current_dir)
                    last_error = None
                    break
                except Exception as exc:
                    last_error = exc
                    message = str(exc).lower()
                    if "load" not in message and "executable" not in message:
                        raise
                    time.sleep(1.5)
            if last_error is not None:
                raise RuntimeError(
                    f"x64dbg could not load the target after 3 attempts: {last_error}"
                ) from last_error
            self.client = client
            self.target = target
            self.started_at = time.time()
            result = {
                "session_pid": session_pid,
                "debugger": client.x64dbg_path,
                "target": target,
                "note": "session started; the debuggee is at the initial system breakpoint" if target else "empty session; load with xdbg_start or run commands",
            }
            if target:
                result.update(self._brief(client))
            return result

    def attach(self, pid: int) -> dict[str, Any]:
        with self._lock:
            self.stop_if_any()
            client = X64DbgClient(x64dbg_path=self._debugger_path())
            session_pid = client.start_session_attach(pid)
            self.client = client
            self.target = f"pid:{pid}"
            self.started_at = time.time()
            return {"session_pid": session_pid, "attached_to": pid, **self._brief(client)}

    def stop(self, *, detach: bool = False) -> dict[str, Any]:
        with self._lock:
            if self.client is None:
                return {"stopped": False, "note": "no session running"}
            client = self.client
            self.client = None
            self.target = None
            self.started_at = None
            try:
                if detach and client.is_debugging():
                    client.detach_session()
                else:
                    client.terminate_session()
            except Exception as exc:  # the debugger may already be gone
                return {"stopped": True, "warning": f"during teardown: {type(exc).__name__}: {exc}"}
            return {"stopped": True, "detached": detach}

    def stop_if_any(self) -> None:
        if self.client is not None:
            try:
                self.client.terminate_session()
            except Exception:
                pass
            self.client = None
            self.target = None
            self.started_at = None

    def status(self) -> dict[str, Any]:
        with self._lock:
            if self.client is None:
                installed = _plugin_installed()
                return {
                    "running": False,
                    "plugin_installed": installed["installed"],
                    "plugin_hint": installed.get("hint"),
                }
            client = self.client
            return {
                "running": True,
                "target": self.target,
                "session_pid": client.session_pid,
                "debugger_pid": client.get_debugger_pid(),
                "debugging": client.is_debugging(),
                "running_state": client.is_running(),
                "debugee_pid": client.debugee_pid(),
                "debugee_bitness": client.debugee_bitness(),
                "elapsed_seconds": round(time.time() - (self.started_at or time.time()), 1),
            }

    @staticmethod
    def _brief(client: X64DbgClient) -> dict[str, Any]:
        brief: dict[str, Any] = {"debugging": client.is_debugging()}
        if client.is_debugging():
            brief["debugee_pid"] = client.debugee_pid()
            brief["debugee_bitness"] = client.debugee_bitness()
        return brief

    # -- execution control ---------------------------------------------------
    def cmd(self, command: str) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            ok = client.cmd_sync(command)
            return {"success": ok, "command": command, "log_tail": self._log_delta(client, 20)}

    def evaluate(self, expression: str) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            value, ok = client.eval_sync(expression)
            return {"success": bool(ok), "expression": expression, "value": hex(value) if value is not None else None}

    def go(self, *, wait_stop_timeout: float = 0.0) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            ok = client.go()
            result: dict[str, Any] = {"success": ok, "running": client.is_running()}
            if wait_stop_timeout > 0:
                result["stopped_within"] = client.wait_until_stopped(int(wait_stop_timeout))
                result.update(self._brief(client))
            return result

    def wait_stopped(self, timeout: float = 10.0) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            stopped = client.wait_until_stopped(int(timeout))
            return {"stopped": stopped, "timeout": timeout, **self._brief(client)}

    def pause(self) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            return {"success": client.pause(), "running": client.is_running()}

    def step_into(self, count: int = 1) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            return {"success": client.stepi(count), **self._regs_brief(client)}

    def step_over(self, count: int = 1) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            return {"success": client.stepo(count), **self._regs_brief(client)}

    def skip(self, count: int = 1) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            return {"success": client.skip(count), **self._regs_brief(client)}

    # -- breakpoints ---------------------------------------------------------
    def bp_set(self, address_or_symbol: str, *, hardware: bool = False, size: int = 1, access: str = "x") -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            if hardware:
                from x64dbg_automate.models import HardwareBreakpointType

                kind = getattr(HardwareBreakpointType, access, HardwareBreakpointType.x)
                ok = client.set_hardware_breakpoint(address_or_symbol, bp_type=kind, size=size)
            else:
                ok = client.set_breakpoint(address_or_symbol)
            return {"success": ok, "breakpoint": address_or_symbol, "hardware": hardware}

    def bp_clear(self, address_or_symbol: str, *, hardware: bool = False) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            if hardware:
                ok = client.clear_hardware_breakpoint(address_or_symbol)
            else:
                ok = client.clear_breakpoint(address_or_symbol)
            return {"success": ok, "breakpoint": address_or_symbol, "hardware": hardware}

    def bp_list(self) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            from x64dbg_automate.models import BreakpointType

            collected: dict[str, Any] = {}
            for bp_type in BreakpointType:
                try:
                    breakpoints = client.get_breakpoints(bp_type)
                except Exception:
                    continue
                for bp in breakpoints:
                    dump = bp.model_dump() if hasattr(bp, "model_dump") else {"raw": str(bp)}
                    dump["addr"] = hex(dump["addr"]) if isinstance(dump.get("addr"), int) else dump.get("addr")
                    collected[f"{bp_type.name}:{dump.get('addr')}"] = dump
            return {"count": len(collected), "breakpoints": collected}

    # -- registers / memory ----------------------------------------------------
    def regs(self) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            return {"registers": _regs_as_dict(client.get_regs())}

    def set_reg(self, name: str, value: int) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            ok = client.set_reg(name, value)
            return {"success": ok, "register": name, "value": hex(value)}

    def mem_read(self, address: int, size: int, *, as_hex: bool = True) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            data: bytes | None = None
            last_error: Exception | None = None
            # Right after a stop the plugin can briefly refuse reads; retry once after
            # a short settle instead of failing the whole tool call.
            for attempt in range(3):
                try:
                    data = client.read_memory(address, size)
                    break
                except RuntimeError as exc:
                    last_error = exc
                    time.sleep(0.3 * (attempt + 1))
            if data is None:
                raise last_error or RuntimeError(f"could not read {hex(address)}")
            return {
                "address": hex(address),
                "size": len(data),
                "hex": data.hex() if as_hex else None,
                "sha256": __import__("hashlib").sha256(data).hexdigest(),
            }

    def mem_write(self, address: int, hex_data: str) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            data = bytes.fromhex(hex_data)
            ok = client.write_memory(address, data)
            return {"success": ok, "address": hex(address), "bytes_written": len(data)}

    def disassemble(self, address: int) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            instruction = client.disassemble_at(address)
            if instruction is None:
                return {"error": f"nothing disassembled at {hex(address)}"}
            dump = instruction.model_dump() if hasattr(instruction, "model_dump") else {"raw": str(instruction)}
            return {"address": hex(address), **dump}

    def assemble(self, address: int, instruction: str) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            written = client.assemble_at(address, instruction)
            if written is None:
                return {"error": f"could not assemble {instruction!r} at {hex(address)}"}
            return {"address": hex(address), "instruction": instruction, "bytes": written}

    def memmap(self) -> dict[str, Any]:
        with self._lock:
            client = self._require_client()
            pages = client.memmap()
            rendered = []
            for page in pages:
                if hasattr(page, "model_dump"):
                    entry = page.model_dump()
                else:
                    entry = {"raw": str(page)}
                rendered.append(entry)
            return {"count": len(rendered), "pages": rendered}

    # -- helpers ---------------------------------------------------------------
    def _regs_brief(self, client: X64DbgClient) -> dict[str, Any]:
        if not client.is_debugging():
            return {}
        try:
            regs = _regs_as_dict(client.get_regs())
            pick = {k: regs.get(k) for k in ("rip", "rax", "rbx", "rcx", "rdx") if k in regs}
            return {"rip": pick.get("rip"), "registers_brief": pick}
        except Exception:
            return {}

    @staticmethod
    def _log_delta(client: X64DbgClient, limit: int) -> list[str]:
        try:
            _, lines, _, _ = client.get_log(0, limit)
            return lines[-limit:]
        except Exception:
            return []


def _regs_as_dict(regs: Any) -> dict[str, Any]:
    """Flatten a RegDump64/32 into {register: hex-string}.

    The client returns a pydantic RegDump whose ``context`` holds the general-purpose
    registers; the other fields (flags, fpu, mxcsr) go into a compact summary.
    """
    dump = regs[0] if isinstance(regs, list) and regs else regs
    result: dict[str, Any] = {}
    context = getattr(dump, "context", None)
    if context is not None:
        for name in ("rax", "rbx", "rcx", "rdx", "rbp", "rsp", "rsi", "rdi",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                     "rip", "eflags", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"):
            value = getattr(context, name, None)
            if value is not None:
                result[name] = hex(value) if isinstance(value, int) else value
    flags = getattr(dump, "flags", None)
    if flags is not None:
        result["flags"] = {k: v for k, v in vars(flags).items()} if hasattr(flags, "__dict__") else str(flags)
    return result


def _plugin_installed() -> dict[str, Any]:
    """Is x64dbg-automate.dp64 present next to the debugger?"""
    from pathlib import Path

    try:
        from ghidra_mcp.dynamic import find_x64dbg

        found = find_x64dbg()
        if not found.get("found"):
            return {"installed": False, "hint": found.get("hint", "x64dbg not found")}
        root = Path(found["root"])
        bits = {"x64": "x64dbg-automate.dp64", "x32": "x64dbg-automate.dp32"}
        status: dict[str, Any] = {"installed": True, "plugins": {}}
        for folder, plugin in bits.items():
            path = root / folder / "plugins" / plugin
            status["plugins"][folder] = {"expected": str(path), "present": path.is_file()}
        status["installed"] = any(v["present"] for v in status["plugins"].values())
        if not status["installed"]:
            status["hint"] = (
                "run install.bat again (it downloads x64dbg-automate.dp64 from GitHub releases) "
                "or copy the plugin manually into x64\\plugins"
            )
        return status
    except Exception as exc:
        return {"installed": False, "hint": f"could not check: {exc}"}


SESSION = X64DbgSession()
