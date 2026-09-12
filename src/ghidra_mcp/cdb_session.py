"""Persistent cdb (WinDbg command-line) session: one attach, many command batches.

The batch-only ``cdb_run`` spawns a fresh debugger per call, which kills any state:
breakpoints, process control, and for attach attempts it even harms the target. This
module keeps one cdb process alive, pipes commands to its stdin, and reads its stdout,
so a session of ``bp -> g -> db -> g`` is several small, readable calls instead of one
giant command string.
"""

from __future__ import annotations

import ctypes
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from ghidra_mcp.dynamic import find_cdb

_TIMEOUT = 30.0
_PROMPT = b"0:000>"


def _symbol_path() -> str:
    """The configured WinDbg symbol path (config.json symbol_path / env override)."""
    from ghidra_mcp.runtime import SETTINGS

    return SETTINGS.symbol_path


class CdbSession:
    """One live cdb process with serialised stdin/stdout access."""

    def __init__(self) -> None:
        self.process: subprocess.Popen[bytes] | None = None
        self.target: str | None = None
        # RLock, not Lock: start() holds it while calling stop() internally.
        self._lock = threading.RLock()
        self.log: list[str] = []

    def _cdb_path(self) -> str:
        found = find_cdb()
        if not found.get("found"):
            raise FileNotFoundError(found.get("hint", "cdb.exe not found"))
        return found["path"]

    def _read_until_idle(self, settle: float = 1.2, max_wait: float = 15.0) -> str:
        """Read what cdb has produced, waiting for output to go quiet - with a hard cap.

        ``settle`` extends on every chunk, but ``max_wait`` is absolute: cdb streams
        symbol downloads for a long time on first runs, and without the cap the wait
        was unbounded. Non-blocking reads through PeekNamedPipe; readline is not used
        because it blocks while cdb is quiet.
        """
        assert self.process and self.process.stdout
        import msvcrt

        handle = msvcrt.get_osfhandle(self.process.stdout.fileno())
        chunks: list[bytes] = []
        started = time.time()
        quiet_deadline = time.time() + settle
        hard_deadline = started + max_wait
        while time.time() < quiet_deadline and time.time() < hard_deadline:
            available = ctypes.c_ulong(0)
            if not ctypes.windll.kernel32.PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None):
                break  # pipe closed: cdb is gone
            if available.value == 0:
                time.sleep(0.05)
                continue
            data = self.process.stdout.read1(min(available.value, 65536))
            if not data:
                break
            chunks.append(data)
            quiet_deadline = time.time() + settle
        return b"".join(chunks).decode("utf-8", "replace")

    def _send(self, command: str, *, wait: float = 1.5) -> str:
        assert self.process and self.process.stdin
        self.process.stdin.write((command + "\n").encode("utf-8", "replace"))
        self.process.stdin.flush()
        time.sleep(wait)
        return self._read_until_idle()

    def start(self, target: str, arguments: str = "") -> dict[str, Any]:
        """Start a target under a fresh cdb and hold it at the initial breakpoint."""
        with self._lock:
            self.stop()
            path = self._cdb_path()
            if not Path(target).is_file():
                raise FileNotFoundError(f"no such target: {target}")
            command_line = [path, "-y", _symbol_path(), "-G", target]
            if arguments:
                command_line += arguments.split()
            self.process = subprocess.Popen(
                command_line,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.target = target
            time.sleep(2.0)
            banner = self._read_until_idle(settle=3.0, max_wait=40.0)
            self.log += banner.splitlines()
            pid = self._extract_pid(banner)
            self.attached_pid = pid
            return {
                "started": True,
                "cdb_pid": self.process.pid,
                "debugee_pid": pid,
                "banner_tail": banner.splitlines()[-8:],
                "note": "session is live; the debuggee sits at the initial breakpoint",
            }

    def attach(self, pid: int) -> dict[str, Any]:
        """Attach to a running pid.

        The safety difference from batch mode: the target is verified to exist before
        anything is spawned, and a failed attach leaves the process untouched - cdb is
        started with -p and if it cannot attach, it exits without sending signals.
        """
        with self._lock:
            # Pre-flight: refuse to touch a pid that is not there. This is what the
            # batch path got wrong - it signalled first and checked afterwards.
            import ctypes
            import ctypes.wintypes as wt

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
            kernel32.OpenProcess.restype = wt.HANDLE
            kernel32.CloseHandle.argtypes = [wt.HANDLE]
            probe = kernel32.OpenProcess(0x0400, 0, pid)  # PROCESS_QUERY_INFORMATION
            if not probe:
                error = ctypes.get_last_error()
                if error == 87:
                    raise RuntimeError(f"pid {pid} does not exist (ERROR_INVALID_PARAMETER); nothing was touched")
                if error == 5:
                    raise RuntimeError(f"pid {pid} exists but needs elevation to inspect")
                raise RuntimeError(f"OpenProcess({pid}) failed with error {error}; nothing was touched")
            kernel32.CloseHandle(probe)

            self.stop()
            path = self._cdb_path()
            command_line = [path, "-p", str(pid), "-G"]
            self.process = subprocess.Popen(
                command_line,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.target = f"pid:{pid}"
            self.attached_pid = pid
            time.sleep(2.0)
            banner = self._read_until_idle(settle=3.0)
            self.log += banner.splitlines()
            if "Detached" in banner or "cannot attach" in banner.lower() or "error" in banner.lower()[:400]:
                self.stop()
                return {"attached": False, "pid": pid, "output": banner[-800:], "note": "cdb could not attach; the process was not modified"}
            return {
                "attached": True,
                "cdb_pid": self.process.pid if self.process else None,
                "debugee_pid": pid,
                "banner_tail": banner.splitlines()[-6:],
            }

    @staticmethod
    def _extract_pid(banner: str) -> int | None:
        import re

        match = re.search(r"Debuggee.*?pid[: ]+(\d+)| SAP\(\w+[^)]*\): (\d+)|\(pid (\d+)", banner)
        if match:
            return int(next(g for g in match.groups() if g))
        return None

    def command(self, command: str, *, wait: float = 1.5) -> dict[str, Any]:
        """Run one debugger command in the live session and return its output."""
        with self._lock:
            if self.process is None or self.process.poll() is not None:
                raise RuntimeError("no live cdb session; dbg_session_start or dbg_session_attach first")
            output = self._send(command, wait=wait)
            self.log += output.splitlines()
            return {"command": command, "output": output[-6000:], "session_alive": self.process.poll() is None}

    def batch(self, commands: list[str], *, wait: float = 1.2) -> dict[str, Any]:
        """Run a sequence of debugger commands, returning each command's output separately.

        This is the multi-step flow the tester asked for: ``bp`` then ``g`` then a dump
        then another ``g`` - one call, structured per-command results, session stays up.
        """
        with self._lock:
            if self.process is None or self.process.poll() is not None:
                raise RuntimeError("no live cdb session; dbg_session_start or dbg_session_attach first")
            steps = []
            for command in commands:
                output = self._send(command, wait=wait)
                self.log += output.splitlines()
                steps.append({"command": command, "output": output[-3000:]})
            return {"steps": steps, "session_alive": self.process.poll() is None}

    def status(self) -> dict[str, Any]:
        with self._lock:
            alive = self.process is not None and self.process.poll() is None
            return {
                "running": alive,
                "cdb_pid": self.process.pid if self.process else None,
                "target": self.target,
                "debugee_pid": self.attached_pid,
                "log_lines": len(self.log),
                "log_tail": self.log[-15:],
            }

    def stop(self, *, detach: bool = False) -> dict[str, Any]:
        with self._lock:
            if self.process is None:
                return {"stopped": False, "note": "no session"}
            process = self.process
            self.process = None
            try:
                if process.stdin:
                    try:
                        process.stdin.write(b"q\n" if not detach else b".detach\n")
                        process.stdin.flush()
                    except OSError:
                        pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
            except Exception:
                pass
            result = {"stopped": True, "detached": detach, "log_lines": len(self.log)}
            self.target = None
            self.attached_pid = None
            return result


_SESSION = CdbSession()


def smart_breakpoint(
    address: str,
    *,
    dumps: list[dict[str, Any]] | None = None,
    max_hits: int = 1,
    continue_after: bool = True,
    wait: float = 8.0,
) -> dict[str, Any]:
    """Set a breakpoint, run to it, dump what it asked for, continue.

    ``dumps``: ``[{"expr": "esp", "size": 64}, {"expr": "eax+0x20", "size": 16}]`` -
    each dump becomes one ``db <expr> L<size>`` executed while stopped at the hit.
    One tool call replaces bp -> go -> read -> go, and the session survives for more.
    """
    commands = [f"bp {address}"]
    if max_hits > 1:
        commands.append(f"bp {address} 1:{max_hits}")
    commands.append(f"g")
    # go blocks until the hit; the read-until-idle loop in _send handles the wait.
    result = _SESSION.batch(commands, wait=wait)
    hit_output = result["steps"][-1]["output"] if result["steps"] else ""
    stopped = any(marker in hit_output for marker in ("Breakpoint 0 hit", "Break instruction", "Single step"))

    dumps_out = []
    if stopped and dumps:
        dump_commands = [f"db {d['expr']} L{int(d.get('size', 64))}" for d in dumps]
        dump_result = _SESSION.batch(dump_commands, wait=1.0)
        dumps_out = dump_result["steps"]

    if continue_after and stopped:
        cont = _SESSION.command("g", wait=1.0)
        dumps_out.append({"command": "g (continue)", "output": cont["output"][:1000]})

    return {
        "breakpoint": address,
        "hit": stopped,
        "hit_output": hit_output[-1500:],
        "dumps": dumps_out,
        "session_alive": _SESSION.status()["running"],
    }


def session_start(target: str, arguments: str = "") -> dict[str, Any]:
    return _SESSION.start(target, arguments)


def session_attach(pid: int) -> dict[str, Any]:
    return _SESSION.attach(pid)


def session_command(command: str, *, wait: float = 1.5) -> dict[str, Any]:
    return _SESSION.command(command, wait=wait)


def session_batch(commands: list[str], *, wait: float = 1.2) -> dict[str, Any]:
    return _SESSION.batch(commands, wait=wait)


def session_status() -> dict[str, Any]:
    return _SESSION.status()


def session_stop(detach: bool = False) -> dict[str, Any]:
    return _SESSION.stop(detach=detach)
