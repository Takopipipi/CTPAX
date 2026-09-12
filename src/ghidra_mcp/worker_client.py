"""Supervisor for the Ghidra worker subprocess.

The MCP server never loads a JVM itself. It starts ``python -m ghidra_mcp.worker``
and talks JSON lines to it. That separation buys three things worth the plumbing:

* a wedged analysis can be killed and restarted without dropping the MCP session;
* Ghidra's noisy ``System.out`` cannot corrupt the MCP stdio channel;
* JVM start-up (5-20s) is paid once, lazily, on the first Ghidra call rather than at
  server start, so a session that only uses the static-analysis tools never pays it.

Requests are serialised: Ghidra's program database is not safe under concurrent
mutation, and the worker enforces this too.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ghidra_mcp import protocol
from ghidra_mcp.config import Settings
from ghidra_mcp.protocol import KIND_ERROR, KIND_PROGRESS, KIND_READY, KIND_RESULT, WorkerError


class WorkerCrashed(WorkerError):
    """The worker process died; a retry may still succeed after a restart."""


class WorkerBusy(WorkerError):
    """Another Ghidra operation is in flight."""


class WorkerClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.process: subprocess.Popen[bytes] | None = None
        self.ready: dict[str, Any] | None = None
        self._lock = threading.RLock()          # guards process lifecycle
        self._call_lock = threading.RLock()     # serialises requests
        self._next_id = 1
        self._pending: dict[int, dict[str, Any]] = {}
        self._pending_lock = threading.Lock()
        self._reader: threading.Thread | None = None
        self._log_path = Path(settings.log_dir) / "worker.log"
        self._log_handle: Any = None
        self.last_progress: dict[str, Any] = {}
        self.start_count = 0
        self.last_error: str | None = None

    # -- process lifecycle -----------------------------------------------
    def _worker_environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        if self.settings.ghidra_dir:
            environment["GHIDRA_INSTALL_DIR"] = str(self.settings.ghidra_dir)
        if self.settings.java_home:
            environment["JAVA_HOME"] = str(self.settings.java_home)
            # JPype resolves the JVM through JAVA_HOME, but Ghidra's own launcher
            # support code shells out to `java`, so make sure the right one is first.
            bin_dir = str(Path(self.settings.java_home) / "bin")
            environment["PATH"] = bin_dir + os.pathsep + environment.get("PATH", "")
        environment["GHIDRA_MCP_PROJECTS"] = str(self.settings.project_dir)
        environment["GHIDRA_MCP_HEAP"] = self.settings.jvm_max_heap
        if not self.settings.allow_write:
            environment["GHIDRA_MCP_READONLY"] = "1"
        source_root = str(Path(__file__).resolve().parent.parent)
        existing = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = source_root + (os.pathsep + existing if existing else "")
        environment["PYTHONUNBUFFERED"] = "1"
        environment["PYTHONIOENCODING"] = "utf-8"
        return environment

    def start(self, *, timeout: float | None = None) -> dict[str, Any]:
        """Start the worker and wait for its ready frame."""
        with self._lock:
            if self.process is not None and self.process.poll() is None and self.ready is not None:
                return self.ready

            problems = self.settings.problems()
            if problems:
                raise WorkerError("cannot start the Ghidra worker: " + " ".join(problems))

            self.settings.ensure_dirs()
            self._open_log()

            command = [sys.executable, "-m", "ghidra_mcp.worker"]
            creation_flags = 0
            if os.name == "nt":
                creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

            self.process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self._log_handle,
                env=self._worker_environment(),
                cwd=str(Path(__file__).resolve().parent.parent),
                creationflags=creation_flags,
                bufsize=0,
            )
            self.start_count += 1
            self.ready = None
            self._pending.clear()

            ready_event = threading.Event()
            self._ready_event = ready_event
            self._reader = threading.Thread(target=self._read_loop, name="ghidra-worker-reader", daemon=True)
            self._reader.start()

            limit = timeout if timeout is not None else self.settings.worker_start_timeout
            if not ready_event.wait(limit):
                tail = self.log_tail(40)
                self.stop()
                raise WorkerError(
                    f"the Ghidra worker did not become ready within {limit:.0f}s. "
                    f"Worker log tail:\n{tail}"
                )
            if self.ready is None:
                tail = self.log_tail(40)
                error = self.last_error or "unknown error"
                self.stop()
                raise WorkerError(f"the Ghidra worker failed to start: {error}\nWorker log tail:\n{tail}")
            return self.ready

    def _open_log(self) -> None:
        if self._log_handle is not None:
            return
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        # Truncate on each start so the tail we show is about this run.
        self._log_handle = open(self._log_path, "wb", buffering=0)

    def stop(self, *, timeout: float = 12.0) -> None:
        with self._lock:
            process = self.process
            self.process = None
            self.ready = None
            if process is None:
                return
            try:
                if process.poll() is None and process.stdin is not None:
                    process.stdin.write(protocol.encode({"op": "__shutdown", "id": 0}))
                    process.stdin.flush()
            except Exception:
                pass
            try:
                process.wait(timeout=timeout)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
            with self._pending_lock:
                for slot in self._pending.values():
                    slot["error"] = "worker stopped"
                    slot["event"].set()
                self._pending.clear()
            if self._log_handle is not None:
                try:
                    self._log_handle.close()
                except Exception:
                    pass
                self._log_handle = None

    def restart(self) -> dict[str, Any]:
        self.stop()
        return self.start()

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def log_tail(self, lines: int = 30) -> str:
        try:
            content = self._log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "(no worker log)"
        rows = [row for row in content.splitlines() if row.strip()]
        return "\n".join(rows[-lines:]) or "(worker log is empty)"

    # -- reader ----------------------------------------------------------
    def _read_loop(self) -> None:
        process = self.process
        if process is None or process.stdout is None:
            return
        try:
            for raw in process.stdout:
                if not raw.strip():
                    continue
                try:
                    frame = protocol.decode(raw)
                except Exception:
                    self._note(f"unparseable frame from worker: {raw[:400]!r}")
                    continue
                self._dispatch(frame)
        except Exception as exc:
            self._note(f"reader loop ended: {type(exc).__name__}: {exc}")
        finally:
            # Wake up anything still waiting: the worker is gone.
            with self._pending_lock:
                for slot in self._pending.values():
                    slot["error"] = "the Ghidra worker exited unexpectedly"
                    slot["event"].set()
                self._pending.clear()
            event = getattr(self, "_ready_event", None)
            if event is not None:
                event.set()

    def _dispatch(self, frame: dict[str, Any]) -> None:
        kind = frame.get("kind")
        if kind == KIND_READY:
            self.ready = frame
            event = getattr(self, "_ready_event", None)
            if event is not None:
                event.set()
            return
        if kind == KIND_ERROR and frame.get("fatal"):
            self.last_error = str(frame.get("message"))
            self._note(f"fatal worker error: {self.last_error}")
            event = getattr(self, "_ready_event", None)
            if event is not None:
                event.set()
            return

        request_id = frame.get("id")
        if kind == KIND_PROGRESS:
            data = frame.get("data") or {}
            self.last_progress = {"id": request_id, "at": time.time(), **data}
            self._note(f"progress {request_id}: {json.dumps(data, default=str)[:400]}")
            return

        with self._pending_lock:
            slot = self._pending.pop(request_id, None) if request_id is not None else None
        if slot is None:
            self._note(f"unmatched frame for id {request_id}: {str(frame)[:300]}")
            return
        if kind == KIND_RESULT:
            slot["result"] = frame.get("data")
        else:
            slot["error"] = str(frame.get("message") or "unknown worker error")
            slot["error_type"] = str(frame.get("error_type") or "WorkerError")
            slot["trace"] = frame.get("trace")
        slot["event"].set()

    def _note(self, message: str) -> None:
        if self._log_handle is None:
            return
        try:
            self._log_handle.write(f"[client] {message}\n".encode("utf-8", "replace"))
        except Exception:
            pass

    # -- requests --------------------------------------------------------
    def call(
        self,
        op: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
        auto_start: bool = True,
        retry_on_crash: bool = True,
    ) -> Any:
        """Run one worker operation and return its result."""
        if auto_start:
            self.start()
        if not self.running:
            raise WorkerCrashed("the Ghidra worker is not running")

        limit = timeout if timeout is not None else self.settings.request_timeout
        with self._call_lock:
            try:
                return self._call_once(op, params or {}, limit)
            except WorkerCrashed:
                if not retry_on_crash:
                    raise
                # One retry: a crash usually leaves a clean slate after a restart, and
                # failing the tool call outright would be worse than trying once more.
                self._note(f"retrying '{op}' after a worker crash")
                self.restart()
                return self._call_once(op, params or {}, limit)

    def _call_once(self, op: str, params: dict[str, Any], timeout: float) -> Any:
        process = self.process
        if process is None or process.poll() is not None or process.stdin is None:
            raise WorkerCrashed("the Ghidra worker is not running")

        with self._pending_lock:
            request_id = self._next_id
            self._next_id += 1
            slot: dict[str, Any] = {"event": threading.Event()}
            self._pending[request_id] = slot

        payload = protocol.encode({"id": request_id, "op": op, "params": params})
        try:
            process.stdin.write(payload)
            process.stdin.flush()
        except Exception as exc:
            with self._pending_lock:
                self._pending.pop(request_id, None)
            raise WorkerCrashed(f"could not send '{op}' to the worker: {exc}") from exc

        if not slot["event"].wait(timeout):
            # Ask the worker to abandon the operation so the next call is not stuck
            # behind it, then report the timeout.
            self._cancel_quietly()
            with self._pending_lock:
                self._pending.pop(request_id, None)
            raise WorkerError(
                f"'{op}' did not finish within {timeout:.0f}s and was cancelled. "
                "Long analyses should be started with a background job "
                "(ghidra_job_start) rather than a blocking call."
            )

        if "error" in slot:
            message = str(slot["error"])
            if "exited unexpectedly" in message or "worker stopped" in message:
                raise WorkerCrashed(message + f"\nWorker log tail:\n{self.log_tail(25)}")
            error = WorkerError(message, kind=str(slot.get("error_type") or "WorkerError"), trace=slot.get("trace"))
            raise error
        return slot.get("result")

    def _cancel_quietly(self) -> None:
        process = self.process
        if process is None or process.stdin is None or process.poll() is not None:
            return
        try:
            with self._pending_lock:
                request_id = self._next_id
                self._next_id += 1
            process.stdin.write(protocol.encode({"id": request_id, "op": "__cancel"}))
            process.stdin.flush()
        except Exception:
            pass

    def cancel(self) -> bool:
        """Interrupt whatever the worker is doing right now."""
        if not self.running:
            return False
        self._cancel_quietly()
        return True

    def ping(self, timeout: float = 20.0) -> dict[str, Any]:
        return self.call("__ping", {}, timeout=timeout, retry_on_crash=False)

    def describe(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "pid": self.process.pid if self.process is not None else None,
            "starts": self.start_count,
            "ready": self.ready,
            "log": str(self._log_path),
            "last_progress": self.last_progress or None,
        }
