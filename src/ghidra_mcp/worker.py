"""Ghidra worker: the only process in this system that owns a JVM.

Run as ``python -m ghidra_mcp.worker`` with ``GHIDRA_INSTALL_DIR`` and ``JAVA_HOME``
set. It speaks the newline-delimited JSON protocol in :mod:`ghidra_mcp.protocol`
over stdin/stdout.

Two threads:

* the reader thread parses requests and answers ``__cancel``/``__ping`` inline, so a
  runaway analysis can still be interrupted;
* the executor thread runs Ghidra operations strictly one at a time, because the
  Ghidra program database is not safe to drive from several threads at once.

stdout is hijacked before the JVM starts: Ghidra logs to ``System.out`` freely and a
single stray line there would corrupt the protocol stream.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import traceback
from typing import Any

# --- stdout isolation, before anything imports jpype -----------------------
_PROTOCOL_FD = os.dup(1)
os.dup2(2, 1)  # fd 1 now points at stderr; Java's System.out lands in the log
_PROTOCOL_OUT = os.fdopen(_PROTOCOL_FD, "wb", buffering=0)
sys.stdout = sys.stderr  # type: ignore[assignment]

from ghidra_mcp import protocol  # noqa: E402  (import after fd surgery)
from ghidra_mcp.protocol import KIND_ERROR, KIND_PROGRESS, KIND_READY, KIND_RESULT  # noqa: E402

_write_lock = threading.Lock()


def send(frame: dict[str, Any]) -> None:
    payload = protocol.encode(frame)
    with _write_lock:
        _PROTOCOL_OUT.write(payload)


def log(message: str) -> None:
    sys.stderr.write(f"[worker] {message}\n")
    sys.stderr.flush()


class Worker:
    def __init__(self) -> None:
        self.requests: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self.session: Any = None  # ghidra_mcp.ghidra_ops.Session
        self.current_id: int | None = None
        self.stop = threading.Event()

    # -- start-up --------------------------------------------------------
    def boot(self) -> None:
        import time

        started = time.time()
        install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        if not install_dir:
            raise RuntimeError("GHIDRA_INSTALL_DIR is not set")
        if not os.environ.get("JAVA_HOME"):
            raise RuntimeError("JAVA_HOME is not set")

        import pyghidra
        from pyghidra.launcher import HeadlessPyGhidraLauncher

        launcher = HeadlessPyGhidraLauncher(verbose=False, install_dir=install_dir)
        heap = os.environ.get("GHIDRA_MCP_HEAP")
        if heap:
            launcher.add_vmargs(f"-Xmx{heap}")
        launcher.start()

        # Ghidra's own stdout/stderr also need to stay off the protocol stream.
        from java.io import PrintStream, FileOutputStream, FileDescriptor  # type: ignore
        from java.lang import System  # type: ignore

        err_stream = PrintStream(FileOutputStream(FileDescriptor.err), True)
        System.setOut(err_stream)
        System.setErr(err_stream)

        from ghidra_mcp import ghidra_ops

        self.session = ghidra_ops.Session(pyghidra)
        elapsed = time.time() - started
        send(
            {
                "kind": KIND_READY,
                "protocol": protocol.PROTOCOL_VERSION,
                "startup_seconds": round(elapsed, 2),
                "ghidra": self.session.ghidra_version(),
                "install_dir": install_dir,
                "ops": sorted(ghidra_ops.OPERATIONS),
            }
        )

    # -- request plumbing ------------------------------------------------
    def reader_loop(self) -> None:
        for raw in sys.stdin.buffer:
            raw = raw.strip()
            if not raw:
                continue
            try:
                request = protocol.decode(raw)
            except Exception as exc:  # malformed frame: report, keep going
                send({"kind": KIND_ERROR, "id": None, "message": f"bad request frame: {exc}"})
                continue
            op = request.get("op")
            if op == "__shutdown":
                self.requests.put(None)
                return
            if op == "__cancel":
                cancelled = self.session.cancel() if self.session else False
                send({"kind": KIND_RESULT, "id": request.get("id"), "data": {"cancelled": cancelled}})
                continue
            if op == "__ping":
                send({"kind": KIND_RESULT, "id": request.get("id"), "data": {"pong": True, "busy": self.current_id is not None}})
                continue
            self.requests.put(request)
        self.requests.put(None)

    def executor_loop(self) -> None:
        from ghidra_mcp import ghidra_ops

        while True:
            request = self.requests.get()
            if request is None:
                self.stop.set()
                return
            request_id = request.get("id")
            self.current_id = request_id
            try:
                handler = ghidra_ops.OPERATIONS.get(request.get("op", ""))
                if handler is None:
                    raise protocol.WorkerError(f"unknown op: {request.get('op')!r}")

                def progress(**data: Any) -> None:
                    send({"kind": KIND_PROGRESS, "id": request_id, "data": data})

                params = request.get("params") or {}
                result = handler(self.session, params, progress)
                send({"kind": KIND_RESULT, "id": request_id, "data": result})
            except Exception as exc:
                send(
                    {
                        "kind": KIND_ERROR,
                        "id": request_id,
                        "message": f"{type(exc).__name__}: {exc}",
                        "error_type": type(exc).__name__,
                        "trace": traceback.format_exc(limit=12),
                    }
                )
            finally:
                self.current_id = None
                if self.session is not None:
                    self.session.clear_cancel()

    def run(self) -> int:
        try:
            self.boot()
        except Exception as exc:
            send(
                {
                    "kind": KIND_ERROR,
                    "id": None,
                    "message": f"worker start-up failed: {type(exc).__name__}: {exc}",
                    "trace": traceback.format_exc(limit=20),
                    "fatal": True,
                }
            )
            return 2

        executor = threading.Thread(target=self.executor_loop, name="ghidra-exec", daemon=True)
        executor.start()
        try:
            self.reader_loop()
        except Exception:
            log("reader loop crashed:\n" + traceback.format_exc())
        self.stop.wait(timeout=10)
        try:
            if self.session is not None:
                self.session.shutdown()
        except Exception:
            log("shutdown failed:\n" + traceback.format_exc())
        return 0


def main() -> int:
    return Worker().run()


if __name__ == "__main__":
    raise SystemExit(main())
