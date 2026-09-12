"""Background jobs for work that outlives a single tool call.

Auto-analysing a large binary, decompiling a whole module, or grepping the
decompilation of ten thousand functions takes minutes. Holding an MCP tool call open
for that is the wrong shape: it blocks, it times out, and the caller learns nothing
until it finishes.

A job runs on a worker thread, publishes progress as it goes, and can be polled or
cancelled. The pattern mirrors how the Ghidra worker already reports progress frames,
so a long ``analyze`` becomes ``job_start`` then ``job_status`` rather than a wait.
"""

from __future__ import annotations

import threading
import time
import traceback
import uuid
from typing import Any, Callable


class Job:
    def __init__(self, label: str, kind: str) -> None:
        self.id = uuid.uuid4().hex[:8]
        self.label = label
        self.kind = kind
        self.status = "running"
        self.progress: dict[str, Any] = {}
        self.log: list[str] = []
        self.result: Any = None
        self.error: str | None = None
        self.trace: str | None = None
        self.started = time.time()
        self.finished: float | None = None
        self.cancel_event = threading.Event()
        self._lock = threading.Lock()

    # -- callbacks handed to the job body --------------------------------
    def set_progress(self, **data: Any) -> None:
        with self._lock:
            self.progress = {"at": round(time.time() - self.started, 1), **data}

    def note(self, message: str) -> None:
        with self._lock:
            self.log.append(f"[{time.time() - self.started:6.1f}s] {message}")
            if len(self.log) > 400:
                del self.log[:200]

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def describe(self, *, include_result: bool = True, log_lines: int = 15) -> dict[str, Any]:
        with self._lock:
            elapsed = (self.finished or time.time()) - self.started
            payload: dict[str, Any] = {
                "job_id": self.id,
                "label": self.label,
                "kind": self.kind,
                "status": self.status,
                "elapsed_seconds": round(elapsed, 1),
                "progress": self.progress or None,
                "log_tail": self.log[-log_lines:] if self.log else [],
            }
            if self.status == "error":
                payload["error"] = self.error
                payload["trace"] = self.trace
            if include_result and self.status == "done":
                payload["result"] = self.result
            return payload


class JobManager:
    MAX_JOBS = 40

    def __init__(self) -> None:
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def start(self, label: str, kind: str, body: Callable[[Job], Any]) -> Job:
        job = Job(label, kind)
        with self._lock:
            self.jobs[job.id] = job
            self._prune()

        def run() -> None:
            try:
                job.result = body(job)
                job.status = "cancelled" if job.cancelled and job.result is None else "done"
            except Exception as exc:
                job.status = "error"
                job.error = f"{type(exc).__name__}: {exc}"
                job.trace = traceback.format_exc(limit=12)
            finally:
                job.finished = time.time()

        threading.Thread(target=run, name=f"job-{job.id}", daemon=True).start()
        return job

    def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    def cancel(self, job_id: str) -> bool:
        job = self.jobs.get(job_id)
        if job is None or job.status != "running":
            return False
        job.cancel_event.set()
        job.note("cancellation requested")
        return True

    def list(self) -> list[dict[str, Any]]:
        return [job.describe(include_result=False, log_lines=3) for job in sorted(self.jobs.values(), key=lambda j: j.started, reverse=True)]

    def _prune(self) -> None:
        if len(self.jobs) <= self.MAX_JOBS:
            return
        finished = sorted(
            (j for j in self.jobs.values() if j.status != "running"),
            key=lambda j: j.finished or j.started,
        )
        for job in finished:
            if len(self.jobs) <= self.MAX_JOBS:
                break
            self.jobs.pop(job.id, None)
