"""JSON-line protocol shared between the MCP server and the Ghidra worker process.

The worker is a separate process because a JVM cannot be un-started: keeping it out
of the MCP server process means a wedged analysis can be killed and restarted
without taking the MCP connection down with it.

Framing is newline-delimited JSON on the worker's stdin/stdout. Both sides keep
stdout *strictly* for protocol frames; every diagnostic goes to stderr, which the
server drains into a log file. Ghidra is chatty on ``System.out``, so the worker
redirects the Java and Python stdout streams to stderr right after start-up and
writes frames to a private duplicate of the original handle.
"""

from __future__ import annotations

import json
from typing import Any

PROTOCOL_VERSION = 1

# Frame kinds sent worker -> server.
KIND_READY = "ready"
KIND_RESULT = "result"
KIND_ERROR = "error"
KIND_PROGRESS = "progress"
KIND_LOG = "log"


def encode(frame: dict[str, Any]) -> bytes:
    """Serialise one frame. ``default=str`` keeps Java objects from killing a response."""
    return (json.dumps(frame, ensure_ascii=False, default=str) + "\n").encode("utf-8", "replace")


def decode(line: bytes | str) -> dict[str, Any]:
    if isinstance(line, bytes):
        line = line.decode("utf-8", "replace")
    return json.loads(line)


class WorkerError(RuntimeError):
    """An error raised inside the worker and re-raised on the server side."""

    def __init__(self, message: str, *, kind: str = "WorkerError", trace: str | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.trace = trace
