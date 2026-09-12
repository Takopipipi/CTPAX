"""Ghidra session management and the operation registry.

This module runs *inside the worker process* and is the only place that touches
Ghidra's Java API. It owns:

* the Ghidra project (one project per install, programs live inside it);
* open program handles, keyed by project path, with their decompiler interfaces;
* a cancellable :class:`TaskMonitor` so a long analysis can be interrupted;
* the ``OPERATIONS`` registry that :mod:`ghidra_mcp.worker` dispatches into.

Design notes worth keeping in mind when extending it:

Analysis results are persisted. A binary is imported into a Ghidra project under a
name derived from its SHA-256, so opening the same file twice reuses the previous
analysis instead of paying 15-120 seconds again. That is also why every mutating
operation saves the program: an agent that renames fifty functions and comes back
tomorrow should still see those names.

Every mutation is wrapped in a Ghidra transaction. Skipping that does not merely
lose undo history, it corrupts the program database.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

OperationFn = Callable[["Session", dict[str, Any], Callable[..., None]], Any]
OPERATIONS: dict[str, OperationFn] = {}


def op(name: str) -> Callable[[OperationFn], OperationFn]:
    """Register an operation callable under *name*."""

    def decorator(fn: OperationFn) -> OperationFn:
        if name in OPERATIONS:
            raise RuntimeError(f"duplicate operation name: {name}")
        OPERATIONS[name] = fn
        return fn

    return decorator


class OpError(RuntimeError):
    """An error whose message is meant for the model, not a stack trace."""


# --------------------------------------------------------------------------
# byte helpers: JPype maps Java's signed byte onto Python ints 0..255 badly in
# both directions, so every conversion goes through these two functions.
# --------------------------------------------------------------------------
def to_jbytes(data: bytes) -> Any:
    from jpype import JArray, JByte  # type: ignore

    return JArray(JByte)([(b - 256) if b > 127 else b for b in data])


def from_jbytes(buf: Any, length: int | None = None) -> bytes:
    count = len(buf) if length is None else length
    return bytes((int(buf[i]) & 0xFF) for i in range(count))


def sha256_file(path: Path, limit: int | None = None) -> str:
    digest = hashlib.sha256()
    read = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            read += len(chunk)
            if limit and read >= limit:
                break
    return digest.hexdigest()


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_name(name: str) -> str:
    cleaned = _SAFE_NAME_RE.sub("_", name).strip("._-")
    return cleaned or "program"


# --------------------------------------------------------------------------
# open program bookkeeping
# --------------------------------------------------------------------------
@dataclass
class OpenProgram:
    key: str  # project path, e.g. "/notepad.exe"
    path: str  # original file path, when known
    program: Any
    consumer: Any
    decompiler: Any = None
    opened_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)

    def touch(self) -> None:
        self.last_used = time.time()


class Session:
    """Owns the Ghidra project and every open program."""

    MAX_OPEN_PROGRAMS = 6

    def __init__(self, pyghidra_module: Any) -> None:
        self.pyghidra = pyghidra_module
        self.project: Any = None
        self.project_dir = Path(os.environ.get("GHIDRA_MCP_PROJECTS") or (Path.home() / ".ghidra_mcp" / "projects"))
        self.project_name = os.environ.get("GHIDRA_MCP_PROJECT") or "mcp"
        self.programs: dict[str, OpenProgram] = {}
        self.active_key: str | None = None
        self._cancel = threading.Event()
        self._lock = threading.RLock()
        self._monitors: list[Any] = []
        self._comment_types: dict[str, Any] | None = None

    # -- lifecycle -------------------------------------------------------
    def ghidra_version(self) -> str:
        from ghidra.framework import Application  # type: ignore

        try:
            return str(Application.getApplicationVersion())
        except Exception:
            return "unknown"

    def ensure_project(self) -> Any:
        if self.project is None:
            self.project_dir.mkdir(parents=True, exist_ok=True)
            self.project = self.pyghidra.open_project(str(self.project_dir), self.project_name, create=True)
        return self.project

    def shutdown(self) -> None:
        with self._lock:
            for entry in list(self.programs.values()):
                self._close_entry(entry, save=True)
            self.programs.clear()
            if self.project is not None:
                try:
                    self.project.close()
                except Exception:
                    pass
                self.project = None

    # -- cancellation ----------------------------------------------------
    def cancel(self) -> bool:
        """Ask the in-flight operation to stop.

        Both halves matter: the flag stops our own Python loops, and cancelling the
        live Ghidra monitors stops work happening inside Java (auto-analysis, a
        decompile, a memory search) which would otherwise ignore the flag entirely.
        """
        self._cancel.set()
        with self._lock:
            monitors = list(self._monitors)
        for monitor in monitors:
            try:
                monitor.cancel()
            except Exception:
                pass
        return True

    def clear_cancel(self) -> None:
        self._cancel.clear()
        with self._lock:
            self._monitors.clear()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def check_cancel(self) -> None:
        if self._cancel.is_set():
            raise OpError("operation cancelled")

    def monitor(self) -> Any:
        """A fresh Ghidra TaskMonitor tracked for cancellation.

        Implementing ``TaskMonitor`` as a JPype proxy is possible but brittle across
        Ghidra versions (the interface keeps gaining default methods). Handing out a
        real ``TaskMonitorAdapter`` and remembering it so :meth:`cancel` can cancel it
        achieves the same thing with none of the fragility.
        """
        from ghidra.util.task import TaskMonitorAdapter  # type: ignore

        monitor = TaskMonitorAdapter(True)
        if self._cancel.is_set():
            monitor.cancel()
        with self._lock:
            self._monitors.append(monitor)
            # Keep the list from growing without bound on a long-lived session.
            if len(self._monitors) > 32:
                del self._monitors[:-8]
        return monitor

    # -- programs --------------------------------------------------------
    def project_path_for(self, file_path: Path, program_name: str | None = None) -> str:
        digest = sha256_file(file_path)[:12]
        base = safe_name(program_name or file_path.name)
        return f"/{base}__{digest}"

    def import_binary(
        self,
        file_path: Path,
        *,
        language: str | None = None,
        compiler: str | None = None,
        loader: str | None = None,
        program_name: str | None = None,
        reimport: bool = False,
        progress: Callable[..., None] | None = None,
    ) -> tuple[str, bool]:
        """Import *file_path* into the project, or reuse a previous import.

        Returns ``(project_path, imported_now)``.
        """
        project = self.ensure_project()
        key = self.project_path_for(file_path, program_name)
        data = project.getProjectData()

        existing = data.getFile(key)
        if existing is not None and not reimport:
            return key, False
        if existing is not None and reimport:
            self.close_program(key, save=False)
            existing.delete()

        if progress:
            progress(stage="import", file=str(file_path))

        builder = self.pyghidra.program_loader().project(project).source(str(file_path))
        builder = builder.projectFolderPath("/").name(key.lstrip("/"))
        if language:
            builder = builder.language(language)
        if compiler:
            builder = builder.compiler(compiler)
        if loader:
            from java.lang import ClassLoader  # type: ignore
            from jpype import JClass  # type: ignore

            builder = builder.loaders(JClass(loader, ClassLoader.getSystemClassLoader()))
        builder = builder.monitor(self.monitor())

        results = builder.load()
        if results is None:
            raise OpError(
                f"Ghidra could not identify '{file_path.name}'. Pass an explicit language "
                "(e.g. 'x86:LE:64:default') or loader."
            )
        try:
            results.save(self.monitor())
        finally:
            results.close()
        return key, True

    def open_program(self, key: str) -> OpenProgram:
        with self._lock:
            entry = self.programs.get(key)
            if entry is not None:
                entry.touch()
                return entry
            project = self.ensure_project()
            program, consumer = self.pyghidra.consume_program(project, key)
            entry = OpenProgram(key=key, path=str(program.getExecutablePath() or ""), program=program, consumer=consumer)
            self.programs[key] = entry
            self.active_key = key
            self._evict_if_needed()
            return entry

    def _evict_if_needed(self) -> None:
        if len(self.programs) <= self.MAX_OPEN_PROGRAMS:
            return
        victims = sorted(self.programs.values(), key=lambda e: e.last_used)
        for victim in victims:
            if len(self.programs) <= self.MAX_OPEN_PROGRAMS:
                break
            if victim.key == self.active_key:
                continue
            self._close_entry(victim, save=True)
            self.programs.pop(victim.key, None)

    def _close_entry(self, entry: OpenProgram, *, save: bool) -> None:
        try:
            if entry.decompiler is not None:
                entry.decompiler.dispose()
                entry.decompiler = None
        except Exception:
            pass
        try:
            if save and entry.program.isChanged():
                entry.program.getDomainFile().save(self.monitor())
        except Exception:
            pass
        try:
            entry.program.release(entry.consumer)
        except Exception:
            pass

    def close_program(self, key: str, *, save: bool = True) -> bool:
        with self._lock:
            entry = self.programs.pop(key, None)
            if entry is None:
                return False
            self._close_entry(entry, save=save)
            if self.active_key == key:
                self.active_key = next(iter(self.programs), None)
            return True

    def resolve(self, params: dict[str, Any]) -> OpenProgram:
        """Pick the program an operation should act on.

        ``program`` may be a project path ("/foo__ab12"), a bare name, or omitted to
        use whatever was opened last. Being forgiving here matters: the model will
        pass back whichever of those three it happens to remember.
        """
        wanted = params.get("program")
        if not wanted:
            if self.active_key and self.active_key in self.programs:
                entry = self.programs[self.active_key]
                entry.touch()
                return entry
            if self.active_key:
                return self.open_program(self.active_key)
            raise OpError("No program is open. Call ghidra_open first.")
        wanted = str(wanted)
        if wanted in self.programs:
            entry = self.programs[wanted]
            entry.touch()
            return entry
        candidates = self.list_project_files()
        exact = [c for c in candidates if c == wanted]
        if exact:
            return self.open_program(exact[0])
        lowered = wanted.lower()
        partial = [c for c in candidates if lowered in c.lower()]
        if len(partial) == 1:
            return self.open_program(partial[0])
        if len(partial) > 1:
            raise OpError(f"'{wanted}' matches several programs: {', '.join(partial[:8])}")
        raise OpError(f"No program '{wanted}' in the project. Open programs: {', '.join(candidates) or '(none)'}")

    def list_project_files(self) -> list[str]:
        project = self.ensure_project()
        out: list[str] = []

        def visit(folder: Any) -> None:
            for file in folder.getFiles():
                out.append(file.getPathname())
            for child in folder.getFolders():
                visit(child)

        visit(project.getProjectData().getRootFolder())
        return sorted(out)

    # -- transactions & saving -------------------------------------------
    def transaction(self, entry: OpenProgram, description: str) -> Any:
        return self.pyghidra.transaction(entry.program, description)

    def save(self, entry: OpenProgram) -> None:
        program = entry.program
        if program.isChanged():
            program.getDomainFile().save(self.monitor())

    # -- decompiler ------------------------------------------------------
    def decompiler(self, entry: OpenProgram) -> Any:
        if entry.decompiler is not None:
            return entry.decompiler
        from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore

        interface = DecompInterface()
        options = DecompileOptions()
        options.setEliminateUnreachable(True)
        interface.setOptions(options)
        interface.setSimplificationStyle("decompile")
        if not interface.openProgram(entry.program):
            raise OpError(f"decompiler refused the program: {interface.getLastMessage()}")
        entry.decompiler = interface
        return interface

    def comment_type(self, name: str) -> Any:
        """Resolve a comment type across Ghidra versions.

        Ghidra 11.4+ uses a ``CommentType`` enum; older releases use int constants on
        ``CodeUnit``. Supporting both keeps this server working across installs.
        """
        if self._comment_types is None:
            table: dict[str, Any] = {}
            try:
                from ghidra.program.model.listing import CommentType  # type: ignore

                for value in CommentType.values():
                    table[str(value).upper()] = value
            except Exception:
                from ghidra.program.model.listing import CodeUnit  # type: ignore

                table = {
                    "EOL": CodeUnit.EOL_COMMENT,
                    "PRE": CodeUnit.PRE_COMMENT,
                    "POST": CodeUnit.POST_COMMENT,
                    "PLATE": CodeUnit.PLATE_COMMENT,
                    "REPEATABLE": CodeUnit.REPEATABLE_COMMENT,
                }
            self._comment_types = table
        key = name.upper().replace("_COMMENT", "")
        if key not in self._comment_types:
            raise OpError(f"unknown comment type '{name}'. Use one of: {', '.join(sorted(self._comment_types))}")
        return self._comment_types[key]


# --------------------------------------------------------------------------
# address / function / symbol resolution shared by the operation modules
# --------------------------------------------------------------------------
_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]+$")


def parse_address(program: Any, value: Any) -> Any:
    """Turn a user-supplied address into a Ghidra ``Address``.

    Accepts ``0x140001010``, ``140001010``, ``ram:140001010``, an int, or a symbol
    name. Symbol names are allowed because the model frequently passes them where an
    address is expected, and failing on that would be needless friction.
    """
    if value is None:
        raise OpError("an address is required")
    factory = program.getAddressFactory()
    if isinstance(value, int):
        return factory.getDefaultAddressSpace().getAddress(value)
    text = str(value).strip()
    if not text:
        raise OpError("an address is required")
    if ":" in text:
        addr = factory.getAddress(text)
        if addr is not None:
            return addr
    stripped = text[2:] if text.lower().startswith("0x") else text
    if _HEX_RE.match(stripped):
        addr = factory.getAddress(stripped)
        if addr is not None:
            return addr
        try:
            return factory.getDefaultAddressSpace().getAddress(int(stripped, 16))
        except Exception:
            pass
    symbol = find_symbol(program, text)
    if symbol is not None:
        return symbol.getAddress()
    raise OpError(f"could not resolve address or symbol '{value}'")


def find_symbol(program: Any, name: str) -> Any:
    table = program.getSymbolTable()
    symbols = list(table.getGlobalSymbols(name))
    if symbols:
        return symbols[0]
    iterator = table.getSymbolIterator(name, True)
    for symbol in iterator:
        return symbol
    return None


def resolve_function(program: Any, value: Any) -> Any:
    """Resolve a function by name, address, or ``entry``."""
    manager = program.getFunctionManager()
    if value is None:
        raise OpError("a function name or address is required")
    text = str(value).strip()
    if text.lower() == "entry":
        for address in program.getSymbolTable().getExternalEntryPointIterator():
            function = manager.getFunctionContaining(address)
            if function is not None:
                return function
    # Exact name first: names beat addresses, since "FUN_140001010" is a name.
    matches = [f for f in manager.getFunctions(True) if str(f.getName()) == text]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        joined = ", ".join(f"{f.getName()}@{f.getEntryPoint()}" for f in matches[:6])
        raise OpError(f"'{text}' is ambiguous, {len(matches)} functions match: {joined}")
    try:
        address = parse_address(program, text)
    except OpError:
        address = None
    if address is not None:
        function = manager.getFunctionAt(address) or manager.getFunctionContaining(address)
        if function is not None:
            return function
    lowered = text.lower()
    fuzzy = [f for f in manager.getFunctions(True) if lowered in str(f.getName()).lower()]
    if len(fuzzy) == 1:
        return fuzzy[0]
    if len(fuzzy) > 1:
        joined = ", ".join(f"{f.getName()}@{f.getEntryPoint()}" for f in fuzzy[:8])
        raise OpError(f"'{text}' matches {len(fuzzy)} functions: {joined}")
    raise OpError(f"no function found for '{value}'")


def function_summary(function: Any) -> dict[str, Any]:
    body = function.getBody()
    return {
        "name": str(function.getName()),
        "entry": str(function.getEntryPoint()),
        "size": int(body.getNumAddresses()),
        "signature": str(function.getSignature().getPrototypeString()),
        "calling_convention": str(function.getCallingConventionName()),
        "thunk": bool(function.isThunk()),
        "external": bool(function.isExternal()),
        "namespace": str(function.getParentNamespace().getName()),
    }


def iter_limited(iterable: Iterable[Any], offset: int, limit: int) -> Iterator[Any]:
    for index, item in enumerate(iterable):
        if index < offset:
            continue
        if index >= offset + limit:
            return
        yield item


def clamp(value: Any, low: int, high: int, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


# Importing the operation modules populates OPERATIONS; keep this at the bottom so
# they can import the helpers above.
from ghidra_mcp import ops_program, ops_code, ops_data, ops_edit, ops_power, ops_re  # noqa: E402,F401
