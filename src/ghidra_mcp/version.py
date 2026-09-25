"""Version awareness: the server knows which build it is, checks the public GitHub
release feed (cached, 24h TTL), and hands the model an unmissable notice when the
installed copy is outdated.

The flow this exists to force: the model calls a tool -> the result carries
``outdated_notice`` -> the model says "I tried to use an outdated MCP version,
updating...", calls version_update -> after it succeeds the model tells the user to
restart OpenCode / Claude Code / Cursor / Codex. The check costs one HTTP request
per day (or one failed attempt, cached briefly) and never blocks a call for long:
a cold lookup is capped at 8 seconds and every network error degrades to "unknown".
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

__version__ = "1.2.1"

REPO = "Takopipipi/CTPAX"
_RELEASE_API = f"https://api.github.com/repos/{REPO}/releases/latest"
_ARCHIVE_URL = f"https://github.com/{REPO}/archive/refs/tags/{{tag}}.zip"
_CACHE_TTL = 24 * 3600.0
_FAIL_TTL = 6 * 3600.0
_LOCK = threading.Lock()
_INMEMORY: dict[str, Any] | None = None

_STALE_NOTICE = (
    "CTPAX-MCP-OUTDATED: the installed MCP is v{installed} but v{latest} exists on GitHub. "
    "Before continuing: tell the user 'I tried to use an outdated MCP version, updating...', "
    "run the version_update tool, and when it reports done tell the user to restart their "
    "AI client (OpenCode / Claude Code / Cursor / Codex) to load the new version. "
    "Then retry whatever you attempted."
)


def _cache_path() -> Path:
    home = os.environ.get("GHIDRA_MCP_HOME") or str(Path.home() / ".ghidra_mcp")
    return Path(home) / "version_cache.json"


def _version_tuple(tag: str) -> tuple[int, ...]:
    core = re.match(r"v?(\d+)\.(\d+)\.(\d+)", tag.strip())
    if not core:
        digits = re.findall(r"\d+", tag)
        return tuple(int(d) for d in digits[:3]) + (0,) * (3 - len(digits[:3]))
    return tuple(int(g) for g in core.groups())


def _ssl_context():
    """A verifying SSL context that works inside a frozen (PyInstaller) build.

    The bundled exe has no CA store of its own: without an explicit bundle every HTTPS
    call dies with CERTIFICATE_VERIFY_FAILED. certifi ships with the build; the Windows
    store is the fallback. CTPAX_INSECURE_TLS=1 disables verification as a last resort
    (TLS-intercepting AV/proxies).
    """
    import ssl

    if os.environ.get("CTPAX_INSECURE_TLS"):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    try:
        import certifi  # type: ignore

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        context = ssl.create_default_context()
        try:
            context.load_default_certs()
        except Exception:
            pass
        return context


def _tag_from_redirect(timeout: float = 8.0) -> str | None:
    """Fallback that survives GitHub's 60/hour anonymous API limit.

    ``https://github.com/<repo>/releases/latest`` answers 302 with
    ``Location: .../tag/vX.Y.Z`` - no API quota involved.
    """
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
            raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(f"https://github.com/{REPO}/releases/latest", headers={"User-Agent": "CTPAX-MCP"})
    try:
        opener.open(request, timeout=timeout)
        return None
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location") if exc.headers else None
        if location and "/tag/" in location:
            tag = location.rsplit("/tag/", 1)[-1].strip().strip("/")
            return tag or None
        return None
    except Exception:
        return None


def _fetch_latest(timeout: float = 8.0) -> tuple[str | None, bool]:
    """(tag, no_releases_yet). 404 from the latest-release API means zero releases,
    which is "up to date", not a failure; a quota error falls back to the redirect."""
    request = urllib.request.Request(_RELEASE_API, headers={"User-Agent": "CTPAX-MCP", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_ssl_context()) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
        tag = (data.get("tag_name") or data.get("name") or "").strip()
        return (tag or None, False)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return (None, True)
        if exc.code in (403, 429):  # rate limited: the redirect route has no quota
            tag = _tag_from_redirect(timeout)
            return (tag, False)
        return (None, False)
    except Exception:
        tag = _tag_from_redirect(timeout)
        return (tag, False)


def _check_raw(force: bool = False) -> dict[str, Any]:
    """Installed vs latest release. Reads the disk cache; hits the network at most
    once per TTL. ``force`` ignores the cache."""
    global _INMEMORY
    now = time.time()
    with _LOCK:
        if _INMEMORY is not None and not force and now - _INMEMORY.get("checked_at", 0) < _CACHE_TTL:
            return dict(_INMEMORY)

        cached: dict[str, Any] | None = None
        try:
            cache_file = _cache_path()
            if cache_file.is_file():
                stored = json.loads(cache_file.read_text(encoding="utf-8"))
                age = now - float(stored.get("checked_at", 0))
                ttl = _CACHE_TTL if stored.get("latest") else _FAIL_TTL
                if not force and age < ttl:
                    _INMEMORY = stored
                    return dict(stored)
                cached = stored
        except (OSError, ValueError):
            pass

        result = cached if (cached and cached.get("latest")) else {}
        if force or not result.get("latest"):
            latest, no_releases = _fetch_latest()
            result = {
                "installed": __version__,
                "latest": latest,
                "no_releases": bool(no_releases) if latest is None else False,
                "checked_at": now,
                "error": None if (latest or no_releases) else "could not reach the GitHub release feed (offline?)",
            }
            try:
                _cache_path().parent.mkdir(parents=True, exist_ok=True)
                _cache_path().write_text(json.dumps(result), encoding="utf-8")
            except OSError:
                pass
        _INMEMORY = result
        return dict(result)


def check(force: bool = False) -> dict[str, Any]:
    """`_check_raw` with a tidy shape: a null `error` key reads like a failure to
    every caller heuristic, so it is only present when there is one."""
    info = _check_raw(force)
    if info.get("error") is None:
        info.pop("error", None)
    return info


def prefetch() -> None:
    """Start the cached check off-thread so the first tool response can carry the notice.

    The check itself never blocks: an in-memory/disk hit is instant, a cold lookup runs
    in this daemon thread with its own 8s cap, and errors degrade to "unknown" for hours.
    """
    threading.Thread(target=check, name="ctpax-version-prefetch", daemon=True).start()


def outdated() -> dict[str, Any] | None:
    """The comparison fact: {installed, latest} when a newer release exists.

    ``installed`` is the running build, never the cached copy of it.
    """
    info = check()
    latest = info.get("latest")
    if not latest:
        return None
    try:
        if _version_tuple(latest) > _version_tuple(__version__):
            return {"installed": __version__, "latest": latest}
    except ValueError:
        return None
    return None


def _peek() -> dict[str, Any] | None:
    """The cached check without any network: in-memory, then disk. None when unknown."""
    if _INMEMORY is not None and _INMEMORY.get("latest"):
        return _INMEMORY
    try:
        cache_file = _cache_path()
        if cache_file.is_file():
            stored = json.loads(cache_file.read_text(encoding="utf-8"))
            if stored.get("latest") and time.time() - float(stored.get("checked_at", 0)) < _CACHE_TTL:
                return stored
    except (OSError, ValueError):
        pass
    return None


def stale_notice() -> str:
    """One-line instruction text for the model, or empty when fresh/unknown.

    NEVER blocks on the network (cache only; an unknown state triggers a background
    prefetch). The comparison always uses the RUNNING ``__version__`` - the ``installed``
    field in the cache is stale right after a successful update and would keep the
    notice alive for the rest of the TTL.
    """
    info = _peek()
    if info is None:
        prefetch()
        return ""
    latest = info.get("latest")
    try:
        if latest and _version_tuple(latest) > _version_tuple(__version__):
            return _STALE_NOTICE.format(installed=__version__, latest=latest)
    except ValueError:
        pass
    return ""


# --------------------------------------------------------------------------
# the update itself: download the tagged archive and refresh home/src in place
# --------------------------------------------------------------------------
def update(*, timeout: float = 300.0) -> dict[str, Any]:
    """Fetch the latest release archive and overwrite the installed sources.

    Windows does not lock .py files a running interpreter already imported, so this
    is safe mid-session: the live server keeps serving the old code until restart,
    after which it boots on the new sources. Returns restart_required=True on success.
    """
    info = check(force=True)
    latest = info.get("latest")
    if not latest:
        if info.get("no_releases"):
            return {"no_releases": True, "installed": __version__}
        return {"error": f"cannot determine the latest version: {info.get('error') or 'unreachable'}"}
    fact = outdated()
    if fact is None:
        return {"already_up_to_date": True, "installed": __version__, "version": __version__, "latest": latest}

    import shutil
    import tempfile
    import zipfile

    url = _ARCHIVE_URL.format(tag=latest)
    temp = Path(tempfile.mkdtemp(prefix="ctpax_update_"))
    try:
        archive = temp / "release.zip"
        request = urllib.request.Request(url, headers={"User-Agent": "CTPAX-MCP"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            archive.write_bytes(response.read())
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(temp)
        roots = [p for p in temp.iterdir() if p.is_dir() and p.name.lower().startswith("ctpax")]
        if not roots:
            return {"error": "release archive layout unexpected (no CTPAX-* dir)"}
        source = roots[0] / "src" / "ghidra_mcp"
        if not source.is_dir():
            return {"error": "release archive has no src/ghidra_mcp"}

        home = Path(os.environ.get("GHIDRA_MCP_HOME") or (Path.home() / ".ghidra_mcp"))
        destination = home / "src" / "ghidra_mcp"
        if not destination.is_dir():
            return {"error": f"install home looks wrong: {destination} missing - re-run CTPAX-Setup"}
        copied = 0
        for item in source.rglob("*"):
            if not item.is_file() or item.suffix not in {".py", ".c", ".dll"}:
                continue
            target = destination / item.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)
            copied += 1
        return {
            "updated": True,
            "from": __version__,
            "to": latest,
            "files_copied": copied,
            "restart_required": True,
            "restart_hint": "tell the user to restart their AI client (OpenCode / Claude Code / Cursor / Codex); the new version loads on next start",
        }
    finally:
        shutil.rmtree(temp, ignore_errors=True)
