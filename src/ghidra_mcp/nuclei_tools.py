"""Nuclei bridge: the template-based vulnerability scanner as a first-class MCP surface.

Nuclei is a single Go binary with a template repository (~13k YAML files, cloned into
``%USERPROFILE%\\nuclei-templates``). This module resolves both, can fetch them on
demand, and wraps the whole CLI surface the model needs: scans against authorized
targets, template search/read/write for custom probes, workflows, and validation.

Output contract: scans run with ``-json -silent -duc -no-color``, every finding is a
JSON object (template id/name/severity, matched host+url, extracted data); the full
JSONL also lands in a report file so big results survive the chat render.

Authorization boundary: scanner output is a report, not permission. Lab and owned
targets only - same rule as the Metasploit tools.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

_INSTALL = Path(r"C:\Tools\nuclei")
_RELEASE_API = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_TEMPLATE_DIRS_KEY = "templates-directory"


def _find_nuclei() -> str | None:
    """PATH, then the standard install dir, then the winget/go layouts."""
    env = os.environ.get("GHIDRA_MCP_NUCLEI")
    if env and Path(env).is_file():
        return env
    found = shutil.which("nuclei")
    if found:
        return found
    for candidate in (
        _INSTALL / "nuclei.exe",
        Path(os.environ.get("USERPROFILE", "")) / "go" / "bin" / "nuclei.exe",
        Path(r"C:\nuclei") / "nuclei.exe",
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def _templates_dir() -> Path | None:
    """Where the template repo lives: config.yaml, env, or the default home dir."""
    env = os.environ.get("NUCLEI_TEMPLATES_DIR")
    if env and Path(env).is_dir():
        return Path(env)
    config = Path(os.environ.get("APPDATA", "")) / "nuclei" / "config.yaml"
    if config.is_file():
        text = config.read_text(encoding="utf-8", errors="replace")
        m = re.search(rf"^{_TEMPLATE_DIRS_KEY}:\s*(.+)$", text, re.M)
        if m:
            configured = Path(m.group(1).strip().strip('"'))
            if configured.is_dir():
                return configured
    home = Path(os.environ.get("USERPROFILE", "")) / "nuclei-templates"
    return home if home.is_dir() else None


def nuclei_status() -> dict[str, Any]:
    """Detect the scanner + template repo; version and template count included.

    Run first. When either is missing, ``nuclei_install`` fetches the GitHub release
    and ``nuclei_templates_update`` clones the template repo.
    """
    status: dict[str, Any] = {"binary": _find_nuclei()}
    status["version"] = None
    binary = status["binary"]
    if binary:
        try:
            result = subprocess.run(
                [binary, "-version", "-duc", "-no-color"],
                capture_output=True, text=True, errors="replace", timeout=60, stdin=subprocess.DEVNULL,
            )
            combined = _ANSI_RE.sub("", (result.stdout or "") + (result.stderr or ""))
            m = re.search(r"Nuclei Engine Version:\s*(\S+)", combined)
            status["version"] = m.group(1) if m else combined.splitlines()[-1][:40] if combined else None
        except (OSError, subprocess.TimeoutExpired) as exc:
            status["version_error"] = str(exc)[:120]
    templates = _templates_dir()
    status["templates_dir"] = str(templates) if templates else None
    status["templates_count"] = (
        sum(1 for _ in templates.rglob("*.yaml")) if templates else 0
    )
    if not binary:
        status["install_hint"] = "call nuclei_install - it fetches the latest GitHub release binary"
    elif not templates:
        status["install_hint"] = "call nuclei_templates_update - clones the template repo (~13k files)"
    return status


def _run(binary: str, args: list[str], *, timeout: float = 600.0) -> subprocess.CompletedProcess[str]:
    # stdin=DEVNULL: nuclei checks stdin at startup, and inside the MCP server the
    # inherited stdin IS the stdio protocol pipe - reading it would hang the tool
    # and steal protocol bytes. Never let a child touch it.
    return subprocess.run(
        [binary, *args], capture_output=True, text=True, errors="replace", timeout=timeout,
        stdin=subprocess.DEVNULL,
    )


def nuclei_install(*, dest: str | None = None) -> dict[str, Any]:
    """Fetch the latest nuclei release from GitHub and unpack it into C:\\Tools\\nuclei.

    One static Go binary (~30MB zip): latest tag + windows amd64 asset from the
    release API, extracted next to the templates. Run ``nuclei_templates_update``
    afterwards to pull the template repo.
    """
    if _find_nuclei():
        return {"already_installed": True, "binary": _find_nuclei()}
    try:
        with urllib.request.urlopen(_RELEASE_API, timeout=30) as response:
            release = json.loads(response.read())
        tag = release["tag_name"]
        version = tag.lstrip("v")
        asset = next(a for a in release["assets"] if a["name"] == f"nuclei_{version}_windows_amd64.zip")
    except Exception as exc:
        return {"error": f"could not read the GitHub release feed: {exc}"}
    destination = Path(dest) if dest else _INSTALL
    destination.mkdir(parents=True, exist_ok=True)
    zip_path = Path(tempfile.gettempdir()) / "nuclei_release.zip"
    try:
        with urllib.request.urlopen(asset["browser_download_url"], timeout=600) as download:
            zip_path.write_bytes(download.read())
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(destination)
    except Exception as exc:
        return {"error": f"download/extract failed: {exc}"}
    finally:
        try:
            zip_path.unlink()
        except OSError:
            pass
    binary = destination / "nuclei.exe"
    if not binary.is_file():
        return {"error": "unpacked archive has no nuclei.exe", "dest": str(destination)}
    return {"installed": True, "binary": str(binary), "version": tag}


def nuclei_templates_update(*, timeout: float = 900.0) -> dict[str, Any]:
    """Clone/update the nuclei-templates repo (~13k YAML files, needs ~250MB)."""
    binary = _find_nuclei()
    if binary is None:
        return {"error": "nuclei not installed - run nuclei_install first"}
    try:
        result = _run(binary, ["-update-templates", "-duc", "-no-color"], timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"template update exceeded {timeout}s"}
    templates = _templates_dir()
    return {
        "updated": bool(templates),
        "templates_dir": str(templates) if templates else None,
        "templates_count": sum(1 for _ in templates.rglob("*.yaml")) if templates else 0,
        "output": _ANSI_RE.sub("", result.stderr or "")[-1500:],
    }


def nuclei_self_update() -> dict[str, Any]:
    """Update the nuclei binary itself (-update replaces the running build)."""
    binary = _find_nuclei()
    if binary is None:
        return {"error": "nuclei not installed - run nuclei_install first"}
    try:
        result = _run(binary, ["-update", "-duc", "-no-color"], timeout=600)
    except subprocess.TimeoutExpired:
        return {"error": "self-update exceeded 600s"}
    status = nuclei_status()
    return {"version": status.get("version"), "output": _ANSI_RE.sub("", result.stderr or "")[-800:]}


# --------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------
def _target_args(targets: list[str] | str, temp_dir: Path) -> tuple[list[str], str | None]:
    if isinstance(targets, str):
        targets = [t.strip() for t in re.split(r"[\n,]", targets) if t.strip()]
    if not targets:
        raise ValueError("no targets given")
    if len(targets) > 8:
        list_file = temp_dir / f"nuclei_targets_{int(time.time())}.txt"
        list_file.write_text("\n".join(targets), encoding="utf-8")
        return ["-l", str(list_file)], str(list_file)
    return ["-u", ",".join(targets)], None


def _parse_findings(stdout: str) -> list[dict[str, Any]]:
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = raw.get("info") or {}
        findings.append({
            "template": (raw.get("template-id") or "").strip(),
            "name": (info.get("name") or "").strip(),
            "severity": (info.get("severity") or "").strip(),
            "tags": info.get("tags") or "",
            "matched": raw.get("matched-at") or raw.get("host") or "",
            "extracted": raw.get("extracted-results") or [],
            "matcher": (raw.get("matcher-name") or raw.get("matcher-status") or ""),
            "type": info.get("classification") or raw.get("type") or "",
            "ip": raw.get("ip"),
            "timestamp": raw.get("timestamp"),
        })
    return findings


def _stats_from_stderr(stderr: str) -> dict[str, Any]:
    stats: dict[str, Any] = {}
    clean = _ANSI_RE.sub("", stderr or "")
    m = re.search(r"(\d+)\s+requests? completed", clean)
    if m:
        stats["requests"] = int(m.group(1))
    m = re.search(r"(\d+)\s+matches? found", clean)
    if m:
        stats["matches"] = int(m.group(1))
    m = re.search(r"([\d.]+\w*)\s+duration", clean)
    if m:
        stats["duration"] = m.group(1)
    stats["errors"] = clean.count("[ERR]")
    return stats


def nuclei_scan(
    targets: list[str] | str,
    *,
    templates: str | list[str] | None = None,
    workflow: str | list[str] | None = None,
    severity: str | list[str] | None = None,
    tags: str | list[str] | None = None,
    exclude_tags: str | list[str] | None = None,
    template_ids: str | list[str] | None = None,
    authors: str | list[str] | None = None,
    exclude_templates: str | list[str] | None = None,
    exclude_hosts: str | list[str] | None = None,
    custom_headers: dict[str, str] | None = None,
    vars: dict[str, str] | None = None,
    env: dict[str, str] | None = None,
    dast: bool = False,
    rate_limit: int = 150,
    concurrency: int = 25,
    timeout: float = 10,
    retries: int = 1,
    max_host_error: int = 30,
    stop_at_first_match: bool = False,
    headless: bool = False,
    no_interactsh: bool = False,
    interactsh_server: str | None = None,
    resolvers: str | None = None,
    max_duration: str | None = None,
    timeout_s: float = 3600,
) -> dict[str, Any]:
    """Run a scan against authorized targets; returns parsed findings + report path.

    ``templates``: YAML files or dirs (-t); ``workflow``: -w chains; ``severity``
    "high,critical"; ``tags``/``template_ids``/``authors`` filter by metadata;
    ``dast`` enables fuzz-mode templates; ``custom_headers`` become -H pairs (auth'd
    hosts); ``vars`` fill template variables (key=value); ``env`` is added to the
    process environment for templates reading {{env(...)}}. Findings come back sorted
    by severity; the JSONL report file keeps everything when the render truncates.
    """
    binary = _find_nuclei()
    if binary is None:
        return {"error": "nuclei not installed - run nuclei_install first"}
    temp_dir = Path(tempfile.mkdtemp(prefix="nuclei_"))
    try:
        target_args, _ = _target_args(targets, temp_dir)
        command = [binary, *target_args, "-jsonl", "-silent", "-duc", "-no-color",
                   "-rl", str(rate_limit), "-c", str(concurrency), "-timeout", str(int(timeout)),
                   "-retries", str(retries), "-mhe", str(max_host_error)]
        for value in _as_list(templates):
            command += ["-t", value]
        for value in _as_list(workflow):
            command += ["-w", value]
        if severity:
            command += ["-severity", _csv(severity)]
        if tags:
            command += ["-tags", _csv(tags)]
        if exclude_tags:
            command += ["-etags", _csv(exclude_tags)]
        if template_ids:
            command += ["-id", _csv(template_ids)]
        if authors:
            command += ["-a", _csv(authors)]
        if exclude_templates:
            command += ["-et", _csv(exclude_templates)]
        if exclude_hosts:
            command += ["-eh", _csv(exclude_hosts)]
        if dast:
            command.append("-dast")
        if stop_at_first_match:
            command.append("-spm")
        if headless:
            command.append("-headless")
        if no_interactsh:
            command.append("-no-interactsh")
        if interactsh_server:
            command += ["-interactsh-server", interactsh_server]
        if resolvers:
            command += ["-r", resolvers]
        for name, value in (custom_headers or {}).items():
            command += ["-H", f"{name}: {value}"]
        for name, value in (vars or {}).items():
            command += ["-var", f"{name}={value}"]
        if max_duration:
            command += ["-mt", max_duration]
        # the report must outlive the scan: persistent dir, not the cleaned tempdir
        reports_dir = Path(tempfile.gettempdir()) / "ghidra-mcp" / "nuclei"
        reports_dir.mkdir(parents=True, exist_ok=True)
        report = reports_dir / f"scan_{int(time.time())}.jsonl"
        command += ["-jle", str(report)]
        started = time.time()
        run_env = {**os.environ, **(env or {})}
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, errors="replace",
                timeout=timeout_s, env=run_env, stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return {"error": f"scan exceeded {timeout_s}s (pass timeout_s or narrow templates)",
                    "targets": targets}
        findings = _parse_findings(result.stdout)
        findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f["severity"], 5))
        loaded = re.search(r"(\d+) templates? loaded", _ANSI_RE.sub("", result.stderr or ""))
        return {
            "targets": targets,
            "findings_total": len(findings),
            "findings": findings[:80],
            "truncated": len(findings) > 80,
            "stats": _stats_from_stderr(result.stderr),
            "templates_loaded": int(loaded.group(1)) if loaded else None,
            "report_file": str(report) if report.exists() else None,
            "duration_s": round(time.time() - started, 1),
            "exit_code": result.returncode,
            "stderr_tail": _ANSI_RE.sub("", result.stderr or "")[-1500:],
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _as_list(value: str | list[str] | None) -> list[str]:
    if not value:
        return []
    return [value] if isinstance(value, str) else list(value)


def _csv(value: str | list[str]) -> str:
    return value if isinstance(value, str) else ",".join(value)


# --------------------------------------------------------------------------
# templates: list, read, write, validate, workflows
# --------------------------------------------------------------------------
_ID_RE = re.compile(r"^id:\s*(\S+)", re.M)
_NAME_RE = re.compile(r"^\s+name:\s*(.+)$", re.M)
_SEVERITY_RE = re.compile(r"^\s+severity:\s*(\w+)", re.M)
_TAGS_RE = re.compile(r"^\s+tags:\s*(.+)$", re.M)


def _template_meta(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    id_match = _ID_RE.search(text)
    name_match = _NAME_RE.search(text)
    severity_match = _SEVERITY_RE.search(text)
    tags_match = _TAGS_RE.search(text)
    return {
        "path": str(path),
        "id": id_match.group(1) if id_match else "",
        "name": name_match.group(1).strip().strip('"') if name_match else "",
        "severity": severity_match.group(1) if severity_match else "",
        "tags": tags_match.group(1).strip() if tags_match else "",
    }


def nuclei_templates_list(
    *, tags: str | None = None, severity: str | None = None, protocol: str | None = None,
    query: str | None = None, limit: int = 100,
) -> dict[str, Any]:
    """Search the local template repo by tags/severity/protocol/free text.

    Walks the YAML headers directly - the same metadata nuclei filters on with
    -tags/-severity, so the results are ready to paste into nuclei_scan.
    """
    templates = _templates_dir()
    if templates is None:
        return {"error": "template repo not found - run nuclei_templates_update first"}
    if protocol and not (templates / protocol).is_dir():
        return {"error": f"no {protocol} templates dir", "available": sorted(p.name for p in templates.iterdir() if p.is_dir())}
    roots = [templates / protocol] if protocol else [templates]
    matches: list[dict[str, Any]] = []
    for root in roots:
        for path in root.rglob("*.yaml"):
            if path.name.endswith("-patch.yaml"):  # helpers that only exist for matchers
                continue
            meta = _template_meta(path)
            if severity and severity.lower() not in meta["severity"].lower():
                continue
            if tags and not any(tag.strip().lower() in meta["tags"].lower() for tag in tags.split(",")):
                continue
            if query and query.lower() not in (meta["name"] + " " + meta["id"] + " " + meta["tags"] + " " + str(path)).lower():
                continue
            matches.append(meta)
            if len(matches) >= limit * 4:
                break
    return {"count": len(matches), "returned": min(len(matches), limit), "templates": matches[:limit]}


def nuclei_templates_info(path: str) -> dict[str, Any]:
    """Read one template: the YAML source, so you can tune or copy it into a custom."""
    target = Path(path)
    if not target.is_absolute():
        templates = _templates_dir()
        if templates is None:
            return {"error": "template repo not found - run nuclei_templates_update first"}
        target = templates / path
    if not target.is_file():
        return {"error": f"no such template: {target}"}
    text = target.read_text(encoding="utf-8", errors="replace")
    return {"path": str(target), "size": len(text), "yaml": text[:12000]}


def _safe_custom_path(path: str) -> Path:
    """Constrain writes to the custom template dir: no traversal, no escaping."""
    templates = _templates_dir()
    if templates is None:
        raise ValueError("template repo not found - run nuclei_templates_update first")
    base = templates / "ghidra-mcp-custom"
    cleaned = path.strip().strip("/")
    if not cleaned or ".." in Path(cleaned).parts or ":" in cleaned:
        raise ValueError("path must be relative, no '..' or drive letters")
    if not cleaned.endswith(".yaml"):
        cleaned += ".yaml"
    target = (base / cleaned).resolve()
    if base.resolve() not in target.parents and base.resolve() != target.parent:
        raise ValueError("path escapes the custom templates dir")
    return target


def nuclei_templates_write(path: str, content: str, *, validate: bool = True) -> dict[str, Any]:
    """Author a custom template under <repo>/ghidra-mcp-custom/ (the AI's own probes).

    For the checks this toolkit needs that the repo lacks: your mock license server
    answers, the target's known endpoints, a token extraction to feed the next scan.
    With validate=True the template is syntax-checked by nuclei -validate before
    returning. Path is relative to the custom dir; traversal is refused.
    """
    try:
        target = _safe_custom_path(path)
    except ValueError as exc:
        return {"error": str(exc)}
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    result: dict[str, Any] = {"written": str(target), "size": len(content)}
    if validate:
        validation = nuclei_validate(str(target))
        result["validation"] = validation
    return result


def nuclei_validate(path: str | None = None) -> dict[str, Any]:
    """Syntax-check templates (-validate): one file or a whole dir.

    Error detail comes back with the verdict: ``[ERR]`` lines name the template and
    the reason, so a failed write is fixable from the tool output alone. Note nuclei
    requires ``author`` under ``info:``.
    """
    binary = _find_nuclei()
    if binary is None:
        return {"error": "nuclei not installed - run nuclei_install first"}
    command = ["-validate", "-duc", "-no-color"]
    if path:
        command += ["-t", path]
    try:
        result = _run(binary, command, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "validation exceeded 120s"}
    clean = _ANSI_RE.sub("", (result.stdout or "") + "\n" + (result.stderr or ""))
    lines = clean.splitlines()
    errors: list[str] = []
    for index, line in enumerate(lines):
        if "[ERR]" in line or "Error occurred" in line:
            # wrapped causes continue on the next lines; take a short window
            errors.append(" ".join(l.strip() for l in lines[index : index + 2]))
    return {"valid": result.returncode == 0, "code": result.returncode, "errors": errors[:20],
            "output": clean[-600:]}


def nuclei_workflows_list(*, limit: int = 80) -> dict[str, Any]:
    """List workflow templates (multi-stage chains: recon -> enrich -> check)."""
    templates = _templates_dir()
    if templates is None:
        return {"error": "template repo not found - run nuclei_templates_update first"}
    workflows_dir = templates / "workflows"
    if not workflows_dir.is_dir():
        return {"error": "no workflows dir in the template repo"}
    items = []
    for path in sorted(workflows_dir.rglob("*.yaml")):
        items.append({"path": str(path.relative_to(templates)), "name": path.stem})
        if len(items) >= limit:
            break
    return {"count": len(items), "workflows": items}
