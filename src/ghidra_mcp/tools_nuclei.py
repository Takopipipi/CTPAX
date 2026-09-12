"""MCP tools for Nuclei: vulnerability scanning, template search/authoring, workflows."""

from __future__ import annotations

from ghidra_mcp import nuclei_tools
from ghidra_mcp.runtime import fail, mcp, render


@mcp.tool()
def nuclei_status() -> str:
    """Detect Nuclei: binary location, version, template repo size.

    Run first. Missing pieces come with exact next calls: nuclei_install for the
    binary, nuclei_templates_update for the ~13k template repo.
    """
    try:
        return render(nuclei_tools.nuclei_status())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def nuclei_install(dest: str | None = None) -> str:
    """Fetch the latest nuclei release from GitHub into C:\\Tools\\nuclei.

    Resolves the latest tag + the windows amd64 asset and unpacks the single Go
    binary. Then run nuclei_templates_update to clone the template repo.
    """
    try:
        return render(nuclei_tools.nuclei_install(dest=dest))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def nuclei_templates_update() -> str:
    """Clone/update the nuclei-templates repo (~13k YAML files, ~250MB)."""
    try:
        return render(nuclei_tools.nuclei_templates_update())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def nuclei_self_update() -> str:
    """Update the nuclei binary itself to the latest release."""
    try:
        return render(nuclei_tools.nuclei_self_update())
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def nuclei_scan(
    targets: list[str],
    templates: list[str] | None = None,
    workflow: list[str] | None = None,
    severity: str | None = None,
    tags: str | None = None,
    exclude_tags: str | None = None,
    template_ids: str | None = None,
    authors: str | None = None,
    exclude_templates: str | None = None,
    exclude_hosts: str | None = None,
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
) -> str:
    """Run a Nuclei scan against authorized targets; returns parsed findings + report.

    Narrow with ``templates`` (files/dirs), ``severity`` ("high,critical"), ``tags``,
    ``template_ids``, or ``workflow`` chains. Auth'd hosts: ``custom_headers`` (-H),
    template ``vars``; ``dast`` for fuzz-mode. Findings sorted by severity; the JSONL
    report file keeps everything when the chat render truncates. Lab/owned only.
    """
    try:
        return render(nuclei_tools.nuclei_scan(
            targets,
            templates=templates,
            workflow=workflow,
            severity=severity,
            tags=tags,
            exclude_tags=exclude_tags,
            template_ids=template_ids,
            authors=authors,
            exclude_templates=exclude_templates,
            exclude_hosts=exclude_hosts,
            custom_headers=custom_headers,
            vars=vars,
            env=env,
            dast=dast,
            rate_limit=rate_limit,
            concurrency=concurrency,
            timeout=timeout,
            retries=retries,
            max_host_error=max_host_error,
            stop_at_first_match=stop_at_first_match,
            headless=headless,
            no_interactsh=no_interactsh,
            interactsh_server=interactsh_server,
            resolvers=resolvers,
            max_duration=max_duration,
            timeout_s=timeout_s,
        ))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def nuclei_templates_list(
    tags: str | None = None,
    severity: str | None = None,
    protocol: str | None = None,
    query: str | None = None,
    limit: int = 100,
) -> str:
    """Search the local template repo by tags/severity/protocol/free text.

    Reads YAML headers - same metadata nuclei filters on, so ``severity``/``tags``
    results paste straight into nuclei_scan. protocol: http, dns, workflows...
    """
    try:
        return render(nuclei_tools.nuclei_templates_list(
            tags=tags, severity=severity, protocol=protocol, query=query, limit=limit,
        ))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def nuclei_templates_info(path: str) -> str:
    """Read one template's YAML source (tune it, or copy into a custom probe)."""
    try:
        return render(nuclei_tools.nuclei_templates_info(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def nuclei_templates_write(path: str, content: str, validate: bool = True) -> str:
    """Author a custom template under <repo>/ghidra-mcp-custom/ and validate it.

    For checks the public repo lacks: your mock servers' answers, known private
    endpoints, a token extraction to chain into the next scan. validate=True runs
    nuclei -validate on the spot; relative path, traversal refused.
    """
    try:
        return render(nuclei_tools.nuclei_templates_write(path, content, validate=validate))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def nuclei_validate(path: str | None = None) -> str:
    """Syntax-check templates (nuclei -validate): one file, a dir, or the whole repo."""
    try:
        return render(nuclei_tools.nuclei_validate(path))
    except Exception as exc:
        return fail(exc)


@mcp.tool()
def nuclei_workflows_list(limit: int = 80) -> str:
    """List workflow templates: multi-stage chains (recon -> enrich -> checks)."""
    try:
        return render(nuclei_tools.nuclei_workflows_list(limit=limit))
    except Exception as exc:
        return fail(exc)
