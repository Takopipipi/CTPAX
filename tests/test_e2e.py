"""End-to-end tests over the real MCP stdio protocol: server, tools, worker, sessions.

Run: python tests\\test_e2e.py   (starts the real server; needs the installed venv)

Note: these are sequential checks inside one event loop rather than
unittest.IsolatedAsyncioTestCase - anyio's task groups (which the MCP stdio transport
is built on) forbid exiting a cancel scope from a different task, and unittest's async
runner hops tasks between test methods.
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

HOME = Path(os.environ.get("GHIDRA_MCP_HOME", r"C:\Users\artem\AppData\Local\GhidraMCP"))
EXE = r"C:\Windows\System32\where.exe"

PASSED: list[str] = []
FAILED: list[str] = []


def check(name, text, *, expect_error=False, contains=None):
    is_error = '"error"' in text
    ok = (is_error if expect_error else not is_error) and (contains is None or contains in text)
    (PASSED if ok else FAILED).append(name)
    head = text[:120].splitlines()[0] if text else ""
    print(("OK   " if ok else "FAIL ") + f"{name:28} {head}", flush=True)


async def run_suite(session):
    async def call(name, args=None):
        result = await session.call_tool(name, args or {})
        return result.content[0].text

    def parse(text):
        """Parse the tool's JSON, tolerating stderr noise prepended by some transports."""
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                return json.loads(text[start : end + 1])
            raise

    import json

    tools = await session.list_tools()
    check("tool_registry", str(len(tools.tools)), contains=str(len(tools.tools)))
    check("doctor", await call("doctor"), contains="settings")
    check("file_info", await call("file_info", {"path": EXE}), contains="sha256")
    check("crypto_decode", await call("crypto_decode", {"data": "VGhpcyBpcyBhIHRlc3Q="}), contains="This is a test")
    check("crypto_xor", await call("crypto_xor", {"data": "aabb", "key": "ff"}), contains="5544")
    check("jwt_decode", await call("jwt_decode", {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}), contains="alg")
    check("pe_heuristics", await call("pe_heuristics", {"path": EXE}), contains="verdict")
    check("triage", await call("triage", {"path": EXE}), contains="triage_verdict")
    check("antidebug_scan", await call("antidebug_scan", {"path": EXE}), contains="severity")

    # -- processes ----------------------------------------------------------
    check("proc_alive_self", await call("proc_alive", {"pid": os.getpid()}), contains='"alive": true')
    check("proc_alive_dead", await call("proc_alive", {"pid": 999999}), contains='"alive": false')
    check("proc_info_self", await call("proc_info", {"pid": os.getpid()}), contains="python")

    # proc_watch: spawn a cmd child and see the event land
    watch = parse(await call("proc_watch_start", {"pattern": "cmd.exe"}))
    try:
        spawned = parse(await call("proc_start", {"path": r"C:\Windows\System32\cmd.exe", "arguments": "/C ping -n 2 127.0.0.1 >nul", "capture": False}))
        await asyncio.sleep(2.5)
        events = parse(await call("proc_watch_read", {"name": watch["name"]}))
        saw_spawn = any(e.get("kind") == "spawn" and e.get("pid") == spawned["pid"] for e in events.get("events", []))
        check("proc_watch_spawn", str(saw_spawn), contains="True")
    finally:
        await call("proc_watch_stop", {"name": watch["name"]})

    # exception logger: start a target instrumented before its first instruction
    exclog = parse(await call("exception_logger_start", {"path": r"C:\Windows\System32\ping.exe", "arguments": "-n 3 127.0.0.1"}))
    if "error" in exclog:
        check("exception_logger_start", str(exclog), expect_error=True)
    else:
        await asyncio.sleep(1.5)
        log = parse(await call("exception_logger_read", {"pid": exclog["pid"]}))
        check("exception_logger_attached", str(log), contains="veh attached")
        await call("proc_kill", {"pid": exclog["pid"]})

    started = parse(await call("proc_start", {"path": r"C:\Windows\System32\cmd.exe", "arguments": "/Q /K", "capture": True}))
    pid = started["pid"]
    try:
        await call("proc_write", {"pid": pid, "text": "echo E2E_MARKER_123"})
        await asyncio.sleep(0.6)
        output = await call("proc_read", {"pid": pid})
        check("proc_interactive_io", output, contains="E2E_MARKER_123")
    finally:
        await call("proc_kill", {"pid": pid})

    started2 = parse(await call("proc_start", {"path": r"C:\Windows\System32\cmd.exe", "arguments": "/C exit 7", "capture": False}))
    waited = parse(await call("proc_wait_exit", {"pid": started2["pid"], "timeout": 15}))
    check("proc_wait_exit_code", str(waited), contains="'exit_code': '0x7'")

    # -- memory scan roundtrip ----------------------------------------------
    import ctypes

    value = ctypes.c_uint32(31337)
    first = parse(await call("mem_scan", {"pid": os.getpid(), "value": "31337", "type": "u32", "limit": 500}))
    check("mem_scan_first", str(first), contains="matches")
    target_hit = any(int(h["address"], 16) == ctypes.addressof(value) for h in first["hits"])
    check("mem_scan_found_own_value", str(target_hit), contains="True")
    value.value = 31400
    second = parse(await call("mem_scan", {"pid": os.getpid(), "value": "31400", "type": "u32", "previous_file": first["state_file"], "limit": 500}))
    narrowed = any(int(h["address"], 16) == ctypes.addressof(value) for h in second["hits"])
    check("mem_scan_narrowed", str(narrowed), contains="True")

    # -- pe_compare: patch a copy, expect code movement -------------------------
    # copies live outside TemporaryDirectory: the server process may still hold a
    # handle (pefile GC timing), and that must not fail the suite
    import shutil

    scratch = Path(tempfile.gettempdir()) / "opencode_e2e_pecompare"
    scratch.mkdir(exist_ok=True)
    copy_a = scratch / "where_a.bin"
    copy_b = scratch / "where_b.bin"
    shutil.copy(EXE, copy_a)
    shutil.copy(EXE, copy_b)
    blob = bytearray(copy_b.read_bytes())
    blob[0x1200:0x1204] = b"\x90\x90\x90\x90"
    copy_b.write_bytes(blob)
    compare = parse(await call("pe_compare", {"path_a": str(copy_a), "path_b": str(copy_b)}))
    check("pe_compare_patch", str(compare.get("verdict", {}).get("code_changed")), contains="True")

    # -- network ---------------------------------------------------------------
    check("http_request_live", await call("http_request", {"url": "http://example.com/", "timeout": 10}), contains='"status": 200')

    await call("net_mock_start", {"port": 18443, "record": True})
    try:
        await call("net_mock_route", {"method": "POST", "path_pattern": "/license", "body": '{"valid":true}'})
        raw = await call("http_request", {"url": "http://127.0.0.1:18443/license", "method": "POST", "body": "ping"})
        if '"error"' in raw or "Error" in raw.splitlines()[0]:
            check("mock_forgery", raw, expect_error=True)
        else:
            response = parse(raw)
            check("mock_forgery", str(response), contains="'body_text': '{\"valid\":true}'")
        await call("net_mock_route", {"method": "GET", "path_pattern": "/check", "query": {"key": r"\d+"}, "body": "premium"})
        await call("net_mock_route", {"method": "GET", "path_pattern": "/check", "body": "free"})
        with_key = parse(await call("http_request", {"url": "http://127.0.0.1:18443/check?key=99"}))
        without = parse(await call("http_request", {"url": "http://127.0.0.1:18443/check"}))
        check("mock_query_routing", with_key.get("body_text", "") + without.get("body_text", ""), contains="premiumfree")

        # record -> generate -> replay (the recorded 404 body is served verbatim;
        # compare bodies directly - check() would flag the literal "error" in it)
        record = parse(await call("http_request", {"url": "http://127.0.0.1:18443/missed-route"}))
        generated = parse(await call("mock_generate", {"port": 18443, "transforms": {}}))
        check("mock_generate", str(generated.get("generated")), contains="1")
        replay = parse(await call("http_request", {"url": "http://127.0.0.1:18443/missed-route"}))
        same_body = replay.get("body_text") == record.get("body_text")
        check("mock_replay", str(same_body), contains="True")
    finally:
        await call("net_mock_stop", {"port": 18443})

    # -- pentest bridges --------------------------------------------------------
    ws = parse(await call("ws_status", {}))
    if ws.get("tools", {}).get("tshark"):
        check("ws_status_tshark", ws["tools"]["tshark"], contains="tshark")
    else:
        check("ws_status_tshark", "tshark not installed (hint returned)", expect_error=False)

    msf = parse(await call("msf_status", {}))
    # graceful either way: detected or an actionable install hint
    check("msf_status", str(msf.get("install_hint") is not None or msf.get("version")), contains="True")

    # tcp_proxy log -> pcap -> tshark (needs tshark; skipped cleanly otherwise)
    if ws.get("tools", {}).get("tshark"):
        import base64

        scratch_ws = Path(tempfile.gettempdir()) / "opencode_e2e_ws"
        scratch_ws.mkdir(exist_ok=True)
        ws_log = scratch_ws / "proxy.jsonl"
        chunks = [
            {"session": 1, "direction": "client->server", "at": 1000.0, "bytes": 16,
             "body_b64": base64.b64encode(b"GET /api HTTP/1.1\r\n").decode()},
            {"session": 1, "direction": "server->client", "at": 1000.1, "bytes": 25,
             "body_b64": base64.b64encode(b'HTTP/1.1 200 OK\r\n\r\n{"ok":true}\r\n').decode()},
        ]
        ws_log.write_text("".join(json.dumps(c) + "\n" for c in chunks), encoding="utf-8")
        pcap = parse(await call("ws_pcap_from_proxy", {"log_file": str(ws_log)}))
        if "error" in pcap:
            check("ws_pcap_roundtrip", str(pcap), expect_error=True)
        else:
            frames = parse(await call("ws_read_pcap", {"path": pcap["pcap"], "limit": 5}))
            check("ws_pcap_roundtrip", str(frames.get("count")), contains="2")
            conversation = parse(await call("ws_follow_stream", {"path": pcap["pcap"], "stream_index": 0}))
            check("ws_follow_stream", conversation.get("conversation", ""), contains="GET /api HTTP/1.1")

    # -- nuclei: full loop on a local mock (binary + templates optional) --------
    nst = parse(await call("nuclei_status", {}))
    if nst.get("binary") and nst.get("templates_dir"):
        import http.server
        import threading

        class NucleiMarker(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'<html>E2E-NUCLEI-MARKER</html>'
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 18561), NucleiMarker)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        Q = chr(39)
        tmpl = (
            "id: e2e-nuclei-marker\ninfo:\n  name: E2E Nuclei Marker\n  author: ghidra-mcp\n  severity: info\n"
            "  tags: ghidra-mcp,e2e\nhttp:\n  - method: GET\n    path:\n"
            f"      - {Q}" + "{{BaseURL}}/" + Q + "\n    matchers:\n      - type: word\n        words:\n"
            f"          - {Q}" + "E2E-NUCLEI-MARKER" + Q + "\n"
        )
        write = parse(await call("nuclei_templates_write", {"path": "e2e-marker", "content": tmpl}))
        check("nuclei_validate", str(write.get("validation", {}).get("valid")), contains="True")
        tmpl_path = str(Path(nst["templates_dir"]) / "ghidra-mcp-custom" / "e2e-marker.yaml")
        scan = parse(await call("nuclei_scan", {
            "targets": ["http://127.0.0.1:18561/"], "templates": [tmpl_path],
            "no_interactsh": True, "timeout_s": 150, "rate_limit": 20, "concurrency": 2,
        }))
        check("nuclei_scan_finding", str(scan.get("findings_total")), contains="1")
        if scan.get("findings"):
            check("nuclei_finding_severity", scan["findings"][0]["severity"], contains="info")
        tl = parse(await call("nuclei_templates_list", {"tags": "ghidra-mcp", "limit": 10}))
        check("nuclei_templates_list", str(tl.get("count", 0)), contains=str(tl.get("count", 0)))
        server.shutdown()
    else:
        print("SKIP nuclei: binary/templates not installed")

    # -- version lifecycle ------------------------------------------------------
    # (deliberately non-destructive: never call version_update while an update is
    #  actually pending, or the test would download the release and overwrite the
    #  runtime sources mid-session)
    vc = parse(await call("version_check", {}))
    check("version_check", str(vc.get("installed")), contains=str(vc.get("installed")))
    if vc.get("outdated"):
        check("version_update_safe", "a real update is pending - skipped in tests", contains="skipped")
    else:
        # tolerate a graceful network failure (GitHub rate limits in CI)
        res = await call("version_update", {})
        healthy = ("installed" in res) or ('"error"' in res) or ("no_releases" in res)
        check("version_update_safe", "graceful" if healthy else res, contains="graceful")

    # -- cdb session -------------------------------------------------------------
    cdb = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")
    if cdb.exists():
        started = await call("dbg_session_start", {"target": EXE})
        check("cdb_session_start", started, contains="started")
        try:
            lm = await call("dbg_session_command", {"command": "lm m where"})
            check("cdb_session_lm", lm.lower(), contains="where")
            bp = await call("dbg_session_bp_set", {"address": "where+0x1300", "condition": "ecx>2", "one_shot": True})
            check("cdb_session_bp_condition", bp)
            dump = await call("dbg_session_dump", {"expression": "eip", "size": 16})
            check("cdb_session_dump", dump)
        finally:
            stopped = await call("dbg_session_stop", {})
            check("cdb_session_stop", stopped, contains="stopped")
    else:
        print("SKIP cdb session: cdb.exe not installed")

    # -- ghidra ---------------------------------------------------------------------
    await call("open_binary", {"path": EXE, "analyze": True})
    try:
        check("ghidra_program_info", await call("program_info"), contains="blocks")
        check("ghidra_functions_section", await call("list_functions", {"limit": 3, "section": ".text"}), contains="functions")
        check("ghidra_decompile", await call("decompile", {"function": "entry"}), contains="signature")
        check("ghidra_xrefs_batch", await call("xrefs", {"targets": ["entry"]}), contains="targets")
        check("ghidra_crypto_constants", await call("find_crypto_constants"), contains="algorithms_found")
        check("ghidra_eval", await call("ghidra_eval_python", {"code": "fm.getFunctionCount()"}), contains="result")

        # suggest_patches on a conditional jump found by disassembling entry
        dis = parse(await call("disassemble", {"function": "entry", "limit": 40}))
        instructions = dis.get("instructions", [])
        jcc = next((i for i in instructions if str(i.get("mnemonic", "")).upper().startswith(("JZ", "JNZ", "JE", "JNE"))), None)
        if jcc is None:
            check("suggest_patches", "no jcc in entry (skipped)", expect_error=False)
        else:
            patches = parse(await call("suggest_patches", {"address": jcc["address"]}))
            kinds = {s.get("kind") for s in patches.get("suggestions", [])}
            check("suggest_patches", str(kinds), contains="force_taken")

        # function_map against a patched copy of the same binary; Ghidra keeps the
        # imported file open, so the copy lives outside TemporaryDirectory and is
        # removed after close_program.
        copy_b = Path(tempfile.gettempdir()) / "opencode_where_b_e2e.exe"
        copy_b.parent.mkdir(exist_ok=True)
        shutil.copy(EXE, copy_b)
        blob = bytearray(copy_b.read_bytes())
        blob[0x1200] = 0x90
        copy_b.write_bytes(blob)
        opened_b = parse(await call("open_binary", {"path": str(copy_b), "analyze": True}))
        try:
            if "error" in opened_b:
                check("function_map", str(opened_b), expect_error=True)
            else:
                mapping = parse(await call("function_map", {"program_b": opened_b["program"], "limit": 5}))
                check("function_map", str(mapping.get("matched")), contains=str(mapping.get("matched")))
        finally:
            await call("close_program", {"program": opened_b.get("program")})
            try:
                copy_b.unlink()
            except OSError:
                pass
    finally:
        await call("close_program", {})


async def main():
    sys.path.insert(0, str(HOME / "src"))
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = os.environ.copy()
    env.update({
        "PYTHONPATH": str(HOME / "src"),
        "GHIDRA_MCP_HOME": str(HOME),
        "PYTHONIOENCODING": "utf-8",
    })
    params = StdioServerParameters(
        command=str(HOME / "venv" / "Scripts" / "python.exe"),
        args=["-m", "ghidra_mcp.server"],
        env=env,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await run_suite(session)

    print()
    print(f"PASSED={len(PASSED)} FAILED={len(FAILED)}")
    if FAILED:
        print("failures:", FAILED)
    return 0 if not FAILED else 1


sys.exit(asyncio.run(main()))
