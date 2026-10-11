"""Unit tests for the pure-logic modules: crypto, notebook, pe_tools, lang_recover.

Run: python tests\\test_unit.py   (no pytest needed; prints PASS/FAIL and exits nonzero on failure)
"""

import json
import os
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghidra_mcp import crypto, lang_recover, net_forge, net_mock, pe_tools, static_analysis  # noqa: E402
from ghidra_mcp.crypto_jwt import jwt_decode, jwt_forge  # noqa: E402
from ghidra_mcp.notebook import Notebook  # noqa: E402


class TestCrypto(unittest.TestCase):
    def test_xor_roundtrip(self):
        data = b"hello world"
        key = b"K"
        encrypted = crypto.xor(data, key)
        self.assertEqual(crypto.xor(encrypted, key), data)

    def test_xor_bruteforce_single_byte_finds_key(self):
        key = 0x5A
        payload = bytes(b ^ key for b in b"This program needs a license key. " * 3)
        result = crypto.xor_bruteforce(payload, max_key_length=1)
        self.assertTrue(result["candidates"], "no candidates returned")
        self.assertEqual(result["best"]["key_hex"], "5a")

    def test_base64_decode(self):
        result = crypto.decode_common(b"VGhpcyBpcyBhIHRlc3Q=")
        self.assertEqual(result["best"]["codec"], "base64")
        self.assertIn("This is a test", result["best"]["preview"])

    def test_score_plaintext_ranks_english(self):
        good = crypto.score_plaintext(b"The quick brown fox jumps over the lazy dog")
        bad = crypto.score_plaintext(bytes(range(256)))
        self.assertGreater(good["score"], bad["score"])

    def test_aes_roundtrip_cbc(self):
        key = b"0123456789abcdef"
        iv = b"fedcba9876543210"
        plaintext = b"secret payload !"  # exactly 16 bytes: CBC needs block-aligned input
        encrypted = crypto.aes(plaintext, key=key, iv=iv, mode="cbc", decrypt=False)
        decrypted = crypto.aes(bytes.fromhex(encrypted["hex"]), key=key, iv=iv, mode="cbc", decrypt=True)
        self.assertEqual(bytes.fromhex(decrypted["hex"]), plaintext)

    def test_caesar_solver(self):
        result = crypto.classic_cipher("Wklv lv d vhfuhw", cipher="caesar")
        best = result["best"]
        self.assertEqual(best["text"], "This is a secret")

    def test_hash_known_values(self):
        result = crypto.hash_data(b"hello")
        self.assertEqual(result["md5"], "5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(result["sha256"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")


class TestJwt(unittest.TestCase):
    def test_decode_roundtrip(self):
        forged = jwt_forge({"sub": "12345", "role": "admin"}, "HS256", key="k3y")
        decoded = jwt_decode(forged["token"])
        self.assertEqual(decoded["payload"]["role"], "admin")
        self.assertEqual(decoded["alg"], "HS256")

    def test_none_attack(self):
        result = jwt_forge({"role": "admin"}, "none")
        self.assertTrue(result["token"].endswith("."))
        decoded = jwt_decode(result["token"])
        self.assertEqual(decoded["alg"], "none")

    def test_weak_secret_detection(self):
        result = jwt_forge({"sub": "x"}, "HS256", key="letmein", secret_candidates=["abc", "letmein"])
        self.assertEqual(result.get("weak_secret_found"), "letmein")


class TestNotebook(unittest.TestCase):
    def test_add_search_regex_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            book = Notebook(Path(tmp) / "notes.json")
            book.add("deadbeef" * 4, "AES key derived from md5(password)", tags=["crypto"], label="finding")
            book.add("cafebabe" * 4, "license check at 0x140001000", tags=["license"], label="finding")
            plain = book.search("license")
            self.assertEqual(plain["count"], 1)
            pattern = book.search(r"AES|md5", regex=True)
            self.assertEqual(pattern["count"], 1)
            export_path = book.export(Path(tmp) / "out.md")
            text = export_path.read_text(encoding="utf-8")
            self.assertIn("AES key derived", text)
            self.assertIn("license check", text)

    def test_remove(self):
        with tempfile.TemporaryDirectory() as tmp:
            book = Notebook(Path(tmp) / "notes.json")
            added = book.add("ab" * 32, "note to delete", label="t")
            self.assertTrue(book.remove("ab" * 32, added["id"]))
            self.assertFalse(book.remove("ab" * 32, added["id"]))


class TestPeTools(unittest.TestCase):
    EXE = Path(r"C:\Windows\System32\where.exe")

    def test_headers(self):
        if not self.EXE.exists():
            self.skipTest("windows-only")
        headers = pe_tools.pe_headers(self.EXE)
        self.assertEqual(headers["machine"], "x64")
        self.assertIn("entry", headers)
        self.assertTrue(headers["entry"]["rva"].startswith("0x"))

    def test_sections_and_imports(self):
        if not self.EXE.exists():
            self.skipTest("windows-only")
        sections = pe_tools.pe_sections(self.EXE)
        self.assertGreater(sections["count"], 0)
        names = {s["name"] for s in sections["sections"]}
        self.assertIn(".text", names)
        imports = pe_tools.pe_imports(self.EXE)
        self.assertGreater(imports["function_count"], 0)

    def test_heuristics_benign_system_binary(self):
        if not self.EXE.exists():
            self.skipTest("windows-only")
        report = pe_tools.pe_heuristics(self.EXE)
        self.assertIn(report["verdict"], ("benign", "suspicious"))
        self.assertIsInstance(report["score"], int)

    def test_overlay_and_relocs(self):
        if not self.EXE.exists():
            self.skipTest("windows-only")
        relocs = pe_tools.pe_relocations(self.EXE)
        self.assertTrue(relocs["present"])
        self.assertGreater(relocs["entry_count"], 0)
        overlay = pe_tools.pe_overlay(self.EXE)
        self.assertIn("present", overlay)


class TestNetForge(unittest.TestCase):
    def test_url_parse_rejects_bad_scheme(self):
        result = net_forge.http_request("ftp://example.com/")
        self.assertIn("error", result)

    def test_cookie_jar_roundtrip(self):
        jar = net_forge._COOKIE_JARS
        jar["test_session"] = {"sid": "abc123"}
        merged = net_forge._merge_cookies({}, "test_session")
        self.assertEqual(merged["Cookie"], "sid=abc123")
        saved = net_forge._store_cookies({"Set-Cookie": "token=xyz; Path=/"}, "test_session")
        self.assertEqual(saved, ["token"])
        self.assertEqual(jar["test_session"]["token"], "xyz")
        del jar["test_session"]

    def test_body_encodings(self):
        self.assertEqual(net_forge._coerce_body("414243", "hex"), b"ABC")
        self.assertEqual(net_forge._coerce_body("QUJD", "base64"), b"ABC")
        self.assertEqual(net_forge._coerce_body("hi", "text"), b"hi")


class TestNetMock(unittest.TestCase):
    def test_route_query_matching(self):
        net_mock._ROUTES.clear()
        net_mock.mock_route("GET", "/check", query={"key": r"\d+"}, body="premium")
        net_mock.mock_route("GET", "/check", body="free")
        handler = net_mock._MockHandler
        import types

        fake = types.SimpleNamespace()
        self.assertEqual(handler._match(fake, "GET", "/check?key=42")["body"], "premium")
        self.assertEqual(handler._match(fake, "GET", "/check?key=abc")["body"], "free")
        self.assertEqual(handler._match(fake, "GET", "/check")["body"], "free")
        net_mock._ROUTES.clear()

    def test_route_replacement(self):
        net_mock._ROUTES.clear()
        net_mock.mock_route("POST", "/api", body="v1")
        result = net_mock.mock_route("POST", "/api", body="v2")
        self.assertTrue(result["replaced"])
        net_mock._ROUTES.clear()


class TestFilePatch(unittest.TestCase):
    def test_patch_single_occurrence(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "t.bin"
            marker = bytes.fromhex("AABBCCDD")
            data = marker + bytes(16) + marker
            target.write_bytes(data)
            # two occurrences: must refuse without disambiguation
            refused = static_analysis.patch_file(target, "AABBCCDD", "11223344")
            self.assertFalse(refused["patched"])
            # first occurrence
            ok = static_analysis.patch_file(target, "AABBCCDD", "11223344", occurrence=1)
            self.assertTrue(ok["patched"])
            self.assertEqual(ok["patch_count"], 1)
            patched = target.read_bytes()
            self.assertEqual(patched[:4], bytes.fromhex("11223344"))
            self.assertEqual(patched[-4:], marker)  # second untouched
            # replace_all patches the remaining one
            ok_all = static_analysis.patch_file(target, "AABBCCDD", "55667788", replace_all=True)
            self.assertEqual(ok_all["patch_count"], 1)
            self.assertTrue(Path(str(target) + ".bak").exists())

    def test_length_mismatch_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "t.bin"
            target.write_bytes(b"1234")
            with self.assertRaises(ValueError):
                static_analysis.patch_file(target, "4142", "41")


class TestSymbolPath(unittest.TestCase):
    def test_symbol_path_configurable(self):
        from ghidra_mcp.config import Settings

        default = Settings.load()
        self.assertIn("msdl.microsoft.com", default.symbol_path)


class TestPeCompare(unittest.TestCase):
    def test_detects_patched_bytes(self):
        import shutil

        source = Path(os.environ["WINDIR"]) / "System32" / "where.exe"
        with tempfile.TemporaryDirectory() as tmp:
            path_a = Path(tmp) / "a.bin"
            path_b = Path(tmp) / "b.bin"
            shutil.copy(source, path_a)
            shutil.copy(source, path_b)
            blob = bytearray(path_b.read_bytes())
            blob[0x1200:0x1204] = b"\x90\x90\x90\x90"
            path_b.write_bytes(blob)
            report = pe_tools.pe_compare(path_a, path_b)
        self.assertIn("verdict", report)
        self.assertTrue(report["verdict"]["code_changed"])
        text_section = report["bytes"].get(".text", {})
        self.assertGreaterEqual(text_section.get("changed_bytes", 0), 4)

    def test_identical_files(self):
        import shutil

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(os.environ["WINDIR"]) / "System32" / "where.exe"
            target = Path(tmp) / "same.bin"
            shutil.copy(source, target)
            report = pe_tools.pe_compare(source, target)
        self.assertFalse(report["verdict"]["code_changed"])


class TestUnityMetadata(unittest.TestCase):
    def _make_fake_metadata(self) -> bytes:
        import io
        import struct

        buf = io.BytesIO()
        buf.write(struct.pack("<II", 0xFAB11BAF, 27))
        sl_count = 2
        sld = b"hello world\x00key expired\x00"
        names = ["MainActivity", "OnCreate", "DoCheck"]
        str_blob = ("\x00".join(names) + "\x00").encode("latin-1")
        sl_off = 0x40
        sld_off = sl_off + sl_count * 8
        str_off = sld_off + len(sld)
        m_off = str_off + len(str_blob)
        m_count = 2
        for offset, count in [(sl_off, sl_count), (sld_off, len(sld)), (str_off, len(str_blob)), (0, 0), (0, 0), (m_off, m_count)]:
            buf.write(struct.pack("<II", offset, count))
        buf.write(b"\x00" * (sl_off - buf.tell()))
        buf.write(struct.pack("<Ii", 11, 0))
        buf.write(struct.pack("<Ii", 11, 12))
        buf.write(sld)
        buf.write(str_blob)
        buf.write(b"\x00" * (m_off - buf.tell()))
        for name_index, token in ((24, 0x06000001), (13, 0x06000002)):
            buf.write(struct.pack("<iiiiiii", name_index, 0, 0, 0, 0, -1, token))
            buf.write(struct.pack("<HHHH", 0, 0, 0, 0))
        return buf.getvalue()

    def test_parses_synthetic_v27(self):
        from ghidra_mcp import unity_metadata

        with tempfile.TemporaryDirectory() as tmp:
            metadata = Path(tmp) / "global-metadata.dat"
            metadata.write_bytes(self._make_fake_metadata())
            result = unity_metadata.unity_dump(metadata)
        self.assertNotIn("error", result)
        self.assertEqual(result["version"], 27)
        self.assertIn("key expired", result["string_literals_sample"])
        self.assertEqual(result["method_stride_validated"], 36)
        self.assertGreaterEqual(result["methods_written"], 2)

    def test_rejects_bad_magic(self):
        from ghidra_mcp import unity_metadata

        with tempfile.TemporaryDirectory() as tmp:
            metadata = Path(tmp) / "global-metadata.dat"
            metadata.write_bytes(b"\x00" * 128)
            result = unity_metadata.unity_dump(metadata)
        self.assertIn("error", result)


class TestMockGenerate(unittest.TestCase):
    def test_generate_routes_from_recording(self):
        from ghidra_mcp import net_mock

        net_mock._ROUTES.clear()
        net_mock._RECORDINGS[59999] = [
            {
                "method": "GET", "path": "/api/handshake", "query": {},
                "status": 200, "response_headers": {"Content-Type": "application/json"},
                "response_body_hex": b'{"nonce":"abcdef"}'.hex(),
            }
        ]
        result = net_mock.mock_generate(59999, {"/api/handshake": [{"find": "abcdef", "replace": "000000"}]})
        self.assertEqual(result["generated"], 1)
        route = net_mock._ROUTES["GET \\x2Fapi\\x2Fhandshake"] if "GET \\x2Fapi\\x2Fhandshake" in net_mock._ROUTES else None
        # the route is stored with a regex-escaped path; check via lookup through the server
        self.assertTrue(any("handshake" in key for key in net_mock._ROUTES))
        net_mock._ROUTES.clear()


class TestPcapWriter(unittest.TestCase):
    def test_proxy_log_becomes_valid_pcap(self):
        import base64
        import struct

        from ghidra_mcp import wireshark

        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "proxy.jsonl"
            chunks = [
                {"session": 1, "direction": "client->server", "at": 1000.0, "bytes": 16,
                 "body_b64": base64.b64encode(b"GET /api HTTP/1.1\r\n").decode()},
                {"session": 1, "direction": "server->client", "at": 1000.1, "bytes": 25,
                 "body_b64": base64.b64encode(b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}\r\n").decode()},
            ]
            log.write_text("".join(json.dumps(c) + "\n" for c in chunks), encoding="utf-8")
            result = wireshark.ws_pcap_from_proxy(str(log), out_file=str(Path(tmp) / "out.pcap"))
            self.assertNotIn("error", result)
            self.assertEqual(result["frames"], 2)
            self.assertEqual(result["sessions"], 1)
            blob = Path(result["pcap"]).read_bytes()
        magic, major, minor = struct.unpack_from("<IHH", blob, 0)
        self.assertEqual(magic, 0xA1B2C3D4)
        self.assertEqual((major, minor), (2, 4))

    def test_missing_log(self):
        from ghidra_mcp import wireshark

        result = wireshark.ws_pcap_from_proxy(r"C:\definitely\not\here.jsonl")
        self.assertIn("error", result)


class TestNucleiTools(unittest.TestCase):
    def test_template_meta_parse(self):
        from ghidra_mcp import nuclei_tools

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "probe.yaml"
            path.write_text(
                "id: my-probe\n\ninfo:\n  name: My Probe\n  author: tester\n  severity: high\n  tags: cve,http,disclosure\n\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n",
                encoding="utf-8",
            )
            meta = nuclei_tools._template_meta(path)
        self.assertEqual(meta["id"], "my-probe")
        self.assertEqual(meta["severity"], "high")
        self.assertIn("disclosure", meta["tags"])

    def test_safe_custom_path_traversal_refused(self):
        from ghidra_mcp import nuclei_tools

        os.environ["NUCLEI_TEMPLATES_DIR"] = str(Path(tempfile.gettempdir()) / "opencode_nuclei_test_repo")
        Path(os.environ["NUCLEI_TEMPLATES_DIR"]).mkdir(parents=True, exist_ok=True)
        try:
            good = nuclei_tools._safe_custom_path("probe-ok")
            self.assertIn("ghidra-mcp-custom", str(good))
            self.assertTrue(str(good).endswith("probe-ok.yaml"))
            for bad in ("../escape", "C:/evil.yaml", "sub/../../x"):
                with self.assertRaises(ValueError):
                    nuclei_tools._safe_custom_path(bad)
        finally:
            del os.environ["NUCLEI_TEMPLATES_DIR"]

    def test_findings_parse(self):
        from ghidra_mcp import nuclei_tools

        line = '{"template-id":"cve-test","info":{"name":"Test","severity":"critical","tags":"cve"},"matched-at":"http://127.0.0.1/","extracted-results":["abc"]}'
        findings = nuclei_tools._parse_findings(line + "\nnot-json\n" + '{"bad"')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertEqual(findings[0]["extracted"], ["abc"])


class TestCTPAX(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "ctpax_engine", Path(__file__).resolve().parents[1] / "install.py",
        )
        cls.engine = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.engine)

    def test_drive_scan(self):
        import ctpax_setup

        drives = ctpax_setup.scan_drives()
        self.assertTrue(drives, "no fixed drives found")
        self.assertGreaterEqual(drives[0]["free_gb"], drives[-1]["free_gb"])
        self.assertTrue(any(d["free_gb"] >= 1 for d in drives))

    def test_banner_art(self):
        import ctpax_setup

        art = ctpax_setup.build_banner("CTPAX")
        rows = art.splitlines()
        self.assertEqual(len(rows), 6)
        self.assertTrue(all(len(row) == len(rows[0]) for row in rows), "rows must align")
        # the shapes that were misread as "СТОАК" must be distinct letters
        for glyph in ("C", "T", "P", "A", "X"):
            self.assertIn(glyph, ctpax_setup._GLYPH_ROWS)

    def test_noninteractive_never_prompts(self):
        saved = getattr(self.engine, "NON_INTERACTIVE", False)
        try:
            self.engine.NON_INTERACTIVE = True
            self.assertEqual(self.engine.ask("anything", default="fallback"), "fallback")
            self.assertTrue(self.engine.confirm("proceed?", default=True))
            self.assertFalse(self.engine.confirm("proceed?", default=False))
        finally:
            self.engine.NON_INTERACTIVE = saved

    def test_prereq_dir_follows_install_root(self):
        saved = getattr(self.engine, "INSTALL_ROOT", None)
        try:
            self.engine.INSTALL_ROOT = Path("X:/CTPAX/GhidraMCP").parent
            self.assertEqual(self.engine.prereq_dir(), Path("X:/CTPAX"))
        finally:
            self.engine.INSTALL_ROOT = saved

    def test_auto_install_helpers_exist(self):
        # the install path must be able to fetch every prerequisite itself
        for name in ("install_ghidra", "install_jdk", "install_x64dbg", "download_file",
                     "install_python", "find_real_python", "_usable_python", "build_venv",
                     "prereq_dir"):
            self.assertTrue(callable(getattr(self.engine, name)), name)

    def test_real_python_is_found_and_usable(self):
        found = self.engine.find_real_python()
        self.assertIsNotNone(found, "no usable Python on PATH (needed to create the venv)")
        self.assertTrue(self.engine._usable_python(found))

    def test_usable_python_rejects_nonsense(self):
        self.assertFalse(self.engine._usable_python(["definitely-not-a-python-xyz"]))

    def test_installer_compiles_and_uses_utf8_captures(self):
        """Two regressions found on a cp1252 VM: a duplicate kwarg, and text=True
        without an explicit codec (pip's output killed the reader thread)."""
        import ast

        script = Path(__file__).resolve().parents[1] / "install.py"
        source = script.read_text(encoding="utf-8-sig")
        compile(source, str(script), "exec")  # ast.parse ignores duplicate keywords
        tree = ast.parse(source)
        offenders = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "run":
                keywords = {keyword.arg for keyword in node.keywords}
                if "text" in keywords and "encoding" not in keywords:
                    offenders.append(node.lineno)
        self.assertEqual(offenders, [], f"subprocess.run(text=True) without encoding at lines {offenders}")

    def test_registration_entries_carry_env_and_timeout(self):
        """Every generated client entry must set PYTHONUTF8 and pass extra_env through,
        so the server survives cp125x VMs and knows X64DBG_DIR from installation."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            python = Path("C:\\py\\python.exe")
            source = Path("C:\\src")
            home = Path(tmp) / "home"
            ghidra = Path("E:\\gh")
            java = Path("E:\\java")
            env = {"X64DBG_DIR": "E:\\x64dbg\\release"}

            opencode_path = Path(tmp) / "opencode.jsonc"
            cursor_path = Path(tmp) / "cursor.json"
            claude_path = Path(tmp) / "claude.json"
            codex_path = Path(tmp) / "codex.toml"
            self.engine.register_with_opencode(opencode_path, python, source, home, ghidra, java, env)
            self.engine.register_with_cursor(cursor_path, python, source, home, ghidra, java, env)
            self.engine.register_with_claude_code(
                python, source, home, ghidra, java, config_path=claude_path, extra_env=env
            )
            self.engine.register_with_codex(
                python, source, home, ghidra, java, config_path=codex_path, extra_env=env
            )

            artifacts = [
                opencode_path.read_text(encoding="utf-8"),
                cursor_path.read_text(encoding="utf-8"),
                claude_path.read_text(encoding="utf-8"),
                codex_path.read_text(encoding="utf-8"),
            ]
            for artifact in artifacts:
                self.assertIn("PYTHONUTF8", artifact, "every entry needs PYTHONUTF8")
                self.assertIn("E:\\\\x64dbg\\\\release", artifact)
                self.assertIn("PYTHONIOENCODING", artifact)

    def test_claude_registration_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".claude.json"
            path.write_text(json.dumps({"mcpServers": {"keep": {}}, "x": 1}), encoding="utf-8")
            ok = self.engine.register_with_claude_code(
                Path("C:\\py\\python.exe"), Path("C:\\src"), Path(tmp), Path("E:\\gh"), Path("E:\\java"), config_path=path,
            )
            self.assertTrue(ok)
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            self.assertIn("ghidra", data["mcpServers"])
            self.assertIn("keep", data["mcpServers"])
            self.assertEqual(data["x"], 1)
            self.assertTrue(self.engine.unregister_from_claude(path))
            self.assertNotIn("ghidra", json.loads(path.read_text())["mcpServers"])

    def test_codex_registration_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text('model = "gpt-5"\n\n[mcp_servers.other]\ncommand = "x"\n', encoding="utf-8")
            ok = self.engine.register_with_codex(
                Path("C:\\py\\python.exe"), Path("C:\\src"), Path(tmp), Path("E:\\gh"), Path("E:\\java"), config_path=path,
            )
            self.assertTrue(ok)
            text = path.read_text(encoding="utf-8")
            self.assertIn("[mcp_servers.ghidra]", text)
            self.assertIn("gpt-5", text)
            self.assertIn("[mcp_servers.other]", text)
            # second run replaces, never duplicates
            self.engine.register_with_codex(
                Path("C:\\py\\python.exe"), Path("C:\\src"), Path(tmp), Path("E:\\gh"), Path("E:\\java"), config_path=path,
            )
            self.assertEqual(path.read_text(encoding="utf-8").count("[mcp_servers.ghidra]"), 1)
            self.assertTrue(self.engine.unregister_from_codex(path))
            self.assertNotIn("ghidra", path.read_text(encoding="utf-8"))


class TestVersion(unittest.TestCase):
    def test_tuple_parse(self):
        from ghidra_mcp import version

        self.assertEqual(version._version_tuple("v1.2.3"), (1, 2, 3))
        self.assertEqual(version._version_tuple("1.0.0"), (1, 0, 0))
        self.assertEqual(version._version_tuple("release-2-1"), (2, 1, 0))

    def test_outdated_with_patched_check(self):
        from ghidra_mcp import version

        saved_inmemory, version._INMEMORY = version._INMEMORY, None
        saved_version = version.__version__
        try:
            # stale_notice reads the cache (never the network): feed it directly.
            # The comparison uses the RUNNING __version__, so lower ours to simulate
            # an old build; the cache's "installed" field must NOT matter.
            version.__version__ = "1.0.0"
            version._INMEMORY = {"installed": "9.9.9", "latest": "1.0.1", "checked_at": time.time()}
            notice = version.stale_notice()
            self.assertIn("CTPAX-MCP-OUTDATED", notice)
            self.assertIn("version_update", notice)
            self.assertIn("restart", notice)

            version._INMEMORY = {"installed": "9.9.9", "latest": "1.0.1", "checked_at": time.time()}
            version.__version__ = "1.0.1"
            self.assertEqual(version.stale_notice(), "")

            # outdated() still consults check() (the network-capable path)
            version.__version__ = "1.0.0"
            saved_check = version.check
            version.check = lambda force=False: {"installed": "1.0.0", "latest": "1.0.1", "checked_at": time.time()}
            fact = version.outdated()
            self.assertIsNotNone(fact)
            self.assertEqual(fact["latest"], "1.0.1")
            version.check = lambda force=False: {"installed": "1.0.0", "latest": None, "error": "offline"}
            self.assertIsNone(version.outdated())
        finally:
            version._INMEMORY = saved_inmemory
            version.__version__ = saved_version

    def test_cache_roundtrip(self):
        from ghidra_mcp import version

        saved_home = os.environ.get("GHIDRA_MCP_HOME")
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["GHIDRA_MCP_HOME"] = tmp
            saved, version._INMEMORY = version._INMEMORY, None
            saved_check = version.check
            try:
                version.check = lambda force=False: {"installed": "1.0.0", "latest": "9.9.9", "checked_at": time.time()}
                path = version._cache_path()
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(version.check()), encoding="utf-8")
                self.assertTrue(path.is_file())
                stored = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(stored["latest"], "9.9.9")
            finally:
                version.check = saved_check
                version._INMEMORY = saved
            if saved_home is not None:
                os.environ["GHIDRA_MCP_HOME"] = saved_home
            else:
                del os.environ["GHIDRA_MCP_HOME"]


class TestPycInfo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write_pyc(self, magic: int, version_parts: tuple[int, ...]) -> str:
        magic_u32 = 0x0A0D0000 | magic  # on-disk magics carry the 0x0a0d\r\n tag in the high half
        header = bytearray()
        if version_parts[0] >= 3 and version_parts[1] >= 8:
            header += struct.pack("<IHHI", magic_u32, 0, 0, 0)  # magic(4) flags(2) pad(2) mtime(4)
            header += struct.pack("<I", 123)  # source size
        elif (3, 7) <= version_parts[:2] < (3, 8):
            header += struct.pack("<IHI", magic_u32, 0, 0)  # magic(4) flags(2) mtime(4)
        else:
            header += struct.pack("<II", magic_u32, 0)  # magic(4) mtime(4)
        pyc = self.tmp.name + os.sep + f"v{version_parts[0]}{version_parts[1]}.pyc"
        with open(pyc, "wb") as fh:
            fh.write(bytes(header))
            fh.write(b"\x00" * 64)
        return pyc

    def test_magic_311(self):
        pyc = self._write_pyc(3495, (3, 11))
        result = lang_recover.pyc_info(pyc)
        self.assertEqual(result["python_version"], "3.11")
        self.assertEqual(result["header_bytes"], 16)

    def test_magic_36_short_header(self):
        pyc = self._write_pyc(3379, (3, 6))
        result = lang_recover.pyc_info(pyc)
        self.assertEqual(result["python_version"], "3.6")
        self.assertEqual(result["header_bytes"], 8)

    def test_unknown_magic_reports_unknown_not_crash(self):
        pyc = self._write_pyc(9999, (9, 9))
        result = lang_recover.pyc_info(pyc)
        self.assertIn("python_version", result)
        self.assertNotIn("error", result)

    def test_garbage_file_is_rejected(self):
        bad = self.tmp.name + os.sep + "junk.bin"
        with open(bad, "wb") as fh:
            fh.write(b"junk")
        result = lang_recover.pyc_info(bad)
        self.assertIn("error", result)

    def test_roundtrip_compile(self):
        source = self.tmp.name + os.sep + "sample.py"
        with open(source, "w", encoding="utf-8") as fh:
            fh.write("def f(x):\n    return x * 2\n")
        import py_compile

        pyc = py_compile.compile(source, cfile=self.tmp.name + os.sep + "sample.pyc", doraise=True)
        result = lang_recover.pyc_info(pyc)
        self.assertTrue(result["python_version"].startswith("3"))


class TestPythonEnginePick(unittest.TestCase):
    def test_modern_version_prefers_pycdc(self):
        self.assertEqual(lang_recover._pick_python_engine(3, 11, True, True, True), "pycdc")
        self.assertEqual(lang_recover._pick_python_engine(3, 11, False, True, True), "uncompyle6")

    def test_old_version_prefers_uncompyle6(self):
        self.assertEqual(lang_recover._pick_python_engine(3, 7, True, True, True), "uncompyle6")
        self.assertEqual(lang_recover._pick_python_engine(3, 7, True, False, True), "decompyle3")

    def test_none_when_everything_missing(self):
        self.assertIsNone(lang_recover._pick_python_engine(3, 11, False, False, False))

    def test_pyc_route_is_last_resort(self):
        self.assertEqual(lang_recover._pick_python_engine(3, 11, True, False, False), "pycdc")


class TestManagedTools(unittest.TestCase):
    def test_status_shape_without_external_tools(self):
        from ghidra_mcp import managed

        status = managed.managed_status()
        for key in ("binary_ninja", "ilspycmd", "dnspy", "dotpeek", "megadumper", "frida"):
            self.assertIn(key, status)
        # frida is not installed in the test env: must degrade cleanly, never raise
        self.assertIn("available", status["frida"])

    def test_binaryninja_status_never_raises(self):
        from ghidra_mcp import managed

        result = managed.binaryninja_status()
        self.assertIn("found", result)

    def test_java_engine_status_known_and_unknown(self):
        info = lang_recover.java_engine_status("cfr")
        self.assertIn("jar", info)
        bad = lang_recover.java_engine_status("nope")
        self.assertIn("error", bad)

    def test_tool_modules_import_and_register(self):
        from ghidra_mcp import tools_frida, tools_managed  # noqa: F401

        self.assertTrue(callable(tools_frida.frida_attach))
        self.assertTrue(callable(tools_frida.frida_hook))
        self.assertTrue(callable(tools_managed.binaryninja_open))
        self.assertTrue(callable(tools_managed.binaryninja_decompile))
        self.assertTrue(callable(tools_managed.dotnet_decompile))
        self.assertTrue(callable(tools_managed.dnspy_open))
        self.assertTrue(callable(tools_managed.dotpeek_open))
        self.assertTrue(callable(tools_managed.mega_dump))
        self.assertTrue(callable(tools_managed.managed_status))

    def test_frida_status_when_missing(self):
        from ghidra_mcp import frida_mcp

        result = frida_mcp.status()
        self.assertIn("available", result)
        if not result.get("available"):
            self.assertIn("hint", result)


class TestHttpdbgMcp(unittest.TestCase):
    """HTTP Debugger integration: tool registration, install detection, bridge protocol."""

    def tearDown(self):
        from ghidra_mcp import httpdbg_mcp

        httpdbg_mcp.stop_session()

    def _spawn_fake(self, script_body: str) -> dict:
        from ghidra_mcp import httpdbg_mcp

        folder = tempfile.mkdtemp()
        script = Path(folder) / "fake_bridge.py"
        script.write_text(script_body, encoding="utf-8")
        httpdbg_mcp.stop_session()
        return httpdbg_mcp._spawn_bridge(timeout=5, command=[sys.executable, str(script)])

    def test_all_official_bridge_tools_registered_under_real_names(self):
        import asyncio

        from ghidra_mcp import httpdbg_mcp, tools_httpdbg  # noqa: F401  (registers its tools)
        from ghidra_mcp.runtime import mcp

        names = {tool.name for tool in asyncio.run(mcp.list_tools())}
        expected = {f"httpdbg_mcp_{name}" for name in httpdbg_mcp._MCP_TOOLS}
        self.assertTrue(expected <= names, f"missing from the registry: {sorted(expected - names)}")
        self.assertNotIn("_wrapped", names, "the wrappers collapsed into one registration")
        for extra in ("httpdbg_status", "httpdbg_mcp_get_session", "httpdbg_mcp_call",
                      "httpdbg_mcp_list_tools", "httpdbg_mcp_stop_session"):
            self.assertIn(extra, names)

    def test_status_without_install_says_where_to_get_it(self):
        from ghidra_mcp import httpdbg_mcp

        empty = Path(tempfile.mkdtemp())
        with mock.patch.object(httpdbg_mcp, "_install_candidates", return_value=[empty]):
            status = httpdbg_mcp.status()
        self.assertFalse(status["installed"])
        self.assertIn("httpdebugger.com", status["note"])
        self.assertFalse(status["bridge_session"]["connected"])

    def test_call_without_session_reports_how_to_connect(self):
        from ghidra_mcp import httpdbg_mcp

        saved = dict(httpdbg_mcp._BRIDGE)
        httpdbg_mcp._BRIDGE.clear()
        try:
            self.assertIn("error", httpdbg_mcp.call("list_transactions"))
            self.assertIn("error", httpdbg_mcp.list_tools())
        finally:
            httpdbg_mcp._BRIDGE.clear()
            httpdbg_mcp._BRIDGE.update(saved)

    def test_mcp_handshake_discovery_and_full_passthrough(self):
        from ghidra_mcp import httpdbg_mcp

        info = self._spawn_fake(_FAKE_MCP_BRIDGE)
        self.assertTrue(info.get("started"), info)
        self.assertEqual(info.get("handshake"), "mcp")

        listed = httpdbg_mcp.list_tools()
        self.assertEqual(listed.get("count"), 2, listed)
        names = {tool["name"] for tool in listed["tools"]}
        self.assertIn("brand_new_tool", names)
        page_param = next(t for t in listed["tools"] if t["name"] == "list_transactions")
        self.assertEqual(page_param["parameters"]["page"]["type"], "integer")

        # documented tool: documented defaults merged with the caller's params
        result = httpdbg_mcp.call("list_transactions", {"page": 1})
        self.assertEqual(result.get("called"), "list_transactions")
        self.assertEqual(result["arguments"].get("page"), 1)
        self.assertIn("session_id", result["arguments"])

        # anything the bridge exposes, even outside the documented 8
        result = httpdbg_mcp.call("brand_new_tool", {"x": True})
        self.assertEqual(result.get("called"), "brand_new_tool")
        self.assertEqual(result.get("arguments"), {"x": True})

    def test_get_session_reuses_running_bridge_and_lists_full_toolset(self):
        from ghidra_mcp import httpdbg_mcp

        self._spawn_fake(_FAKE_MCP_BRIDGE)
        session = httpdbg_mcp.get_session()
        self.assertTrue(session.get("connected"), session)
        self.assertEqual(session.get("protocol"), "mcp")
        self.assertIn("brand_new_tool", session.get("tools") or [])
        self.assertEqual(session.get("tool_count"), 2)

    def test_legacy_bridge_falls_back_to_raw_methods(self):
        from ghidra_mcp import httpdbg_mcp

        info = self._spawn_fake(_FAKE_LEGACY_BRIDGE)
        self.assertEqual(info.get("handshake"), "legacy", info)
        result = httpdbg_mcp.call("list_transactions", {"page": 2})
        self.assertTrue(result.get("legacy"), result)
        self.assertEqual(result["params"].get("page"), 2)
        self.assertEqual(result["params"].get("session_id"), None)

    def test_hung_bridge_times_out_instead_of_blocking_server(self):
        from ghidra_mcp import httpdbg_mcp

        info = self._spawn_fake(_FAKE_SILENT_BRIDGE)
        self.assertEqual(info.get("handshake"), "mcp", info)
        started = time.time()
        result = httpdbg_mcp.call("list_transactions", timeout=1.0)
        elapsed = time.time() - started
        self.assertLess(elapsed, 5.0, "the call blocked instead of timing out")
        self.assertIn("timeout", str(result.get("error", "")), result)

    def test_stop_session_is_idempotent(self):
        from ghidra_mcp import httpdbg_mcp

        self.assertFalse(httpdbg_mcp.stop_session().get("stopped"))
        self._spawn_fake(_FAKE_MCP_BRIDGE)
        self.assertTrue(httpdbg_mcp.stop_session().get("stopped"))
        self.assertFalse(httpdbg_mcp.stop_session().get("stopped"))


class TestCheatEngine(unittest.TestCase):
    """Cheat Engine integration: detection, autorun bridge, mailbox protocol, sugar."""

    def tearDown(self):
        from ghidra_mcp import ce_mcp

        ce_mcp._CE_LOCK.release() if ce_mcp._CE_LOCK.locked() else None

    def _patched(self, state: Path, exe_dir: Path | None):
        """Contexts patching the state dir and (optionally) the CE install location."""
        from ghidra_mcp import ce_mcp

        env = mock.patch.dict(os.environ, {"CTPAX_CE_STATE_DIR": str(state)})
        if exe_dir is None:
            finder = mock.patch.object(ce_mcp, "_find_exe", return_value=None)
        else:
            exe = exe_dir / "Cheat Engine.exe"
            finder = mock.patch.object(ce_mcp, "_find_exe", return_value=exe)
        return env, finder

    @staticmethod
    def _fake_bridge(state: Path, payload: dict, *, stop_after: int = 1):
        """A thread that plays the CE side: read request.lua, write the response."""
        import threading as th

        request = state / "request.lua"

        def run():
            served = 0
            for _ in range(200):  # up to 10s
                if request.exists():
                    try:
                        text = request.read_text(encoding="utf-8")
                    except OSError:
                        time.sleep(0.05)
                        continue
                    request.unlink(missing_ok=True)
                    nonce = text.split("ctpax-nonce:", 1)[1].splitlines()[0].strip()
                    (state / f"response_{nonce}.json").write_text(json.dumps(payload), encoding="utf-8")
                    served += 1
                    if served >= stop_after:
                        return
                time.sleep(0.05)

        thread = th.Thread(target=run, daemon=True)
        thread.start()
        return thread

    def test_tools_registered(self):
        import asyncio

        from ghidra_mcp import tools_ce  # noqa: F401  (registers its tools)
        from ghidra_mcp.runtime import mcp

        names = {tool.name for tool in asyncio.run(mcp.list_tools())}
        expected = {
            "ce_status", "ce_launch", "ce_bridge_install", "ce_bridge_status",
            "ce_lua", "ce_attach", "ce_read", "ce_write", "ce_assemble", "ce_focus",
        }
        self.assertTrue(expected <= names, f"missing: {sorted(expected - names)}")

    def test_status_without_install_says_where_to_get_it(self):
        from ghidra_mcp import ce_mcp

        state = Path(tempfile.mkdtemp())
        env, finder = self._patched(state, None)
        with env, finder:
            status = ce_mcp.status()
        self.assertFalse(status["installed"])
        self.assertIn("cheatengine.org", status["note"])

    def test_bridge_install_writes_autorun_script_and_is_idempotent(self):
        from ghidra_mcp import ce_mcp

        state = Path(tempfile.mkdtemp())
        exe_dir = Path(tempfile.mkdtemp())
        env, finder = self._patched(state, exe_dir)
        with env, finder:
            first = ce_mcp.bridge_install()
            second = ce_mcp.bridge_install()
        self.assertTrue(first.get("installed"), first)
        self.assertTrue(first.get("changed"), first)
        self.assertFalse(second.get("changed"), second)
        script = exe_dir / "autorun" / ce_mcp._BRIDGE_FILENAME
        self.assertTrue(script.is_file())
        text = script.read_text(encoding="utf-8")
        self.assertIn("createTimer", text)
        self.assertIn("request.lua", text)
        self.assertIn("openProcess", text)
        self.assertNotIn(text.encode("ascii", "strict").decode("ascii"), "")  # pure ASCII

    def test_bridge_install_without_ce_errors(self):
        from ghidra_mcp import ce_mcp

        env, finder = self._patched(Path(tempfile.mkdtemp()), None)
        with env, finder:
            result = ce_mcp.bridge_install()
        self.assertIn("error", result)

    def test_lua_without_heartbeat_fails_fast_with_hint(self):
        from ghidra_mcp import ce_mcp

        state = Path(tempfile.mkdtemp())
        env, _ = self._patched(state, None)
        with env:
            started = time.time()
            result = ce_mcp.lua("return 1", timeout=5)
        self.assertLess(time.time() - started, 2.0, "should not wait when the bridge is absent")
        self.assertIn("error", result)
        self.assertIn("ce_bridge_install", str(result.get("hint", "")))

    def test_lua_roundtrip_through_fake_bridge(self):
        from ghidra_mcp import ce_mcp

        state = Path(tempfile.mkdtemp())
        state.mkdir(exist_ok=True)
        (state / "heartbeat").write_text(str(int(time.time())), encoding="utf-8")
        env, _ = self._patched(state, None)
        payload = {"ok": True, "result": {"hp": 100, "flags": [1, 0, 1]}}
        with env:
            thread = self._fake_bridge(state, payload)
            result = ce_mcp.lua("return {hp=100}", timeout=5)
            thread.join(5)
        self.assertEqual(result, {"ok": True, "result": payload["result"]})

    def test_lua_surfaces_bridge_errors(self):
        from ghidra_mcp import ce_mcp

        state = Path(tempfile.mkdtemp())
        (state / "heartbeat").write_text(str(int(time.time())), encoding="utf-8")
        env, _ = self._patched(state, None)
        with env:
            thread = self._fake_bridge(state, {"ok": False, "error": "attempt to index nil"})
            result = ce_mcp.lua("return nil", timeout=5)
            thread.join(5)
        self.assertIn("error", result)
        self.assertIn("attempt to index nil", result["error"])

    def test_lua_timeout_is_fast_and_cleans_up(self):
        from ghidra_mcp import ce_mcp

        state = Path(tempfile.mkdtemp())
        (state / "heartbeat").write_text(str(int(time.time())), encoding="utf-8")
        env, _ = self._patched(state, None)
        with env:
            started = time.time()
            result = ce_mcp.lua("return 1", timeout=1.0)
            elapsed = time.time() - started
        self.assertLess(elapsed, 5.0, "timeout must not hang the server")
        self.assertIn("timeout", str(result.get("error", "")))
        self.assertFalse((state / "request.lua").exists(), "stale request left behind")

    def test_sugar_tools_build_expected_ce_lua(self):
        from ghidra_mcp import ce_mcp

        captured: list[str] = []

        def fake_lua(script, **kwargs):
            captured.append(script)
            return {"ok": True, "result": None}

        with mock.patch.object(ce_mcp, "lua", side_effect=fake_lua):
            ce_mcp.attach("game.exe")
            ce_mcp.read("game.exe+100", 4)
            ce_mcp.write("0x1234", "90 90 CC")
            ce_mcp.assemble("nop")
        self.assertEqual(captured[0], 'return openProcess("game.exe")')
        self.assertEqual(captured[1], 'return readBytes("game.exe+100", 4, true)')
        self.assertEqual(captured[2], "return writeBytes(4660, 144,144,204)")
        self.assertEqual(captured[3], 'return autoAssemble("nop")')

    def test_write_rejects_non_hex_payload(self):
        from ghidra_mcp import ce_mcp

        self.assertIn("error", ce_mcp.write("0x1234", "zz"))
        self.assertIn("error", ce_mcp.write("0x1234", "9"))  # odd nibble

    def test_lua_quote_and_arg(self):
        from ghidra_mcp import ce_mcp

        self.assertEqual(ce_mcp._lua_quote('a"b\\c\nd'), '"a\\"b\\\\c\\nd"')
        self.assertEqual(ce_mcp._lua_arg(42), "42")
        self.assertEqual(ce_mcp._lua_arg("12345"), "12345")
        self.assertEqual(ce_mcp._lua_arg("notepad.exe"), '"notepad.exe"')
        # addresses: 0x becomes a Lua number, everything else stays CE's own syntax
        self.assertEqual(ce_mcp._lua_address("0x1234"), "4660")
        self.assertEqual(ce_mcp._lua_address("00400000"), '"00400000"')
        self.assertEqual(ce_mcp._lua_address("game.exe+100"), '"game.exe+100"')
        self.assertEqual(ce_mcp._lua_address(4660), "4660")


# A minimal MCP bridge over stdio: it answers initialize, tools/list and
# tools/call - the protocol HTTPDebuggerMcp.exe speaks.
_FAKE_MCP_BRIDGE = r'''
import json, sys

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    method = msg.get("method") or ""
    if mid is None:
        continue  # notification
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-httpdbg", "version": "0"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
            {"name": "list_transactions", "description": "captured transactions",
             "inputSchema": {"type": "object",
                             "properties": {"page": {"type": "integer", "description": "page index"}},
                             "required": []}},
            {"name": "brand_new_tool", "description": "not one of the documented 8",
             "inputSchema": {"type": "object", "properties": {}}}]}})
    elif method == "tools/call":
        params = msg.get("params") or {}
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": json.dumps(
                {"called": params.get("name"), "arguments": params.get("arguments")})}],
            "isError": False}})
    else:
        send({"jsonrpc": "2.0", "id": mid,
              "error": {"code": -32601, "message": "Method not found"}})
'''

# A bridge that refuses the MCP handshake but answers the legacy raw methods.
_FAKE_LEGACY_BRIDGE = r'''
import json, sys

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    method = msg.get("method") or ""
    if mid is None:
        continue
    if method == "list_transactions" or method == "get_capture_status":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "legacy": True, "method": method, "params": msg.get("params")}})
    else:
        send({"jsonrpc": "2.0", "id": mid,
              "error": {"code": -32601, "message": "Method not found"}})
'''

# Completes the handshake, then never answers anything else.
_FAKE_SILENT_BRIDGE = r'''
import json, sys

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    if mid is None:
        continue
    if msg.get("method") == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "serverInfo": {"name": "silent-httpdbg", "version": "0"}}})
'''


if __name__ == "__main__":
    unittest.main(verbosity=2)
