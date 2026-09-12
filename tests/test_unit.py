"""Unit tests for the pure-logic modules: crypto, notebook, pe_tools, lang_recover.

Run: python tests\\test_unit.py   (no pytest needed; prints PASS/FAIL and exits nonzero on failure)
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
