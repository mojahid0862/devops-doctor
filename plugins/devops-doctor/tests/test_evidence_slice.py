import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import evidence_slice as reader


class EvidenceSliceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, text, name="saved.txt"):
        path = self.root / name
        path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
        return path

    def wire(self, result):
        return reader.encode_bytes(result)

    def expand(self, result):
        lines = []
        for item in result["items"]:
            for record in item["records"]:
                for number in range(record.get("start", record.get("line")), record.get("end", record.get("line")) + 1):
                    lines.append({"line": number, "text": record["text"], "eol": record["eol"], "redacted": record["redacted"]})
        return lines

    def test_exact_lines_eol_controls_and_unchanged_source(self):
        raw = "one\r\ntwo\rthree\nfour\t\x1b\u202e\x00".encode()
        path = self.write(raw)
        result = reader.read_evidence(path, "lines", ranges=[[2, 4]])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["source"]["path"], str(path.resolve()))
        self.assertEqual(result["source"]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual([(r["text"], r["eol"]) for r in self.expand(result)], [("two", "\r"), ("three", "\n"), ("four\t\x1b\u202e\x00", "")])
        self.assertNotIn(b"\x1b", self.wire(result))
        self.assertEqual(path.read_bytes(), raw)

    def test_exact_repeats_pack_but_timestamps_status_and_eol_do_not(self):
        rows = ["progress waiting for package\r\n"] * 30 + ["t=1 status=ok\n", "t=2 status=ok\n", "t=2 status=failed\n", "same\r\n", "same\n", "WARN unique\n"]
        path = self.write("".join(rows))
        plain = reader.read_evidence(path, "lines", ranges=[[1, len(rows)]])
        packed = reader.read_evidence(path, "lines", ranges=[[1, len(rows)]], pack_runs=True)
        self.assertEqual(self.expand(plain), self.expand(packed))
        first = packed["items"][0]["records"][0]
        self.assertEqual((first["start"], first["end"], first["count"], first["eol"]), (1, 30, 30, "\r\n"))
        self.assertLess(len(self.wire(packed)), len(self.wire(plain)))
        self.assertIn(b"WARN unique", self.wire(packed))

    def test_different_secrets_never_become_identical_runs_after_redaction(self):
        path = self.write('password="synthetic-one"\npassword="synthetic-two"\npassword="synthetic-three"\n')
        result = reader.read_evidence(path, "lines", ranges=[[1, 3]], pack_runs=True)
        records = result["items"][0]["records"]
        self.assertEqual(len(records), 3)
        self.assertTrue(all("line" in record and record["redacted"] for record in records))
        self.assertNotIn(b"synthetic-", self.wire(result))

    def test_no_gain_has_identical_packet(self):
        path = self.write("a\nb\nc\n")
        plain = reader.read_evidence(path, "lines", ranges=[[1, 3]])
        packed = reader.read_evidence(path, "lines", ranges=[[1, 3]], pack_runs=True)
        self.assertEqual(self.wire(plain), self.wire(packed))

    def test_multiline_secrets_masked_even_when_selection_starts_inside(self):
        cases = [
            ("-----BEGIN PRIVATE KEY-----\nsynthetic-private\n-----END PRIVATE KEY-----\ntail\n", 2),
            ("-----BEGIN PRIVATE KEY-----\nsynthetic-unclosed\n", 2),
            ('command --token "synthetic\nsecret-suffix"\ntail\n', 2),
            ("password: |\n  synthetic-yaml\ntail\n", 2),
            ('const password = `\nsynthetic-template\n`;\ntail\n', 2),
            ('password = """\nsynthetic-python\n"""\ntail\n', 2),
        ]
        for content, line in cases:
            with self.subTest(content=content.splitlines()[0]):
                path = self.write(content)
                result = reader.read_evidence(path, "lines", ranges=[[line, line]])
                self.assertEqual(result["items"][0]["records"][0]["text"], reader.common.MASK)
                self.assertNotIn(b"synthetic", self.wire(result))

    def test_packing_retains_context_dependent_redaction(self):
        path = self.write("same\n-----BEGIN PRIVATE KEY-----\nsame\nsame\n-----END PRIVATE KEY-----\nsame\n")
        result = reader.read_evidence(path, "lines", ranges=[[1, 6]], pack_runs=True)
        self.assertEqual([r["redacted"] for r in self.expand(result)], [False, True, True, True, True, False])

    def test_json_pointer_escapes_empty_keys_and_exact_scalar_types(self):
        path = self.write('{"a/b":{"~key":{"":false}},"zero":0,"negative":-12,"nil":null,"number":"12","tiny":1e-400,"huge":1e400,"integer":9007199254740993123456789}', "saved.json")
        pointers = ["/a~1b/~0key/", "/zero", "/negative", "/nil", "/number", "/tiny", "/huge", "/integer"]
        result = reader.read_evidence(path, "json", pointers=pointers)
        self.assertEqual(result["status"], "complete")
        values = [item["records"][0]["value"] for item in result["items"]]
        self.assertEqual(values[:5], [False, reader.Number("0"), reader.Number("-12"), None, "12"])
        self.assertEqual(values[5:], [reader.Number("1e-400"), reader.Number("1e400"), reader.Number("9007199254740993123456789")])
        self.assertIn(b'"value":1e400', self.wire(result))
        self.assertNotIn(b"Infinity", self.wire(result))

    def test_json_array_whole_records_and_collection_context(self):
        path = self.write('{"status":"partial","truncated":true,"NextToken":"page-two","returned_count":3,"data":[{"id":1,"status":"ok"},{"id":2,"status":"failed","error":"exact detail"},{"id":3,"status":"ok"}]}', "saved.json")
        result = reader.read_evidence(path, "json", pointers=["/data"], array_range=[1, 1])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["context"]["fields"]["status"], "partial")
        self.assertTrue(result["context"]["fields"]["truncated"])
        self.assertEqual(result["context"]["fields"]["NextToken"], "page-two")
        item = result["items"][0]
        self.assertEqual(item["delivered"], [[1, 1]])
        self.assertEqual(item["records"][0]["value"], {"id": reader.Number("2"), "status": "failed", "error": "exact detail"})
        self.assertEqual(item["remaining"], [])

    def test_secret_ancestry_named_env_values_and_key_blocks(self):
        content = {"secret": {"nested": "synthetic-secret"}, "environment": [{"name": "PUBLIC", "value": "synthetic-env"}],
                   "setting": {"Name": "API_KEY", "Value": "synthetic-key"}, "note": "-----BEGIN PRIVATE KEY-----\nsynthetic-key-block"}
        path = self.write(json.dumps(content), "saved.json")
        result = reader.read_evidence(path, "json", pointers=["/secret/nested", "/environment/0/value", "/setting/Value", "/note"])
        self.assertEqual(result["status"], "complete")
        self.assertTrue(all(item["records"][0]["redacted"] for item in result["items"]))
        self.assertNotIn(b"synthetic", self.wire(result))

    def test_embedded_json_without_secrets_is_not_reformatted(self):
        inner = '{ "count" : 1e400, "ok": false }'
        path = self.write(json.dumps({"message": inner}), "saved.json")
        result = reader.read_evidence(path, "json", pointers=["/message"])
        self.assertEqual(result["items"][0]["records"][0]["value"], inner)
        self.assertFalse(result["items"][0]["records"][0]["redacted"])

    def test_invalid_json_duplicates_and_nonfinite_fail_without_echo(self):
        for content in ['{"x":1,"x":2}', '{"x":{"a":1,"a":2}}', '{bad synthetic-private', '{} {}', '{"v":NaN}', '{"v":Infinity}']:
            with self.subTest(content=content):
                result = reader.read_evidence(self.write(content), "json", pointers=[""])
                self.assertEqual(result["status"], "failed")
                self.assertNotIn(b"synthetic-private", self.wire(result))
                self.assertNotIn("items", result)

    def test_missing_or_invalid_pointers_do_not_dump_source(self):
        path = self.write('{"records":["synthetic-hidden"]}')
        for pointer in ["/missing", "/records/01", "/records/-", "/records/99", "/records/0/missing", "#fragment", "/bad~2escape"]:
            with self.subTest(pointer=pointer):
                result = reader.read_evidence(path, "json", pointers=[pointer])
                self.assertEqual(result["status"], "failed")
                self.assertNotIn(b"synthetic-hidden", self.wire(result))

    def test_missing_and_out_of_range_selections_explicit(self):
        path = self.write("one\ntwo\n")
        result = reader.read_evidence(path, "lines", ranges=[[1, 1], [2, 3]])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["items"][1]["remaining"], [[2, 3]])
        self.assertEqual(result["items"][1]["records"], [])
        path = self.write('{"rows":[1,2]}')
        result = reader.read_evidence(path, "json", pointers=["/rows"], array_range=[1, 2])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["items"][0]["error"], "array_range_outside_source")

    def test_oversized_line_has_no_clipping_and_can_be_retrieved(self):
        path = self.write("x" * 6000 + "\nsmall\n")
        result = reader.read_evidence(path, "lines", ranges=[[1, 2]], max_bytes=1024)
        item = result["items"][0]
        self.assertEqual(item["records"], [])
        self.assertEqual(item["remaining"], [[1, 2]])
        self.assertTrue(item["next"]["oversized_record"])
        self.assertLessEqual(len(self.wire(result)), 1024)
        retry = reader.read_evidence(path, "lines", ranges=[[1, 2]], sha256=result["source"]["sha256"], max_bytes=8000)
        self.assertEqual(retry["status"], "complete")
        self.assertEqual(retry["items"][0]["records"][0]["text"], "x" * 6000)

    def test_array_budget_delivers_whole_records_and_explicit_remaining(self):
        path = self.write(json.dumps({"rows": [{"id": i, "message": "x" * 100} for i in range(30)]}))
        result = reader.read_evidence(path, "json", pointers=["/rows"], array_range=[0, 29], max_bytes=1500)
        item = result["items"][0]
        self.assertEqual(result["status"], "partial")
        self.assertGreater(len(item["records"]), 0)
        self.assertEqual(item["remaining"], [[len(item["records"]), 29]])
        self.assertTrue(all(record["value"]["message"] == "x" * 100 for record in item["records"]))
        self.assertLessEqual(len(self.wire(result)), 1500)

    def test_oversized_pointer_does_not_block_smaller_independent_pointer(self):
        path = self.write(json.dumps({"large": "x" * 6000, "small": False}))
        result = reader.read_evidence(path, "json", pointers=["/large", "/small"], max_bytes=1500)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["items"][0]["records"], [])
        self.assertTrue(result["items"][0]["next"]["oversized_record"])
        self.assertIs(result["items"][1]["records"][0]["value"], False)
        self.assertLessEqual(len(self.wire(result)), 1500)

    def test_metadata_overflow_retains_entire_request_pending(self):
        path = self.write("one\n")
        result = reader.read_evidence(path, "lines", ranges=[[1, 1]] * 100, max_bytes=1024)
        self.assertEqual(result["error"], "request_metadata_exceeds_budget")
        self.assertEqual(result["remaining"], "entire_request")
        self.assertLessEqual(len(self.wire(result)), 1024)

    def test_pinned_source_drift_rejected_and_source_never_written(self):
        path = self.write("first\n")
        first = reader.read_evidence(path, "lines", ranges=[[1, 1]])
        path.write_bytes(b"second\n")
        result = reader.read_evidence(path, "lines", ranges=[[1, 1]], sha256=first["source"]["sha256"])
        self.assertEqual(result["error"], "source_sha256_mismatch")
        self.assertNotIn(b"second", self.wire(result))
        self.assertEqual(path.read_bytes(), b"second\n")

    def test_credential_paths_invalid_utf8_and_limits(self):
        for name in [".env", ".env.prod", "credentials", "id_rsa", "private.pem", ".npmrc"]:
            with self.subTest(name=name):
                result = reader.read_evidence(self.write("synthetic-private", name), "lines", ranges=[[1, 1]])
                self.assertEqual(result["error"], "credential_file_not_read")
        self.assertEqual(reader.read_evidence(self.write(b"\xff"), "lines", ranges=[[1, 1]])["error"], "source_requires_utf8")
        with patch.object(reader, "MAX_INPUT_BYTES", 2):
            self.assertEqual(reader.read_evidence(self.write("123"), "lines", ranges=[[1, 1]])["error"], "source_exceeds_8MiB_limit")
        with patch.object(reader, "MAX_LINES", 2):
            self.assertEqual(reader.read_evidence(self.write("\n\n\n"), "lines", ranges=[[1, 1]])["error"], "source_exceeds_100000_lines")

    def test_negative_zero_invalid_ranges_and_mode_combinations_fail(self):
        path = self.write('[1,2]')
        for bounds in [[0, 1], [-1, 2], [2, 1], [True, 2]]:
            self.assertEqual(reader.read_evidence(path, "lines", ranges=[bounds])["status"], "failed")
        self.assertEqual(reader.read_evidence(path, "json", pointers=[""], array_range=[-1, 1])["status"], "failed")
        self.assertEqual(reader.read_evidence(path, "json", pointers=[""], pack_runs=True)["status"], "failed")
        self.assertEqual(reader.read_evidence(path, "json", pointers=["", "/0"], array_range=[0, 1])["status"], "failed")

    def test_known_app_credential_stores_are_refused_without_reading(self):
        for relative in ["auth.json", "application_default_credentials.json", "accessTokens.json", ".kube/config", ".azure/cache.json"]:
            with self.subTest(relative=relative):
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"synthetic":"private-fixture"}', encoding="utf-8")
                with patch.object(Path, "open", side_effect=AssertionError("credential file must not be opened")):
                    result = reader.read_evidence(path, "json", pointers=[""])
                self.assertEqual(result["error"], "credential_file_not_read")
                self.assertNotIn(b"private-fixture", self.wire(result))

    def test_empty_pointer_and_empty_file(self):
        result = reader.read_evidence(self.write('false'), "json", pointers=[""])
        self.assertIs(result["items"][0]["records"][0]["value"], False)
        result = reader.read_evidence(self.write(""), "lines", ranges=[[1, 1]])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["items"][0]["source_line_count"], 0)

    def test_cli_json_framing_and_exit_code(self):
        path = self.write("line\n" * 50)
        proc = subprocess.run([sys.executable, "-B", str(Path(reader.__file__)), "--file", str(path), "--max-bytes", "1024", "lines", "--range", "1:50"], capture_output=True, check=False)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, b"")
        self.assertLessEqual(len(proc.stdout), 1024)
        self.assertTrue(proc.stdout.endswith(b"\n"))
        self.assertFalse(proc.stdout.endswith(b"\r\n"))
        self.assertEqual(json.loads(proc.stdout)["status"], "partial")


if __name__ == "__main__":
    unittest.main()
