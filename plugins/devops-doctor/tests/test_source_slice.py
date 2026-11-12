import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import source_slice as reader


class SourceSliceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Source Reader Test")
        self.git("config", "user.email", "source-reader@example.invalid")
        self.write("sample.txt", "first\nsecond\nthird\nfourth\nfifth\n")
        self.write("other.txt", "other first\nother second\n")
        self.write("unicode.txt", 'a"\\\t' + "\u2603\U0001f642" * 100 + "\nend\n")
        self.write("large.txt", "x" * 6000 + "\nsmall\n")
        self.write("secrets.txt", 'before\npassword="synthetic-password"\n-----BEGIN PRIVATE KEY-----\nsynthetic-private\n-----END PRIVATE KEY-----\nafter\ncmd --token "synthetic\nsecret suffix"\ntail\n')
        self.write("secret.yaml", "before\npassword: |\n  synthetic-yaml-value\nafter\n")
        self.write("secret.py", 'before\npassword = """\nsynthetic-python-value\n"""\nafter\n')
        self.write("secret.js", 'before\nconst password = `\nsynthetic-javascript-value\n`;\nafter\n')
        self.write("empty.txt", "")
        self.write(".env", "ANY_VALUE=synthetic-private-env\n")
        self.write("binary.bin", b"abc\x00def")
        self.write("nonutf8.txt", b"\xff\xfe")
        self.git("add", "--all")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        self.revision = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True,
                              text=True, encoding="utf-8", env=env).stdout

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)

    def request(self, path="sample.txt", start=1, end=5):
        return {"path": path, "start": start, "end": end}

    def read(self, requests=None, **kwargs):
        return reader.read_ranges(self.root, self.revision, requests or [self.request()], **kwargs)

    def expand_compact(self, result):
        expanded = json.loads(reader.encode(result))
        self.assertEqual(expanded.pop("format"), "compact")
        for item in expanded.get("items", []):
            item["lines"] = [{"number": line[0], "text": line[1], "redacted": len(line) == 3 and line[2]}
                             for line in item["lines"]]
        return expanded

    def expand_text(self, result):
        wire = result if isinstance(result, bytes) else reader.encode_bytes(result)
        records = wire.decode("utf-8").split("\n")
        self.assertEqual(records.pop(), "")
        self.assertEqual(records.pop(), "END")
        self.assertEqual(records.pop(0), "SOURCE_SLICE_TEXT_V1")
        self.assertTrue(records[0].startswith("RESULT "))
        expanded = json.loads(records.pop(0)[7:])
        self.assertEqual(expanded.pop("format"), "text")
        item = None
        for record in records:
            if record.startswith("ITEM "):
                item = json.loads(record[5:])
                item["lines"] = []
                expanded["items"].append(item)
                continue
            self.assertIsNotNone(item)
            prefix, payload = record.split("\t", 1)
            number = prefix.rstrip("RJ")
            flags = prefix[len(number):]
            self.assertIn(flags, ("", "R", "J", "RJ"))
            text = json.loads(payload) if "J" in flags else payload
            self.assertIsInstance(text, str)
            item["lines"].append({"number": int(number), "text": text, "redacted": "R" in flags})
        for item in expanded.get("items", []):
            numbers = [line["number"] for line in item["lines"]]
            self.assertEqual(numbers, sorted(set(numbers)))
            if "delivered" in item:
                self.assertEqual(reader.merge_ranges([[number, number] for number in numbers]), item["delivered"])
        return expanded

    def test_exact_ranges_and_immutable_source(self):
        self.write("sample.txt", "working tree changed\n")
        result = self.read([self.request(start=2, end=3), self.request("other.txt", 2, 2)])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["source"]["revision"], self.revision)
        item = result["items"][0]
        self.assertEqual(item["delivered"], [[2, 3]])
        self.assertEqual(item["remaining"], [])
        self.assertEqual([(line["number"], line["text"]) for line in item["lines"]], [(2, "second"), (3, "third")])
        self.assertEqual(item["blob_sha"], self.git("rev-parse", self.revision + ":sample.txt").strip())
        self.assertEqual(result["items"][1]["lines"][0]["text"], "other second")

    def test_overlap_deduplicates_only_actual_requested_lines(self):
        result = self.read([self.request(start=1, end=2), self.request(start=2, end=3), self.request(start=5, end=5)])
        item = result["items"][0]
        self.assertEqual(item["requested"], [[1, 3], [5, 5]])
        self.assertEqual([line["number"] for line in item["lines"]], [1, 2, 3, 5])

    def test_new_revision_reads_new_blob_without_reusing_delivery(self):
        old = self.read([self.request(start=1, end=1)])
        self.write("sample.txt", "new first\n")
        self.git("add", "sample.txt")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "new revision")
        new_revision = self.git("rev-parse", "HEAD").strip()
        new = reader.read_ranges(self.root, new_revision, [self.request(start=1, end=1)])
        repeated = self.read([self.request(start=1, end=1)])
        self.assertEqual(new["items"][0]["lines"][0]["text"], "new first")
        self.assertNotEqual(new["items"][0]["blob_sha"], old["items"][0]["blob_sha"])
        self.assertEqual(old, repeated)

    def test_budget_accounts_for_escaped_unicode_and_json(self):
        request = [self.request("unicode.txt", 1, 2)]
        result = self.read(request, max_chars=1024)
        self.assertLessEqual(len(reader.encode(result)), 1024)
        self.assertEqual(result["status"], "partial")
        item = result["items"][0]
        self.assertEqual(item["remaining"], [[1, 2]])
        self.assertEqual(item["next_line"]["reason"], "oversized_line")
        minimum = item["next_line"]["minimum_max_chars_for_single_line_request"]
        single = self.read([self.request("unicode.txt", 1, 1)], max_chars=minimum)
        self.assertEqual(single["status"], "complete")
        self.assertLessEqual(len(reader.encode(single)), minimum)
        self.assertEqual(single["items"][0]["lines"][0]["text"], 'a"\\\t' + "\u2603\U0001f642" * 100)
        command = [sys.executable, "-B", str(Path(reader.__file__)), "--root", str(self.root), "--revision", self.revision,
                   "--request", "-", "--max-chars", str(minimum)]
        cli = subprocess.run(command, input=json.dumps([self.request("unicode.txt", 1, 1)]).encode("utf-8"), capture_output=True)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertEqual(cli.stdout, reader.encode(single).encode("ascii"))
        self.assertLessEqual(len(cli.stdout), minimum)

    def test_large_line_is_unread_not_truncated_and_can_be_retried(self):
        result = self.read([self.request("large.txt", 1, 2)], max_chars=1200)
        item = result["items"][0]
        self.assertEqual(item["lines"], [])
        self.assertEqual(item["remaining"], [[1, 2]])
        self.assertEqual(item["next_line"]["number"], 1)
        self.assertEqual(item["next_line"]["serialized_line_chars"], len(reader.encode({"number": 1, "text": "x" * 6000, "redacted": False})) - 1)
        result = self.read([self.request("large.txt", 1, 2)], max_chars=10000)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["items"][0]["lines"][0]["text"], "x" * 6000)

    def test_response_budget_preserves_delivery_and_all_pending_ranges(self):
        self.write("many.txt", "".join(f"line {number} " + "x" * 120 + "\n" for number in range(1, 31)))
        self.git("add", "many.txt")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "many lines")
        revision = self.git("rev-parse", "HEAD").strip()
        result = reader.read_ranges(self.root, revision, [self.request("many.txt", 1, 30)], 1600)
        item = result["items"][0]
        self.assertEqual(result["status"], "partial")
        self.assertTrue(item["lines"])
        self.assertLessEqual(len(reader.encode(result)), 1600)
        last = item["lines"][-1]["number"]
        self.assertEqual(item["delivered"], [[1, last]])
        self.assertEqual(item["remaining"], [[last + 1, 30]])
        self.assertEqual(item["next_line"]["reason"], "response_budget")

    def test_mixed_errors_never_imply_complete_or_hide_success(self):
        result = self.read([self.request(start=3, end=9), self.request("missing.txt", 1, 1), self.request("other.txt", 1, 1)])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["items"][0]["delivered"], [[3, 5]])
        self.assertEqual(result["items"][0]["requested"], [[3, 9]])
        self.assertEqual(result["items"][0]["effective"], [[3, 5]])
        self.assertEqual(result["items"][0]["eof_clipped"], [[3, 9]])
        self.assertEqual(result["items"][0]["source_line_count"], 5)
        self.assertEqual(result["items"][0]["remaining"], [])
        self.assertEqual(result["items"][0]["status"], "complete")
        self.assertEqual(result["items"][1]["status"], "failed")
        self.assertEqual(result["items"][2]["status"], "complete")

    def test_start_past_eof_and_empty_source_are_explicit_failures(self):
        for request, code in ((self.request(start=8, end=9), "requested_start_past_eof"),
                              (self.request("empty.txt", 1, 1), "empty_source_file")):
            result = self.read([request])
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["items"][0]["error"], code)
            self.assertEqual(result["items"][0]["effective"], [])
            self.assertEqual(result["items"][0]["unavailable"], [[request["start"], request["end"]]])

    def test_invalid_paths_ranges_revisions_roots_and_object_types(self):
        for path in ("../sample.txt", "x/../sample.txt", "/sample.txt", "C:/sample.txt", "a\\b", "-config", ":(glob)*", "sample.txt\n", "./sample.txt"):
            with self.subTest(path=path):
                result = self.read([self.request(path, 1, 1)])
                self.assertEqual(result["status"], "failed")
        for start, end in ((0, 1), (2, 1), (True, 2), (1, "2")):
            self.assertEqual(self.read([self.request(start=start, end=end)])["status"], "failed")
        for revision in ("HEAD", self.revision[:12], "--help", "g" * 40, "0" * 40):
            self.assertEqual(reader.read_ranges(self.root, revision, [self.request()])["status"], "failed")
        blob = self.git("rev-parse", self.revision + ":sample.txt").strip()
        self.assertEqual(reader.read_ranges(self.root, blob, [self.request()])["error"], "revision_is_not_commit")
        (self.root / "child").mkdir()
        self.assertEqual(reader.read_ranges(self.root / "child", self.revision, [self.request()])["error"], "root_must_be_repository_toplevel")

    def test_git_is_offline_and_full_sha256_identity_is_required(self):
        with patch.dict(os.environ, {"GIT_DIR": "unrelated-repository", "GIT_ALLOW_PROTOCOL": "https:file:ext"}):
            with patch.object(reader.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"commit", b"")) as run:
                reader._git(self.root, "cat-file", "-t", self.revision)
                env = run.call_args.kwargs["env"]
                self.assertEqual(env["GIT_ALLOW_PROTOCOL"], "")
                self.assertEqual(env["GIT_NO_LAZY_FETCH"], "1")
                self.assertNotIn("GIT_DIR", env)
                self.assertIn("--no-replace-objects", run.call_args.args[0])
        full = "a" * 64
        with patch.object(reader, "_git", side_effect=[str(self.root).encode("utf-8"), b"commit", full.encode("ascii")]):
            result = reader.read_ranges(self.root, full[:40], [self.request()])
        self.assertEqual(result["error"], "revision_requires_full_commit_hash")

    def test_redaction_preserves_original_line_numbers_including_multiline(self):
        result = self.read([self.request("secrets.txt", 1, 9)])
        serialized = reader.encode(result)
        self.assertNotIn("synthetic", serialized)
        self.assertNotIn("suffix", serialized)
        lines = result["items"][0]["lines"]
        self.assertEqual([line["number"] for line in lines], list(range(1, 10)))
        self.assertEqual(lines[5]["text"], "after")
        self.assertEqual(lines[8]["text"], "tail")
        self.assertEqual([line["number"] for line in lines if line["redacted"]], [2, 3, 4, 5, 7, 8])
        # Requesting just a private-key body still needs surrounding context.
        middle = self.read([self.request("secrets.txt", 4, 4)])
        self.assertEqual(middle["items"][0]["lines"][0]["text"], reader.common.MASK)

    def test_yaml_python_and_javascript_multiline_secret_bodies_are_masked(self):
        for path, total in (("secret.yaml", 4), ("secret.py", 5), ("secret.js", 5)):
            with self.subTest(path=path):
                result = self.read([self.request(path, 1, total)])
                self.assertEqual(result["status"], "complete")
                self.assertNotIn("synthetic", reader.encode(result))
                lines = result["items"][0]["lines"]
                self.assertEqual([line["number"] for line in lines], list(range(1, total + 1)))
                self.assertEqual(lines[-1]["text"], "after")
                middle = self.read([self.request(path, 3, 3)])
                self.assertEqual(middle["items"][0]["lines"][0]["text"], reader.common.MASK)

    def test_credential_binary_and_non_utf8_files_are_explicit_failures(self):
        for path, error in ((".env", "credential_file_not_read"), ("binary.bin", "binary_blob_not_read"), ("nonutf8.txt", "non_utf8_blob_not_read")):
            result = self.read([self.request(path, 1, 1)])
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["items"][0]["error"], error)
            self.assertNotIn("synthetic", reader.encode(result))

    def test_request_metadata_overflow_leaves_entire_batch_unread(self):
        requests = [self.request("missing-" + str(index) + ".txt", 1, 1) for index in range(20)]
        result = self.read(requests, max_chars=1024)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["remaining"], "entire_request")
        self.assertEqual(result["failed_items"], 20)
        self.assertGreater(result["required_metadata_chars"], 1024)
        self.assertLessEqual(len(reader.encode(result)), 1024)

    def test_cli_stdin_file_invalid_json_and_state_cannot_skip_reads(self):
        command = [sys.executable, "-B", str(Path(reader.__file__)), "--root", str(self.root), "--revision", self.revision, "--request", "-"]
        result = subprocess.run(command, input=json.dumps([self.request(start=1, end=2)]), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["items"][0]["delivered"], [[1, 2]])
        self.write("request.json", json.dumps([self.request(start=1, end=1)]))
        result = subprocess.run(command[:-1] + [str(self.root / "request.json")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(command, input="not json", capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "failed")
        self.write("receipt.json", json.dumps({"revision": self.revision, "delivered": [[1, 99999]]}))
        result = subprocess.run(command + ["--state", str(self.root / "receipt.json")], input="[]", capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("unrecognized arguments: --state", result.stderr)
        self.assertEqual(self.read([self.request(start=1, end=1)])["items"][0]["delivered"], [[1, 1]])

    def test_compact_roundtrip_preserves_all_source_range_eof_and_error_metadata(self):
        requests = [self.request(start=1, end=2), self.request(start=5, end=10),
                    self.request(start=8, end=9), self.request("unicode.txt", 1, 2),
                    self.request("missing.txt", 1, 1), self.request("empty.txt", 1, 1),
                    self.request(".env", 1, 1), self.request("binary.bin", 1, 1),
                    self.request("nonutf8.txt", 1, 1), {"invalid": "request"}]
        verbose = self.read(requests)
        compact = self.read(requests, format="compact")
        self.assertEqual(self.read(requests, format="verbose"), verbose)
        self.assertEqual(self.expand_compact(compact), verbose)
        self.assertEqual(compact["items"][0]["lines"], [[1, "first"], [2, "second"], [5, "fifth"]])
        self.assertLess(len(reader.encode(compact)), len(reader.encode(verbose)))

    def test_compact_redaction_matches_verbose_including_context_outside_request(self):
        requests = [self.request("secrets.txt", 1, 9), self.request("secret.yaml", 3, 3),
                    self.request("secret.py", 3, 3), self.request("secret.js", 3, 3)]
        compact = self.read(requests, format="compact")
        self.assertEqual(self.expand_compact(compact), self.read(requests))
        serialized = reader.encode(compact)
        self.assertNotIn("synthetic", serialized)
        self.assertNotIn("suffix", serialized)
        lines = compact["items"][0]["lines"]
        self.assertEqual([line[0] for line in lines if len(line) == 3 and line[2] is True], [2, 3, 4, 5, 7, 8])
        self.assertEqual(lines[5], [6, "after"])
        self.assertEqual(lines[8], [9, "tail"])
        for item in compact["items"][1:]:
            self.assertEqual(item["lines"], [[3, reader.common.MASK, True]])

    def test_secret_assignment_expressions_mask_entire_lines_in_all_formats(self):
        source = ('secret: process.env.SIGNING_SECRET || "FAKE_FALLBACK",\n'
                  'password: enabled ? "FAKE_TRUE" : "FAKE_FALSE",\n'
                  'token: process.env.API_TOKEN ||\n'
                  '  "FAKE_CONTINUATION",\n'
                  'const api_key = env.API_KEY ?? "FAKE_NULLISH";\n'
                  'const endpoint = process.env.API_URL || "https://example.invalid";\n'
                  'const enabled = mode ? "safe-a" : "safe-b";\n'
                  'after\n')
        self.write("expressions.js", source)
        self.git("add", "expressions.js")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "synthetic secret expressions")
        revision = self.git("rev-parse", "HEAD").strip()
        for format in ("verbose", "compact", "text"):
            with self.subTest(format=format):
                result = reader.read_ranges(self.root, revision, [self.request("expressions.js", 1, 8)], format=format)
                self.assertNotIn("FAKE_", reader.encode(result))
                expanded = self.expand_compact(result) if format == "compact" else self.expand_text(result) if format == "text" else result
                self.assertEqual(expanded["status"], "complete")
                self.assertEqual(expanded["items"][0]["lines"],
                                 [{"number": number, "text": reader.common.MASK, "redacted": True} for number in range(1, 6)] +
                                 [{"number": number, "text": text, "redacted": False} for number, text in enumerate(source.splitlines()[5:], 6)])
                middle = reader.read_ranges(self.root, revision, [self.request("expressions.js", 4, 4)], format=format)
                middle = self.expand_compact(middle) if format == "compact" else self.expand_text(middle) if format == "text" else middle
                self.assertEqual(middle["items"][0]["lines"], [{"number": 4, "text": reader.common.MASK, "redacted": True}])

    def test_compact_oversized_line_estimates_match_format_and_exact_cli_budget(self):
        for format in ("verbose", "compact"):
            for path, text in (("large.txt", "x" * 6000), ("unicode.txt", 'a"\\\t' + "\u2603\U0001f642" * 100)):
                with self.subTest(format=format, path=path):
                    pending = self.read([self.request(path, 1, 2)], max_chars=1024, format=format)
                    item = pending["items"][0]
                    self.assertEqual(item["lines"], [])
                    self.assertEqual(item["remaining"], [[1, 2]])
                    pointer = item["next_line"]
                    self.assertEqual(pointer["reason"], "oversized_line")
                    expected_line = [1, text] if format == "compact" else {"number": 1, "text": text, "redacted": False}
                    self.assertEqual(pointer["serialized_line_chars"], len(json.dumps(expected_line, ensure_ascii=True, separators=(",", ":"))))
                    minimum = pointer["minimum_max_chars_for_single_line_request"]
                    command = [sys.executable, "-B", str(Path(reader.__file__)), "--root", str(self.root),
                               "--revision", self.revision, "--request", "-", "--format", format, "--max-chars"]
                    request = [self.request(path, 1, 1)]
                    for budget in (minimum - 1, minimum):
                        result = self.read(request, max_chars=budget, format=format)
                        cli = subprocess.run(command + [str(budget)], input=json.dumps(request).encode("utf-8"), capture_output=True)
                        self.assertEqual(cli.stdout, reader.encode(result).encode("ascii"))
                        self.assertLessEqual(len(cli.stdout), budget)
                        self.assertTrue(cli.stdout.endswith(b"\n"))
                        self.assertFalse(cli.stdout.endswith(b"\r\n"))
                        if budget == minimum:
                            self.assertEqual(cli.returncode, 0, cli.stderr)
                            self.assertEqual(len(cli.stdout), minimum)
                            self.assertEqual(result["items"][0]["lines"], [expected_line])
                        else:
                            self.assertEqual(cli.returncode, 1, cli.stderr)
                            self.assertEqual(result["items"][0]["remaining"], [[1, 1]])

    def test_compact_response_budget_retains_disjoint_pending_ranges(self):
        self.write("many.txt", "".join(f"line {number} " + "x" * 120 + "\n" for number in range(1, 31)))
        self.git("add", "many.txt")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "many lines")
        revision = self.git("rev-parse", "HEAD").strip()
        requests = [self.request("many.txt", 1, 15), self.request("many.txt", 20, 30)]
        result = reader.read_ranges(self.root, revision, requests, 1600, format="compact")
        item = result["items"][0]
        self.assertEqual(result["status"], "partial")
        self.assertTrue(item["lines"])
        self.assertLessEqual(len(reader.encode(result)), 1600)
        last = item["lines"][-1][0]
        self.assertEqual(item["lines"], [[number, f"line {number} " + "x" * 120] for number in range(1, last + 1)])
        self.assertEqual(item["delivered"], [[1, last]])
        self.assertEqual(item["remaining"], [[last + 1, 15], [20, 30]])
        self.assertEqual(item["next_line"]["reason"], "response_budget")
        retry = reader.read_ranges(self.root, revision, [self.request("many.txt", start, end) for start, end in item["remaining"]], format="compact")
        self.assertEqual(retry["status"], "complete")
        self.assertEqual(retry["items"][0]["delivered"], item["remaining"])
        self.assertEqual([line[0] for line in item["lines"] + retry["items"][0]["lines"]], list(range(1, 16)) + list(range(20, 31)))

    def test_compact_metadata_overflow_and_global_failures_stay_explicit(self):
        requests = [self.request("missing-" + str(index) + ".txt", 1, 1) for index in range(20)]
        result = self.read(requests, max_chars=1024, format="compact")
        verbose = self.read(requests, max_chars=1024)
        self.assertEqual(result["error"], "request_metadata_exceeds_budget")
        self.assertEqual(result["remaining"], "entire_request")
        self.assertEqual(result["failed_items"], 20)
        self.assertEqual(result["request_count"], 20)
        self.assertGreater(result["required_metadata_chars"], verbose["required_metadata_chars"])
        self.assertLessEqual(len(reader.encode(result)), 1024)
        for revision, request in (("HEAD", [self.request()]), (self.revision, [])):
            compact = reader.read_ranges(self.root, revision, request, format="compact")
            verbose = reader.read_ranges(self.root, revision, request)
            self.assertEqual(self.expand_compact(compact), verbose)
        command = [sys.executable, "-B", str(Path(reader.__file__)), "--root", str(self.root),
                   "--revision", self.revision, "--request", "-", "--format", "compact", "--max-chars", "1024"]
        cli = subprocess.run(command, input=b"not json", capture_output=True)
        self.assertEqual(cli.returncode, 2)
        self.assertEqual(json.loads(cli.stdout), {"format": "compact", "status": "failed", "error": "invalid_or_unreadable_request_json", "remaining": "entire_request"})
        self.assertLessEqual(len(cli.stdout), 1024)
        with self.assertRaisesRegex(ValueError, "format must be verbose or compact"):
            self.read(format="unknown")

    def test_text_roundtrip_preserves_identity_source_metadata_and_redaction(self):
        requests = [self.request(start=1, end=2), self.request(start=5, end=10),
                    self.request(start=8, end=9), self.request("unicode.txt", 1, 2),
                    self.request("missing.txt", 1, 1), self.request("empty.txt", 1, 1),
                    self.request(".env", 1, 1), self.request("binary.bin", 1, 1),
                    self.request("nonutf8.txt", 1, 1), {"invalid": "request"},
                    self.request("secrets.txt", 1, 9), self.request("secret.yaml", 3, 3),
                    self.request("secret.py", 3, 3), self.request("secret.js", 3, 3)]
        result = self.read(requests, max_chars=20000, format="text")
        self.assertEqual(self.expand_text(result), self.read(requests, max_chars=20000))
        self.assertNotIn(b"synthetic", reader.encode_bytes(result))
        self.assertNotIn(b"suffix", reader.encode_bytes(result))

    def test_text_preserves_literal_whitespace_and_escapes_controls_without_record_spoofing(self):
        source = ['const message = "hello"; // \\path', "\t  spaced\ttext  ", "", "END",
                  'ITEM {"status":"complete"}', "SOURCE_SLICE_TEXT_V1", "RESULT {}",
                  "ordinary \u2603\U0001f642", "escape\x1b[2Jbody", "back\bspace\rreturn",
                  "control\x01\x7f\x85end", "bidi\u202evalue\u2066end", "separator\u2028\u2029end"]
        self.write("controls.txt", "\n".join(source) + "\n")
        self.git("add", "controls.txt")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "text framing fixture")
        revision = self.git("rev-parse", "HEAD").strip()
        request = [self.request("controls.txt", 1, len(source))]
        text = reader.read_ranges(self.root, revision, request, format="text")
        wire = reader.encode_bytes(text)
        self.assertEqual(self.expand_text(wire), reader.read_ranges(self.root, revision, request))
        self.assertEqual([line["text"] for line in text["items"][0]["lines"]], source)
        self.assertIn(('1\t' + source[0] + "\n").encode("utf-8"), wire)
        self.assertIn(b"2\t\t  spaced\ttext  \n3\t\n4\tEND\n", wire)
        for number in range(9, len(source) + 1):
            self.assertIn(f"{number}J\t".encode("ascii"), wire)
        for control in (b"\x1b", b"\b", b"\r", b"\x01", b"\x7f", "\u202e".encode("utf-8")):
            self.assertNotIn(control, wire)
        with self.assertRaises(AssertionError):
            self.expand_text(wire.removesuffix(b"END\n"))

    def test_text_retry_estimates_and_cli_budget_measure_exact_utf8_bytes(self):
        controls = "\x1b" * 300 + "\u2603" * 20
        self.write("control-large.txt", controls + "\n")
        self.git("add", "control-large.txt")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "large escaped line fixture")
        self.revision = self.git("rev-parse", "HEAD").strip()
        for path, value, encoding in (("large.txt", "x" * 6000, "T"),
                                      ("unicode.txt", 'a"\\\t' + "\u2603\U0001f642" * 100, "T"),
                                      ("control-large.txt", controls, "J")):
            with self.subTest(path=path):
                pending = self.read([self.request(path, 1, 2)], max_chars=1024, format="text")
                pointer = pending["items"][0]["next_line"]
                self.assertEqual(pointer["reason"], "oversized_line")
                payload = json.dumps(value, ensure_ascii=True) if encoding == "J" else value
                prefix = "1J" if encoding == "J" else "1"
                self.assertEqual(pointer["serialized_line_chars"], len(f"{prefix}\t{payload}".encode("utf-8")))
                minimum = pointer["minimum_max_chars_for_single_line_request"]
                command = [sys.executable, "-B", str(Path(reader.__file__)), "--root", str(self.root),
                           "--revision", self.revision, "--range", path + ":1:1", "--format", "text", "--max-bytes"]
                for budget in (minimum - 1, minimum):
                    result = self.read([self.request(path, 1, 1)], max_chars=budget, format="text")
                    cli = subprocess.run(command + [str(budget)], capture_output=True)
                    self.assertEqual(cli.stdout, reader.encode_bytes(result))
                    self.assertLessEqual(len(cli.stdout), budget)
                    self.assertTrue(cli.stdout.endswith(b"END\n"))
                    self.assertNotIn(b"\r\n", cli.stdout)
                    decoded = self.expand_text(cli.stdout)
                    self.assertEqual(cli.returncode, 0 if budget == minimum else 1, cli.stderr)
                    if budget == minimum:
                        self.assertEqual(len(cli.stdout), minimum)
                        self.assertEqual(decoded["items"][0]["lines"], [{"number": 1, "text": value, "redacted": False}])
                    else:
                        self.assertEqual(decoded["items"][0]["remaining"], [[1, 1]])
                if path == "unicode.txt":
                    self.assertGreater(len(cli.stdout), len(cli.stdout.decode("utf-8")))

    def test_text_budget_preserves_disjoint_pending_ranges_and_failed_items(self):
        self.write("many.txt", "".join(f"line {number} " + "x" * 120 + "\n" for number in range(1, 31)))
        self.git("add", "many.txt")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "many text lines")
        revision = self.git("rev-parse", "HEAD").strip()
        requests = [self.request("many.txt", 1, 15), self.request("many.txt", 20, 30), self.request("missing.txt", 1, 1)]
        result = reader.read_ranges(self.root, revision, requests, 1900, format="text")
        decoded = self.expand_text(result)
        item = decoded["items"][0]
        self.assertEqual(decoded["status"], "partial")
        self.assertEqual(decoded["items"][1]["status"], "failed")
        self.assertTrue(item["lines"])
        self.assertLessEqual(len(reader.encode_bytes(result)), 1900)
        last = item["lines"][-1]["number"]
        self.assertEqual(item["remaining"], [[last + 1, 15], [20, 30]])
        retry = reader.read_ranges(self.root, revision, [self.request("many.txt", start, end) for start, end in item["remaining"]], format="text")
        self.assertEqual(retry["status"], "complete")
        self.assertEqual(retry["items"][0]["delivered"], item["remaining"])
        self.assertEqual([line["number"] for line in item["lines"] + self.expand_text(retry)["items"][0]["lines"]],
                         list(range(1, 16)) + list(range(20, 31)))

    def test_text_global_failures_and_metadata_overflow_remain_bounded(self):
        requests = [self.request("missing-" + str(index) + ".txt", 1, 1) for index in range(20)]
        result = self.read(requests, max_chars=1024, format="text")
        decoded = self.expand_text(result)
        self.assertEqual(decoded["error"], "request_metadata_exceeds_budget")
        self.assertEqual(decoded["remaining"], "entire_request")
        self.assertEqual(decoded["failed_items"], 20)
        self.assertEqual(decoded["request_count"], 20)
        self.assertGreater(decoded["required_metadata_chars"], 1024)
        self.assertLessEqual(len(reader.encode_bytes(result)), 1024)
        for revision, request in (("HEAD", [self.request()]), (self.revision, [])):
            text = reader.read_ranges(self.root, revision, request, format="text")
            self.assertEqual(self.expand_text(text), reader.read_ranges(self.root, revision, request))
        command = [sys.executable, "-B", str(Path(reader.__file__)), "--root", str(self.root),
                   "--revision", self.revision, "--request", "-", "--format", "text", "--max-bytes", "1024"]
        cli = subprocess.run(command, input=b"not json", capture_output=True)
        self.assertEqual(cli.returncode, 2)
        self.assertEqual(self.expand_text(cli.stdout), {"status": "failed", "error": "invalid_or_unreadable_request_json", "remaining": "entire_request"})
        self.assertLessEqual(len(cli.stdout), 1024)

    def test_inline_stdin_and_file_requests_have_identical_cli_results(self):
        self.write("folder/snow \u2603.txt", "snow\n")
        self.git("add", "folder")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "inline path fixture")
        revision = self.git("rev-parse", "HEAD").strip()
        requests = [self.request(start=1, end=2), self.request(start=2, end=3),
                    self.request(start=5, end=9), self.request("folder/snow \u2603.txt", 1, 1)]
        data = json.dumps(requests).encode("utf-8")
        self.write("request.json", data)
        for format in ("verbose", "compact", "text"):
            with self.subTest(format=format):
                command = [sys.executable, "-B", str(Path(reader.__file__)), "--root", str(self.root),
                           "--revision", revision, "--format", format]
                stdin = subprocess.run(command + ["--request", "-"], input=data, capture_output=True)
                file = subprocess.run(command + ["--request", str(self.root / "request.json")], capture_output=True)
                arguments = [arg for request in requests for arg in ("--range", f'{request["path"]}:{request["start"]}:{request["end"]}')]
                inline = subprocess.run(command + arguments, capture_output=True)
                self.assertEqual(stdin.returncode, 0, stdin.stderr)
                self.assertEqual(file.returncode, 0, file.stderr)
                self.assertEqual(inline.returncode, 0, inline.stderr)
                self.assertEqual(stdin.stdout, file.stdout)
                self.assertEqual(inline.stdout, file.stdout)
                expected = reader.read_ranges(self.root, revision, requests, format=format)
                self.assertEqual(inline.stdout, reader.encode_bytes(expected))

    def test_inline_invalid_syntax_paths_ranges_and_argument_exclusivity(self):
        command = [sys.executable, "-B", str(Path(reader.__file__)), "--root", str(self.root),
                   "--revision", self.revision, "--format", "text"]
        for value in ("synthetic-private-input", "sample.txt:1", "sample.txt:one:2", "sample.txt:-1:2",
                      "sample.txt:1:99999999999", "sample.txt:\u0661:2"):
            with self.subTest(value=value):
                cli = subprocess.run(command + ["--range", "sample.txt:1:1", "--range", value], capture_output=True)
                self.assertEqual(cli.returncode, 2, cli.stderr)
                decoded = self.expand_text(cli.stdout)
                self.assertEqual(decoded["status"], "failed")
                self.assertEqual(decoded["remaining"], "entire_request")
                self.assertNotIn("items", decoded)
                self.assertNotIn(b"synthetic", cli.stdout + cli.stderr)
        for value, error in (("sample.txt:0:2", "invalid_inclusive_line_range"),
                             ("sample.txt:2:1", "invalid_inclusive_line_range"),
                             ("sample.txt:1:2147483648", "invalid_inclusive_line_range"),
                             ("../sample.txt:1:1", "invalid_relative_path"),
                             ("sample.txt:1:2:3", "invalid_relative_path"),
                             (":1:1", "invalid_relative_path"),
                             (".env:1:1", "credential_file_not_read")):
            with self.subTest(value=value):
                cli = subprocess.run(command + ["--range", value], capture_output=True)
                self.assertEqual(cli.returncode, 2, cli.stderr)
                self.assertEqual(self.expand_text(cli.stdout)["items"][0]["error"], error)
        for arguments in ([], ["--range", "sample.txt:1:1", "--request", "-"]):
            cli = subprocess.run(command + arguments, input=b"[]", capture_output=True)
            self.assertEqual(cli.returncode, 2)
            self.assertEqual(cli.stdout, b"")

    def test_inline_request_size_limit_applies_to_complete_normalized_batch(self):
        values = ["folder/\u2603 one.txt:1:2", "other.txt:3:4"]
        expected = [self.request("folder/\u2603 one.txt", 1, 2), self.request("other.txt", 3, 4)]
        size = len(json.dumps(expected, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        with patch.object(reader, "MAX_REQUEST_BYTES", size):
            self.assertEqual(reader._inline_requests(values), expected)
        with patch.object(reader, "MAX_REQUEST_BYTES", size - 1):
            with self.assertRaisesRegex(reader.SourceError, "request_exceeds_256KiB_split_batch"):
                reader._inline_requests(values)
        with self.assertRaisesRegex(reader.SourceError, "request_exceeds_256KiB_split_batch"):
            reader._inline_requests(["x" * reader.MAX_REQUEST_BYTES + ":1:1"])

    def test_single_line_retry_minimum_includes_initial_pending_metadata_in_all_formats(self):
        # Keep metadata byte counts identical on Windows and Linux test hosts.
        root = PureWindowsPath("C:/synthetic-review-repository")
        path = "/".join(["x" * 100] * 5 + ["x" * 19])
        self.assertEqual(len(path), 524)
        lines = [{"number": number, "text": "x" * 50, "redacted": False} for number in (1, 2)]
        requests = [self.request(path, 1, 2), self.request("other.txt", 1, 1)]
        with patch.object(reader, "_identity", return_value=(root, self.revision)), \
                patch.object(reader, "_blob", return_value=("b" * 40, lines)):
            for format in ("verbose", "compact", "text"):
                with self.subTest(format=format):
                    budget = 1400 if format == "text" else 1380
                    batch = reader.read_ranges(root, self.revision, requests, budget, format=format)
                    self.assertEqual(batch["status"], "partial")
                    pointer = batch["items"][0]["next_line"]
                    minimum = pointer["minimum_max_chars_for_single_line_request"]
                    retry_request = [self.request(path, pointer["number"], pointer["number"])]
                    retry = reader.read_ranges(root, self.revision, retry_request, minimum, format=format)
                    self.assertEqual(retry["status"], "complete")
                    self.assertLessEqual(len(reader.encode_bytes(retry)), minimum)
                    expanded = self.expand_compact(retry) if format == "compact" else self.expand_text(retry) if format == "text" else retry
                    self.assertEqual(expanded["items"][0]["lines"], [lines[pointer["number"] - 1]])
                    if format == "text":
                        self.assertEqual(minimum, 1025)
                        too_small = reader.read_ranges(root, self.revision, retry_request, minimum - 1, format=format)
                        self.assertEqual(too_small["error"], "request_metadata_exceeds_budget")
                        self.assertEqual(too_small["required_metadata_chars"], minimum)


if __name__ == "__main__":
    unittest.main()
