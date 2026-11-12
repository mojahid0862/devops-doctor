import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
