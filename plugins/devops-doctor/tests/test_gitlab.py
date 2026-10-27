"""Offline regression tests: no GitLab, network, credentials, or cloud access."""
from __future__ import annotations
import argparse
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import gitlab_mr_fast_review as fast
import gitlab_mr_snapshot as mr
import gitlab_pipeline_snapshot as pipeline


def ok(data):
    return {"ok": True, "data": data, "truncated": False, "returncode": 0}


def mr_fixture():
    return {"state": "opened", "sha": "a" * 40, "changes_count": "1",
            "diff_refs": {"head_sha": "a" * 40, "base_sha": "b" * 40, "start_sha": "c" * 40}}


def version_fixture():
    return {"id": 7, "state": "collected", "head_commit_sha": "a" * 40,
            "base_commit_sha": "b" * 40, "start_commit_sha": "c" * 40,
            "diffs": [{"old_path": "main.py", "new_path": "main.py", "a_mode": "100644", "b_mode": "100644",
                       "diff": "@@ -1 +1 @@\n-before\n+after\n"}]}


class ExecutableDiscoveryTests(unittest.TestCase):
    def test_path_is_default(self):
        with patch.dict(mr.os.environ, {}, clear=True), patch.object(mr.shutil, "which", return_value="/usr/bin/glab") as which:
            self.assertEqual("/usr/bin/glab", mr.find_glab())
            which.assert_called_once_with("glab")

    def test_explicit_executable_overrides_path(self):
        with patch.dict(mr.os.environ, {"DEVOPS_DOCTOR_GLAB": "/opt/tools/glab"}), \
             patch.object(mr.shutil, "which", return_value="/opt/tools/glab") as which:
            self.assertEqual("/opt/tools/glab", mr.find_glab())
            which.assert_called_once_with("/opt/tools/glab")

    def test_invalid_override_does_not_fall_back(self):
        with patch.dict(mr.os.environ, {"DEVOPS_DOCTOR_GLAB": "/missing/glab"}), \
             patch.object(mr.shutil, "which", return_value=None) as which:
            self.assertIsNone(mr.find_glab())
            which.assert_called_once_with("/missing/glab")


class MergeReadinessTests(unittest.TestCase):
    def test_missing_and_non_success_ci_block(self):
        for statuses in ([], ["running"], ["pending"], ["manual"], ["skipped"], ["failed"], ["success", "canceled"]):
            with self.subTest(statuses=statuses):
                _, verdict, reasons = fast.score_review([], statuses, "opened")
                self.assertTrue(verdict.startswith("Blocked"))
                self.assertTrue(reasons)

    def test_incomplete_evidence_blocks_even_successful_ci(self):
        _, verdict, _ = fast.score_review([], ["success"], "opened", evidence_complete=False)
        self.assertTrue(verdict.startswith("Blocked"))

    def test_success_is_review_required_not_merge_authorization(self):
        _, verdict, reasons = fast.score_review([], ["success"], "opened")
        self.assertEqual("Evidence checks passed; review required", verdict)
        self.assertEqual([], reasons)

    def test_old_sha_pipeline_does_not_validate_head(self):
        self.assertEqual([], fast.ci_for_head(ok([]), ok([{"id": 4, "sha": "old", "status": "success"}]), "head"))

    def test_newest_pipeline_and_status_attempt_win(self):
        statuses = ok([{"id": 1, "name": "test", "status": "failed", "sha": "head"},
                       {"id": 2, "name": "test", "status": "success", "sha": "head"}])
        pipelines = ok([{"id": 5, "sha": "head", "status": "success"},
                        {"id": 7, "sha": "old", "status": "success"},
                        {"id": 6, "sha": "head", "status": "running"}])
        self.assertEqual(["success", "running"], fast.ci_for_head(statuses, pipelines, "head"))

    def test_main_missing_diff_blocks_with_successful_ci(self):
        args = argparse.Namespace(repo="group/repo", mr_iid="1", max_workers=2, max_pages=2, output=None)
        first = {"merge_request": ok(mr_fixture()), "latest_diff_version": ok([version_fixture()]),
                 "pipelines": ok([{"sha": "a" * 40, "id": 1, "status": "success"}])}
        second = {"statuses": ok([]), "diff": {"ok": False, "error": "403 forbidden"}}
        output = io.StringIO()
        with patch.object(fast, "parse_args", return_value=args), patch.object(fast, "find_glab", return_value="glab"), \
             patch.object(fast, "run_glab", side_effect=[ok("authenticated"), ok(mr_fixture())]), \
             patch.object(fast, "run_glab_tasks", side_effect=[first, second]), contextlib.redirect_stdout(output):
            code = fast.main()
        result = json.loads(output.getvalue())
        self.assertNotEqual(0, code)
        self.assertTrue(result["summary"]["verdict"].startswith("Blocked"))
        self.assertIn("diff", [item["scope"] for item in result["blockers"]])

    def test_auth_failure_stops_every_gitlab_entrypoint(self):
        args = argparse.Namespace(repo="group/repo", mr_iid="1", output=None)
        for module in (fast, mr, pipeline):
            with self.subTest(module=module.__name__), patch.object(module, "parse_args", return_value=args), \
                 patch.object(module, "find_glab", return_value="glab"), \
                 patch.object(module, "run_glab", return_value={"ok": False, "error": "authentication failed"}) as read, \
                 patch.object(module, "run_glab_tasks") as fetch, contextlib.redirect_stdout(io.StringIO()):
                self.assertNotEqual(0, module.main())
                read.assert_called_once()
                fetch.assert_not_called()


class RevisionConsistencyTests(unittest.TestCase):
    def review(self, *, metadata=None, latest=None, diff=None, final=None):
        args = argparse.Namespace(repo="group/repo", mr_iid="1", max_workers=2, max_pages=2, output=None)
        version = version_fixture()
        first = {"merge_request": ok(mr_fixture() if metadata is None else metadata),
                 "latest_diff_version": ok([{key: value for key, value in version.items() if key != "diffs"}]) if latest is None else latest,
                 "pipelines": ok([{"sha": "a" * 40, "id": 1, "status": "success"}])}
        second = {"statuses": ok([]), "diff": ok(version) if diff is None else diff}
        output = io.StringIO()
        with patch.object(fast, "parse_args", return_value=args), patch.object(fast, "find_glab", return_value="glab"), \
             patch.object(fast, "run_glab", side_effect=[ok("authenticated"), ok(mr_fixture()) if final is None else final]) as read, \
             patch.object(fast, "run_glab_tasks", side_effect=[first, second]) as fetch, contextlib.redirect_stdout(output):
            code = fast.main()
        return code, json.loads(output.getvalue()), fetch.call_args_list, read.call_args_list

    def assert_incomplete(self, outcome, scope):
        code, result, _, _ = outcome
        self.assertEqual(1, code)
        self.assertFalse(result["collection"]["complete"])
        self.assertTrue(result["summary"]["verdict"].startswith("Blocked"))
        self.assertIn(scope, [item["scope"] for item in result["blockers"]])

    def test_stable_revision_uses_pinned_diff_and_one_final_check(self):
        code, result, fetches, reads = self.review()
        self.assertEqual(0, code)
        self.assertTrue(result["collection"]["complete"])
        self.assertEqual(mr_fixture()["diff_refs"], result["evidence"]["diff_refs"])
        self.assertEqual(7, result["evidence"]["diff_version_id"])
        self.assertEqual(["main.py"], result["evidence"]["changed_paths"])
        self.assertEqual(2, len(fetches))
        tasks = fetches[1].args[1]
        self.assertEqual(["api", "projects/group%2Frepo/merge_requests/1/versions/7"], tasks["diff"][0])
        self.assertIn("/commits/" + "a" * 40 + "/statuses", tasks["statuses"][0][1])
        self.assertEqual(2, len(reads))
        self.assertEqual(["api", "projects/group%2Frepo/merge_requests/1"], reads[-1].args[1])

    def test_mixed_version_refs_block_even_when_file_count_and_ci_match(self):
        for ref in ("head_commit_sha", "base_commit_sha", "start_commit_sha"):
            with self.subTest(ref=ref):
                diff = version_fixture()
                diff[ref] = "d" * 40
                self.assert_incomplete(self.review(diff=ok(diff)), "diff")

    def test_changed_or_missing_final_refs_block(self):
        for ref in ("head_sha", "base_sha", "start_sha", "missing"):
            with self.subTest(ref=ref):
                final = mr_fixture()
                if ref == "missing":
                    del final["diff_refs"]
                else:
                    final["diff_refs"][ref] = "d" * 40
                    if ref == "head_sha":
                        final["sha"] = "d" * 40
                self.assert_incomplete(self.review(final=ok(final)), "revision_check")

    def test_missing_initial_refs_stops_dependent_reads(self):
        for ref in ("head_sha", "base_sha", "start_sha"):
            with self.subTest(ref=ref):
                metadata = mr_fixture()
                del metadata["diff_refs"][ref]
                outcome = self.review(metadata=metadata)
                self.assert_incomplete(outcome, "merge_request")
                self.assertEqual(1, len(outcome[2]))
                self.assertEqual(1, len(outcome[3]))

    def test_stale_or_unverifiable_version_lookup_stops_dependent_reads(self):
        for change in ({"head_commit_sha": "d" * 40}, {"base_commit_sha": None}, {"id": None}, {"state": "overflow"}):
            with self.subTest(change=change):
                version = version_fixture()
                version.update(change)
                outcome = self.review(latest=ok([version]))
                self.assert_incomplete(outcome, "latest_diff_version")
                self.assertEqual(1, len(outcome[2]))
                self.assertEqual(1, len(outcome[3]))

    def test_missing_or_mismatched_diff_provenance_blocks(self):
        for change in ({"head_commit_sha": None}, {"base_commit_sha": None}, {"start_commit_sha": None}, {"id": 8}, {"state": "overflow"}):
            with self.subTest(change=change):
                version = version_fixture()
                version.update(change)
                self.assert_incomplete(self.review(diff=ok(version)), "diff")

    def test_omitted_diff_content_blocks(self):
        for change in ({"too_large": True}, {"collapsed": True}, {"diff": None}, {"diff": ""}):
            with self.subTest(change=change):
                version = version_fixture()
                version["diffs"][0].update(change)
                self.assert_incomplete(self.review(diff=ok(version)), "diff")

    def test_final_fetch_failure_and_changed_review_state_block(self):
        self.assert_incomplete(self.review(final={"ok": False, "error": "403 forbidden"}), "revision_check")
        for change in ({"draft": True}, {"has_conflicts": True}, {"state": "closed"}):
            with self.subTest(change=change):
                final = mr_fixture()
                final.update(change)
                code, result, _, _ = self.review(final=ok(final))
                self.assertNotEqual(0, code)
                self.assertTrue(result["summary"]["verdict"].startswith("Blocked"))


class PagingTests(unittest.TestCase):
    def test_collects_failure_on_second_page(self):
        first = [{"id": i, "status": "success"} for i in range(100)]
        second = [{"id": 100, "status": "failed"}]
        with patch.object(mr, "run_glab", side_effect=[ok(first), ok(second)]) as read:
            result = mr.run_glab_pages("glab", "projects/test/pipelines/1/jobs", max_pages=2)
        self.assertEqual(101, len(result["data"]))
        self.assertTrue(result["complete"])
        self.assertEqual([100], [row["id"] for row in pipeline.summarize_jobs(result)["failed"]])
        self.assertIn("page=2", read.call_args_list[1].args[1][1])

    def test_page_cap_is_partial_not_empty_success(self):
        with patch.object(mr, "run_glab", return_value=ok([{}] * 100)):
            result = mr.run_glab_pages("glab", "projects/test/jobs", max_pages=1)
        self.assertTrue(result["truncated"])
        self.assertFalse(result["complete"])
        self.assertTrue(mr.result_blockers({"jobs": result}))

    def test_page_error_preserves_partial_rows_and_fails(self):
        with patch.object(mr, "run_glab", side_effect=[ok([{}] * 100), {"ok": False, "error": "timeout"}]):
            result = mr.run_glab_pages("glab", "projects/test/jobs", max_pages=2)
        self.assertFalse(result["ok"])
        self.assertEqual(100, len(result["data"]))
        self.assertEqual("timeout", result["error"])

    def test_non_list_response_fails(self):
        with patch.object(mr, "run_glab", return_value=ok({"message": "bad response"})):
            self.assertFalse(mr.run_glab_pages("glab", "projects/test/jobs")["ok"])

    def test_malformed_list_item_fails(self):
        with patch.object(mr, "run_glab", return_value=ok([None])):
            self.assertFalse(mr.run_glab_pages("glab", "projects/test/jobs")["ok"])

    def test_server_omitted_diff_is_partial(self):
        result = mr.validate_diffs(ok([{"new_path": "big.py", "too_large": True}]))
        self.assertFalse(result["complete"])
        self.assertTrue(result["truncated"])


class TraceTests(unittest.TestCase):
    def test_successful_commands_do_not_become_failure_causes(self):
        trace = "pip install completed successfully\npytest: 120 passed\ndocker build successful\nDeploy finished successfully"
        self.assertEqual([], pipeline.classify_trace(trace, failed=True))

    def test_actual_error_requires_failed_job(self):
        trace = "npm ERR! ERESOLVE unable to resolve dependency tree"
        self.assertEqual([], pipeline.classify_trace(trace))
        findings = pipeline.classify_trace(trace, failed=True)
        self.assertEqual("dependency_install", findings[0]["code"])
        self.assertEqual(1, findings[0]["evidence"][0]["line"])

    def test_successful_job_cannot_get_failure_candidate(self):
        job = ok({"id": 1, "status": "success", "failure_reason": "stale"})
        self.assertEqual([], pipeline.build_root_cause_candidates(job, "AssertionError: example", {"failed": []}))

    def test_failed_job_keeps_failure_reason_and_error_evidence(self):
        job = ok({"id": 1, "name": "test", "status": "failed", "failure_reason": "script_failure"})
        candidates = pipeline.build_root_cause_candidates(job, "AssertionError: expected 2", {"failed": []})
        self.assertEqual(["gitlab_failure_reason", "test_failure"], [row["category"] for row in candidates])


if __name__ == "__main__":
    unittest.main()
