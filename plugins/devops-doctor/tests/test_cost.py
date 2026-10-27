import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import aws_cost_snapshot as cost


def response(amounts, unit="USD", estimated=False):
    return {"ok": True, "data": {"ResultsByTime": [
        {"TimePeriod": {"Start": f"2020-01-{index + 1:02}", "End": f"2020-01-{index + 2:02}"},
         "Estimated": estimated, "Groups": [{"Keys": ["Example Service"], "Metrics": {"UnblendedCost": {"Amount": amount, "Unit": unit}}}]}
        for index, amount in enumerate(amounts)]}}


class CostTests(unittest.TestCase):
    def test_decimal_currency_and_estimated_values(self):
        summary, _ = cost.summarize_cost(response(["0.1", "0.2"], estimated=True))
        self.assertEqual(summary["total"], "0.3")
        self.assertEqual(summary["currency"], "USD")
        self.assertTrue(summary["estimated"])

    def test_invalid_intervals_and_dimensions_are_rejected(self):
        cases = (["--days", "0"], ["--days", "367"], ["--start", "2020-01-01"],
                 ["--group-by", "SERVICE,REGION,OPERATION"], ["--group-by", "UNSUPPORTED"],
                 ["--start", "2020-02-01", "--end", "2020-01-01"],
                 ["--start", "2020-01-01", "--end", "2020-02-01", "--days", "14"])
        for argv in cases:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                cost.parse_args(argv)

    def test_pagination_and_service_filter(self):
        args = cost.parse_args(["--start", "2020-01-01", "--end", "2020-01-03", "--service", "Example Service"])
        first, second = response(["0.1"]), response(["0.2"])
        first["data"]["NextPageToken"] = "test-page-two"
        with patch.object(cost, "run", side_effect=[first, second]) as command:
            result = cost.fetch_cost(args, args.start, args.end)
        self.assertEqual(result["pages"], 2)
        self.assertFalse(result["truncated"])
        self.assertIn("--next-page-token", command.call_args_list[1].args[0])
        initial = command.call_args_list[0].args[0]
        self.assertEqual(json.loads(initial[initial.index("--filter") + 1])["Dimensions"]["Values"], ["Example Service"])
        self.assertEqual(cost.summarize_cost(result)[0]["total"], "0.3")

    def test_auth_failure_never_requests_costs(self):
        with patch.object(cost, "run", return_value={"ok": False, "error": "ExpiredToken"}), \
             patch.object(cost, "fetch_cost") as fetch:
            result = cost.build_report(cost.parse_args(["--days", "7"]))
        fetch.assert_not_called()
        self.assertEqual(result["status"], "failed")

    def test_equal_previous_interval_and_zero_baseline(self):
        args = cost.parse_args(["--start", "2020-01-08", "--end", "2020-01-15", "--compare-previous"])
        intervals = []
        def fetch(args, start, end):
            intervals.append((start.isoformat(), end.isoformat()))
            return response(["10" if start == args.start else "0"])
        with patch.object(cost, "run", return_value={"ok": True, "data": {"Account": "123456789012"}}), \
             patch.object(cost, "fetch_cost", side_effect=fetch):
            result = cost.build_report(args)
        self.assertCountEqual(intervals, [("2020-01-01", "2020-01-08"), ("2020-01-08", "2020-01-15")])
        comparison = result["summary"]["comparison"]
        self.assertEqual(comparison["changes"][0]["delta"], "10")
        self.assertIsNone(comparison["changes"][0]["percent_change"])

    def test_multiple_currencies_are_not_added(self):
        first = response(["1"], "USD")
        first["data"]["ResultsByTime"] += response(["2"], "EUR")["data"]["ResultsByTime"]
        summary, _ = cost.summarize_cost(first)
        self.assertTrue(summary["mixed_currencies"])
        self.assertIsNone(summary["total"])

    def test_two_dimensions_and_nonfinite_amount(self):
        result = response(["1"])
        result["data"]["ResultsByTime"][0]["Groups"][0]["Keys"].append("eu-west-1")
        summary, _ = cost.summarize_cost(result, ["SERVICE", "REGION"])
        self.assertEqual(summary["top_groups"][0]["dimensions"]["REGION"], "eu-west-1")
        with self.assertRaises(ValueError):
            cost.summarize_cost(response(["NaN"]))


if __name__ == "__main__":
    unittest.main()
