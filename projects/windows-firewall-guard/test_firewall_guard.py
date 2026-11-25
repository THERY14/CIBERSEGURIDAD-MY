import copy
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

import firewall_guard as fw


class AuditTests(unittest.TestCase):
    def test_default_outbound_is_reported(self):
        codes = [row["code"] for row in fw.audit(fw.DEMO)["findings"]]
        self.assertEqual(codes.count("OUTBOUND_DEFAULT_ALLOW"), 3)

    def test_rule_count_is_a_review_not_proof_of_exposure(self):
        result = fw.audit(fw.DEMO)
        self.assertIn({"level": "review", "code": "REVIEW_ALL_PROFILE_INBOUND_ALLOW_RULES"},
                      result["findings"])

    def test_disabled_and_allow_inbound_are_high(self):
        data = copy.deepcopy(fw.DEMO)
        data["profiles"][2].update(enabled="False", inbound="Allow")
        high = [x["code"] for x in fw.audit(data)["findings"] if x["level"] == "high"]
        self.assertEqual(high, ["FIREWALL_DISABLED", "INBOUND_DEFAULT_ALLOW"])

    def test_unknown_is_not_silently_assumed_safe(self):
        data = copy.deepcopy(fw.DEMO)
        data["profiles"][0]["outbound"] = "NotConfigured"
        result = fw.audit(data)
        self.assertEqual(result["profiles"][0]["outbound"], "Unknown")
        self.assertIn("PROFILE_SETTING_UNKNOWN", [x["code"] for x in result["findings"]])

    def test_missing_and_duplicate_profiles_rejected(self):
        for profiles in (fw.DEMO["profiles"][1:], fw.DEMO["profiles"] + fw.DEMO["profiles"]):
            with self.assertRaises(ValueError):
                fw.audit(dict(fw.DEMO, profiles=profiles))

    def test_invalid_counts_rejected(self):
        for bad in (True, -1, "3"):
            with self.assertRaises(ValueError):
                fw.audit(dict(fw.DEMO, outbound_block_rules=bad))

    def test_unknown_values_and_identifiers_do_not_leak(self):
        data = copy.deepcopy(fw.DEMO)
        data["profiles"][0].update(machine="secret-workstation", outbound="secret-raw")
        self.assertNotIn("secret-", json.dumps(fw.audit(data)))

    def test_demo_entry_point(self):
        with patch.object(fw, "run_windows", side_effect=AssertionError("unexpected query")):
            with patch("builtins.print") as output:
                self.assertEqual(fw.main(["--demo"]), 0)
            self.assertEqual(json.loads(output.call_args.args[0])["source"], "synthetic-demo")

    def test_windows_adapter_handles_json_and_suppresses_stderr(self):
        with patch.object(sys, "platform", "win32"), patch.object(fw.subprocess, "run") as run:
            run.return_value.stdout = json.dumps(fw.DEMO)
            self.assertEqual(fw.run_windows(), fw.DEMO)
            self.assertEqual(run.call_args.kwargs["timeout"], 30)
            self.assertNotIn("shell", run.call_args.kwargs)
            run.side_effect = subprocess.CalledProcessError(1, "powershell", stderr="secret")
            with self.assertRaisesRegex(RuntimeError, "^Could not query"):
                fw.run_windows()


if __name__ == "__main__":
    unittest.main()
