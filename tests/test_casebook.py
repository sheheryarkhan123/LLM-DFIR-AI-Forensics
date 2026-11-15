"""Regression tests for the synthetic Wazuh casebook and event semantics."""
import json
import unittest
from pathlib import Path

from app.core import analyze, report_markdown

ROOT = Path(__file__).resolve().parents[1]


class CasebookTests(unittest.TestCase):
    def load(self, filename):
        fixture = ROOT / "samples" / filename
        payload = fixture.read_bytes()
        return analyze(payload, fixture.name)

    def test_case001_uses_member_sid_not_group_name(self):
        result = self.load("case_001_account_group_change.json")
        self.assertEqual(result["count"], 4)
        member = next(e for e in result["events"] if e["event_id"] == "4732")
        account = next(e for e in result["events"] if e["event_id"] == "4720")
        self.assertEqual(member["group_name"], "Administrators")
        self.assertEqual(member["target_user"], "Administrators")
        self.assertEqual(member["user"], member["member_sid"])
        self.assertNotEqual(member["target_user"], account["target_user"])
        self.assertEqual(member["member_sid"], account["target_sid"])
        self.assertEqual(len(result["sequences"]), 1)
        self.assertIn("SID match", result["sequences"][0]["sequence"])
        self.assertIn("EV-00001", report_markdown(result))

    def test_no_account_group_sequence_if_sid_differs(self):
        fixture = ROOT / "samples" / "case_001_account_group_change.json"
        raw = json.loads(fixture.read_text())
        raw[1]["data"]["win"]["eventdata"]["memberSid"] = "S-1-5-21-99999-9-9-9"
        result = analyze(json.dumps(raw).encode(), fixture.name)
        self.assertEqual(result["sequences"], [])

    def test_case002_has_authentication_lead(self):
        result = self.load("case_002_authentication_review.json")
        self.assertEqual(result["count"], 5)
        self.assertEqual(sum(e["event_id"] == "4625" for e in result["events"]), 4)
        self.assertEqual(len(result["sequences"]), 1)
        seq = result["sequences"][0]
        self.assertEqual((seq["first_evidence_id"], seq["second_evidence_id"]),
                         ("EV-00004", "EV-00005"))
        self.assertIn("not proof", seq["review_note"])

    def test_mismatched_source_ips_are_not_correlated(self):
        fixture = ROOT / "samples" / "case_002_authentication_review.json"
        raw = json.loads(fixture.read_text())
        raw[-1]["data"]["win"]["eventdata"]["ipAddress"] = "192.0.2.3"
        result = analyze(json.dumps(raw).encode(), fixture.name)
        self.assertEqual(result["sequences"], [])

    def test_fixture_hash_is_exact(self):
        fixture = ROOT / "samples" / "case_001_account_group_change.json"
        result = analyze(fixture.read_bytes(), fixture.name)
        generated = (ROOT / "cases" / "generated" / "case_001_report.md").read_text()
        self.assertIn(result["sha256"], generated)
        self.assertIn("SYNTHETIC TRAINING", generated)


if __name__ == "__main__":
    unittest.main()
