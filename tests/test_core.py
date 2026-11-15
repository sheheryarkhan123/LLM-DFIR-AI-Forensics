import json
import unittest
from app.core import analyze, sha256, report_markdown, parse_time


class CoreTests(unittest.TestCase):
    def sample_event(self, event_id, stamp, *, host="WIN11", user="analyst"):
        return {"event_id": event_id, "timestamp": stamp, "host": host, "user": user}

    def test_hash_is_stable(self):
        self.assertEqual(sha256(b"test"), "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")

    def test_wazuh_parser(self):
        payload = [{"timestamp": "2026-01-01T00:00:00Z", "agent": {"name": "LAB"},
                    "data": {"win": {"system": {"eventID": "4720"}}}}]
        result = analyze(json.dumps(payload).encode(), "events.json")
        self.assertEqual(result["events"][0]["event_id"], "4720")
        self.assertEqual(result["events"][0]["severity"], "medium")
        self.assertIn("EV-00001", report_markdown(result))

    def test_csv(self):
        result = analyze(b"event_id,timestamp,host\n4625,2026-01-01T00:00:00Z,WIN11\n", "events.csv")
        self.assertEqual(result["count"], 1)

    def test_jsonl(self):
        result = analyze(b'{"event_id":"4625"}\n{"event_id":"4624"}\n', "events.jsonl")
        self.assertEqual(result["count"], 2)

    def test_unsupported(self):
        with self.assertRaises(ValueError):
            analyze(b"hello", "file.txt")

    def test_utc_timestamp_sorting(self):
        items = [
            self.sample_event("4624", "2026-01-01T11:00:00+02:00"),
            self.sample_event("4625", "2026-01-01T08:30:00Z"),
        ]
        result = analyze(json.dumps(items).encode(), "events.json")
        self.assertEqual([e["event_id"] for e in result["events"]], ["4625", "4624"])
        self.assertEqual(result["events"][1]["timestamp"], "2026-01-01T09:00:00Z")

    def test_naive_time_not_treated_as_utc(self):
        result = analyze(json.dumps([self.sample_event("4625", "2026-01-01T09:00:00")]).encode(), "events.json")
        self.assertEqual(result["unverified_timestamps"], 1)
        self.assertIsNone(parse_time("2026-01-01T09:00:00"))

    def test_sequence_lead(self):
        items = [
            self.sample_event("4625", "2026-01-01T10:00:00Z"),
            self.sample_event("4624", "2026-01-01T10:03:00Z"),
            self.sample_event("4720", "2026-01-01T10:10:00Z"),
            self.sample_event("4732", "2026-01-01T10:11:00Z"),
        ]
        result = analyze(json.dumps(items).encode(), "events.json")
        # Without a membership SID, 4720→4732 is intentionally NOT correlated.
        self.assertEqual(len(result["sequences"]), 1)
        self.assertEqual(result["sequences"][0]["elapsed_minutes"], 3.0)

    def test_sequence_same_user_host_required(self):
        items = [
            self.sample_event("4625", "2026-01-01T10:00:00Z", host="A", user="X"),
            self.sample_event("4624", "2026-01-01T10:03:00Z", host="B", user="X"),
        ]
        result = analyze(json.dumps(items).encode(), "events.json")
        self.assertEqual(result["sequences"], [])

    def test_sequence_outside_window(self):
        items = [
            self.sample_event("4625", "2026-01-01T10:00:00Z"),
            self.sample_event("4624", "2026-01-01T11:00:00Z"),
        ]
        result = analyze(json.dumps(items).encode(), "events.json")
        self.assertEqual(result["sequences"], [])

    def test_report_contains_hash_and_notes(self):
        result = analyze(json.dumps([self.sample_event("4625", "2026-01-01T10:00:00Z")]).encode(), "events.json")
        report = report_markdown(result, "Need to check authentication ticket")
        self.assertIn(result["sha256"], report)
        self.assertIn("Need to check authentication ticket", report)

    def test_limit(self):
        with self.assertRaises(ValueError):
            analyze(b"a" * (15 * 1024 * 1024 + 1), "oversized.csv")


if __name__ == "__main__":
    unittest.main()
