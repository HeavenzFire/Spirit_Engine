import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.unified_field_ledger import Ledger


class UnifiedFieldLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "state" / "events.sqlite3"
        self.ledger = Ledger(self.db)

    def test_new_ledger_verifies_empty(self):
        result = self.ledger.verify()
        self.assertTrue(result["ok"])
        self.assertEqual(result["events_checked"], 0)

    def test_append_is_persistent_and_canonical(self):
        first = self.ledger.append("task.created", {"z": 1, "a": "hello"})
        self.assertEqual(first["payload"], {"a": "hello", "z": 1})
        reopened = Ledger(self.db)
        result = reopened.verify()
        self.assertTrue(result["ok"])
        self.assertEqual(result["events_checked"], 1)
        self.assertEqual(reopened.list_events()[0]["event_id"], first["event_id"])

    def test_hash_chain_links_events(self):
        first = self.ledger.append("node.started", {"node": "local-1"})
        second = self.ledger.append("task.finished", {"ok": True})
        self.assertEqual(second["prev_hash"], first["event_hash"])
        self.assertTrue(self.ledger.verify()["ok"])

    def test_payload_tampering_is_detected(self):
        self.ledger.append("task.created", {"task": "safe"})
        with sqlite3.connect(self.db) as connection:
            connection.execute(
                "UPDATE events SET payload_json = ? WHERE seq = 1",
                (json.dumps({"task": "altered"}),),
            )
        result = self.ledger.verify()
        self.assertFalse(result["ok"])
        self.assertIn("event_hash_mismatch", [f["reason"] for f in result["failures"]])

    def test_export_contains_verification_evidence(self):
        self.ledger.append("sync.observed", {"peer_count": 1})
        target = Path(self.temp.name) / "export" / "ledger.json"
        count = self.ledger.export_json(target)
        exported = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(count, 1)
        self.assertEqual(exported["schema_version"], 1)
        self.assertTrue(exported["verification"]["ok"])
        self.assertEqual(len(exported["events"]), 1)

    def test_empty_kind_is_rejected(self):
        with self.assertRaises(ValueError):
            self.ledger.append("  ", {"x": 1})


if __name__ == "__main__":
    unittest.main()
