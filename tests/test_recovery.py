import json
import tempfile
import unittest
from pathlib import Path

from scripts.recovery import snapshot, verify, build_plan


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.destination = self.base / "snapshot"
        self.source.mkdir()
        (self.source / "hello.txt").write_text("hello recovery\n", encoding="utf-8")
        (self.source / ".env").write_text("SECRET=must-not-copy\n", encoding="utf-8")
        (self.source / "node_modules").mkdir()
        (self.source / "node_modules" / "ignored.js").write_text("ignored", encoding="utf-8")
        self.policy = {
            "schema_version": 1,
            "source_roots": [str(self.source)],
            "destination_root": str(self.destination),
            "exclude_directory_names": [".git", "node_modules", "__pycache__"],
            "exclude_file_names": [".env"],
            "exclude_extensions": [".key", ".pem"],
            "max_file_size_mb": 2,
            "copy_symlinks": False,
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_plan_excludes_secrets_and_dependency_trees(self):
        entries, _ = build_plan(self.policy)
        names = [Path(entry["source"]).name for entry in entries]
        self.assertEqual(names, ["hello.txt"])

    def test_snapshot_and_verify(self):
        manifest_path = snapshot(self.policy, self.destination)
        self.assertTrue(manifest_path.is_file())
        checked, byte_count, failures = verify(self.destination)
        self.assertEqual(checked, 1)
        self.assertGreater(byte_count, 0)
        self.assertEqual(failures, [])
        self.assertFalse((self.destination / "root-0" / ".env").exists())

    def test_tampering_is_detected(self):
        snapshot(self.policy, self.destination)
        payload = self.destination / "root-0" / "hello.txt"
        payload.write_text("modified\n", encoding="utf-8")
        checked, _, failures = verify(self.destination)
        self.assertEqual(checked, 0)
        self.assertTrue(any("mismatch" in item for item in failures))

    def test_manifest_path_traversal_is_rejected(self):
        snapshot(self.policy, self.destination)
        manifest_path = self.destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"][0]["path"] = "../outside.txt"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        _, _, failures = verify(self.destination)
        self.assertTrue(any("unsafe manifest path" in item for item in failures))


if __name__ == "__main__":
    unittest.main()
