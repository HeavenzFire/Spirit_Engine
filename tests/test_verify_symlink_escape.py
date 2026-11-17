import tempfile
import unittest
from pathlib import Path

from scripts.recovery import snapshot, verify


class SnapshotSymlinkVerificationTests(unittest.TestCase):
    def test_verifier_rejects_symlink_resolving_outside_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            output = base / "snapshot"
            source.mkdir()
            (source / "payload.txt").write_text("approved payload\n", encoding="utf-8")
            policy = {
                "schema_version": 1,
                "source_roots": [str(source)],
                "destination_root": str(output),
                "exclude_directory_names": [],
                "exclude_file_names": [],
                "exclude_extensions": [],
                "max_file_size_mb": 2,
                "copy_symlinks": False,
            }

            snapshot(policy, output)
            copied_file = output / "root-0" / "payload.txt"
            outside_file = base / "outside.txt"
            outside_file.write_text("approved payload\n", encoding="utf-8")
            copied_file.unlink()
            copied_file.symlink_to(outside_file)

            checked, _, failures = verify(output)

            self.assertEqual(checked, 0)
            self.assertTrue(
                any("path escapes snapshot rejected" in failure for failure in failures),
                failures,
            )

    def test_verifier_rejects_directory_symlink_resolving_outside_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            output = base / "snapshot"
            nested = source / "nested"
            nested.mkdir(parents=True)
            (nested / "payload.txt").write_text("approved payload\n", encoding="utf-8")
            policy = {
                "schema_version": 1,
                "source_roots": [str(source)],
                "destination_root": str(output),
                "exclude_directory_names": [],
                "exclude_file_names": [],
                "exclude_extensions": [],
                "max_file_size_mb": 2,
                "copy_symlinks": False,
            }

            snapshot(policy, output)
            copied_directory = output / "root-0" / "nested"
            outside_directory = base / "outside"
            outside_directory.mkdir()
            (outside_directory / "payload.txt").write_text(
                "approved payload\n", encoding="utf-8"
            )
            (copied_directory / "payload.txt").unlink()
            copied_directory.rmdir()
            copied_directory.symlink_to(outside_directory, target_is_directory=True)

            checked, _, failures = verify(output)

            self.assertEqual(checked, 0)
            self.assertTrue(
                any("path escapes snapshot rejected" in failure for failure in failures),
                failures,
            )


if __name__ == "__main__":
    unittest.main()
