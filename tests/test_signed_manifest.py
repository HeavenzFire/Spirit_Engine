import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.signed_manifest import (
    sign_manifest, verify_signed_manifest, validate_manifest,
)


class SignedManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.snapshot = self.root / "snapshot"
        self.snapshot.mkdir()
        self.private = Ed25519PrivateKey.generate()
        self.private_path = self.root / "private.pem"
        self.public_path = self.root / "public.pem"
        self.private_path.write_bytes(self.private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        self.public_path.write_bytes(self.private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        payload = b"integrity is necessary; authenticity matters too\n"
        (self.snapshot / "payload.txt").write_bytes(payload)
        import hashlib
        self.manifest = {
            "schema_version": 1,
            "created_utc": "2026-11-12T00:00:00+00:00",
            "file_count": 1,
            "total_bytes": len(payload),
            "hash_algorithm": "sha256",
            "files": [{
                "path": "payload.txt", "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }],
        }
        (self.snapshot / "manifest.json").write_text(
            json.dumps(self.manifest), encoding="utf-8"
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_sign_and_verify(self):
        sign_manifest(self.snapshot, self.private_path)
        result = verify_signed_manifest(self.snapshot, self.public_path)
        self.assertEqual(result["file_count"], 1)

    def test_modified_manifest_fails_signature(self):
        sign_manifest(self.snapshot, self.private_path)
        changed = dict(self.manifest)
        changed["created_utc"] = "2026-11-13T00:00:00+00:00"
        (self.snapshot / "manifest.json").write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            verify_signed_manifest(self.snapshot, self.public_path)

    def test_wrong_trusted_key_fails(self):
        sign_manifest(self.snapshot, self.private_path)
        other = Ed25519PrivateKey.generate().public_key()
        self.public_path.write_bytes(other.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        with self.assertRaisesRegex(ValueError, "key ID"):
            verify_signed_manifest(self.snapshot, self.public_path)

    def test_duplicate_paths_rejected(self):
        duplicate = dict(self.manifest)
        duplicate["files"] = duplicate["files"] * 2
        duplicate["file_count"] = 2
        duplicate["total_bytes"] *= 2
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            validate_manifest(duplicate)

    def test_inconsistent_totals_rejected(self):
        invalid = dict(self.manifest)
        invalid["total_bytes"] += 1
        with self.assertRaisesRegex(ValueError, "total_bytes"):
            validate_manifest(invalid)

    def test_traversal_rejected(self):
        invalid = dict(self.manifest)
        invalid["files"] = [dict(self.manifest["files"][0], path="../outside")]
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            validate_manifest(invalid)


if __name__ == "__main__":
    unittest.main()
