#!/usr/bin/env python3
"""Ed25519 signing and strict validation for Spirit Engine snapshot manifests.

Private keys are supplied explicitly by the operator and are never generated,
stored, or uploaded by this module. Signatures are detached from manifest.json.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError as exc:  # pragma: no cover - exercised in minimal installs
    raise ImportError(
        "Ed25519 support requires: python -m pip install -r requirements-security.txt"
    ) from exc

SIGNATURE_FILE = "manifest.sig.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    """Stable UTF-8 representation; timestamps and values remain part of signature."""
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def validate_manifest(manifest: Any) -> dict[str, Any]:
    """Reject ambiguous, incomplete, or unsafe manifests before trust decisions."""
    if not isinstance(manifest, dict):
        raise ValueError("Manifest must be a JSON object.")
    if manifest.get("schema_version") != 1:
        raise ValueError("Unsupported manifest schema_version.")
    if manifest.get("hash_algorithm") != "sha256":
        raise ValueError("Unsupported manifest hash_algorithm.")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValueError("Manifest files must be a list.")
    if type(manifest.get("file_count")) is not int or manifest["file_count"] != len(files):
        raise ValueError("Manifest file_count does not match files.")
    total = 0
    seen: set[str] = set()
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            raise ValueError(f"Manifest file entry {index} must be an object.")
        path = item.get("path")
        if (not isinstance(path, str) or not path or "\\" in path or "\x00" in path
                or re.match(r"^[A-Za-z]:", path)):
            raise ValueError(f"Manifest file entry {index} has an invalid path.")
        rel = PurePosixPath(path)
        if rel.is_absolute() or any(part in ("", ".", "..") for part in path.split("/")):
            raise ValueError(f"Unsafe manifest path rejected: {path}")
        normalized = rel.as_posix()
        if normalized in seen:
            raise ValueError(f"Duplicate manifest path rejected: {path}")
        seen.add(normalized)
        size = item.get("size_bytes")
        if type(size) is not int or size < 0:
            raise ValueError(f"Invalid size_bytes for {path}.")
        digest = item.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValueError(f"Invalid SHA-256 digest for {path}.")
        total += size
    if type(manifest.get("total_bytes")) is not int or manifest["total_bytes"] != total:
        raise ValueError("Manifest total_bytes does not match file entries.")
    return manifest


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Private key must be an unencrypted Ed25519 PEM key.")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Public key must be an Ed25519 PEM key.")
    return key


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()



def verify_payload_files(snapshot_dir: Path, manifest: dict[str, Any]) -> None:
    """Verify each payload byte stream and reject symlink/path escapes."""
    root = snapshot_dir.expanduser().resolve()
    for item in manifest["files"]:
        candidate = root
        for part in PurePosixPath(item["path"]).parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise ValueError(f"Symlink in snapshot payload path: {item['path']}")
        resolved = candidate.resolve(strict=True)
        if root not in resolved.parents or not resolved.is_file():
            raise ValueError(f"Snapshot payload is missing or escapes root: {item['path']}")
        if resolved.stat().st_size != item["size_bytes"]:
            raise ValueError(f"Snapshot payload size mismatch: {item['path']}")
        digest = hashlib.sha256()
        with resolved.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != item["sha256"]:
            raise ValueError(f"Snapshot payload SHA-256 mismatch: {item['path']}")


def sign_manifest(snapshot_dir: Path, private_key_path: Path) -> Path:
    snapshot_dir = snapshot_dir.expanduser().resolve()
    manifest_path = snapshot_dir / "manifest.json"
    manifest = validate_manifest(json.loads(manifest_path.read_text(encoding="utf-8")))
    verify_payload_files(snapshot_dir, manifest)
    private_key = load_private_key(private_key_path)
    public_key = private_key.public_key()
    signature = private_key.sign(canonical_manifest_bytes(manifest))
    record = {
        "schema_version": 1,
        "algorithm": "Ed25519",
        "key_id": key_id(public_key),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    target = snapshot_dir / SIGNATURE_FILE
    if target.exists():
        raise FileExistsError(f"Refusing to overwrite existing signature: {target}")
    target.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return target


def verify_signed_manifest(snapshot_dir: Path, public_key_path: Path) -> dict[str, Any]:
    snapshot_dir = snapshot_dir.expanduser().resolve()
    manifest = validate_manifest(
        json.loads((snapshot_dir / "manifest.json").read_text(encoding="utf-8"))
    )
    record = json.loads((snapshot_dir / SIGNATURE_FILE).read_text(encoding="utf-8"))
    if not isinstance(record, dict) or record.get("schema_version") != 1:
        raise ValueError("Unsupported or malformed signature record.")
    if record.get("algorithm") != "Ed25519":
        raise ValueError("Unsupported signature algorithm.")
    public_key = load_public_key(public_key_path)
    if record.get("key_id") != key_id(public_key):
        raise ValueError("Trusted public key ID does not match signature record.")
    try:
        signature = base64.b64decode(record["signature"], validate=True)
        public_key.verify(signature, canonical_manifest_bytes(manifest))
    except (KeyError, ValueError) as exc:
        raise ValueError("Malformed signature encoding.") from exc
    except Exception as exc:
        # InvalidSignature is intentionally surfaced as a stable validation error.
        raise ValueError("Manifest signature verification failed.") from exc
    verify_payload_files(snapshot_dir, manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sign = sub.add_parser("sign", help="sign a snapshot manifest with an operator key")
    sign.add_argument("snapshot_dir", type=Path)
    sign.add_argument("--private-key", required=True, type=Path)
    verify = sub.add_parser("verify", help="verify a manifest against a trusted public key")
    verify.add_argument("snapshot_dir", type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "sign":
            path = sign_manifest(args.snapshot_dir, args.private_key)
            print(f"SIGNATURE={path}")
        else:
            manifest = verify_signed_manifest(args.snapshot_dir, args.public_key)
            print(f"RESULT=PASS signed_manifest=true files={manifest['file_count']}")
        return 0
    except Exception as exc:
        print(f"RESULT=FAIL {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
