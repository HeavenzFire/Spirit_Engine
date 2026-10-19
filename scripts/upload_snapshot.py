#!/usr/bin/env python3
"""Upload a verified local snapshot to a versioned S3-compatible bucket.

Credentials are read only from environment variables. The source snapshot is
never modified. The sanitized remote manifest is uploaded last as the commit
marker, so a partial upload is not mistaken for a complete backup.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path

try:
    import boto3
except ImportError:
    print("Missing optional dependency. Install with: python -m pip install -r requirements-cloud.txt", file=sys.stderr)
    raise SystemExit(2)

from recovery import verify, sha256_file


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"Required environment variable is not set: {name}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot_dir", type=Path)
    parser.add_argument("--snapshot-id", required=True, help="Unique ID, e.g. 2026-10-18T201500Z")
    args = parser.parse_args()

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", args.snapshot_id):
        raise SystemExit("Invalid snapshot ID; use only letters, digits, dot, underscore, and hyphen.")

    snapshot_dir = args.snapshot_dir.expanduser().resolve()
    checked, _, failures = verify(snapshot_dir)
    if failures:
        for failure in failures:
            print(f"VERIFY_FAIL: {failure}", file=sys.stderr)
        return 2

    manifest = json.loads((snapshot_dir / "manifest.json").read_text(encoding="utf-8"))
    if checked != int(manifest.get("file_count", -1)):
        raise SystemExit("Manifest file_count does not match verified file count.")

    endpoint = required_env("HF_S3_ENDPOINT_URL")
    bucket = required_env("HF_S3_BUCKET")
    access_key = required_env("HF_S3_ACCESS_KEY_ID")
    secret_key = required_env("HF_S3_SECRET_ACCESS_KEY")
    region = os.environ.get("HF_S3_REGION", "us-east-1")
    prefix = f"snapshots/{args.snapshot_id}"
    sse = os.environ.get("HF_S3_SERVER_SIDE_ENCRYPTION", "").strip()

    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )

    versioning = client.get_bucket_versioning(Bucket=bucket)
    if versioning.get("Status") != "Enabled":
        raise SystemExit(
            f"Refusing upload: bucket {bucket!r} does not report versioning Enabled. "
            "Enable versioning and verify bucket access before retrying."
        )

    common_extra: dict = {}
    if sse:
        if sse not in ("AES256", "aws:kms"):
            raise SystemExit("HF_S3_SERVER_SIDE_ENCRYPTION must be AES256 or aws:kms.")
        common_extra["ServerSideEncryption"] = sse
        if sse == "aws:kms" and os.environ.get("HF_S3_KMS_KEY_ID"):
            common_extra["SSEKMSKeyId"] = os.environ["HF_S3_KMS_KEY_ID"]

    uploaded = 0
    remote_records = []
    for record in manifest["files"]:
        rel = Path(record["path"])
        if rel.is_absolute() or ".." in rel.parts:
            raise SystemExit(f"Unsafe manifest path rejected: {rel}")
        local_path = (snapshot_dir / rel).resolve()
        if snapshot_dir not in local_path.parents or not local_path.is_file():
            raise SystemExit(f"Snapshot file is missing or escapes snapshot root: {rel}")
        digest = sha256_file(local_path)
        if digest != record["sha256"] or local_path.stat().st_size != int(record["size_bytes"]):
            raise SystemExit(f"Snapshot changed after verification: {rel}")

        key = f"{prefix}/{rel.as_posix()}"
        extra = dict(common_extra)
        extra["Metadata"] = {"sha256": digest}
        client.upload_file(str(local_path), bucket, key, ExtraArgs=extra)
        head = client.head_object(Bucket=bucket, Key=key)
        if int(head["ContentLength"]) != local_path.stat().st_size:
            raise RuntimeError(f"Remote size verification failed for {key}")
        if head.get("Metadata", {}).get("sha256") != digest:
            raise RuntimeError(f"Remote SHA-256 metadata verification failed for {key}")
        remote_records.append({
            "path": rel.as_posix(),
            "size_bytes": int(record["size_bytes"]),
            "sha256": digest,
            "object_key": key,
        })
        uploaded += 1
        print(f"VERIFIED {key} ({record['size_bytes']} bytes)")

    # Do not leak absolute local paths into cloud metadata.
    remote_manifest = {
        "schema_version": 1,
        "snapshot_id": args.snapshot_id,
        "created_utc": manifest.get("created_utc"),
        "hash_algorithm": "sha256",
        "file_count": len(remote_records),
        "total_bytes": sum(item["size_bytes"] for item in remote_records),
        "files": remote_records,
    }
    body = json.dumps(remote_manifest, indent=2, sort_keys=True).encode("utf-8")
    manifest_key = f"{prefix}/manifest.json"
    extra = dict(common_extra)
    extra["ContentType"] = "application/json"
    extra["Metadata"] = {
        "sha256": hashlib.sha256(body).hexdigest(),
        "snapshot-id": args.snapshot_id,
    }
    client.put_object(Bucket=bucket, Key=manifest_key, Body=body, **extra)
    head = client.head_object(Bucket=bucket, Key=manifest_key)
    expected = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    if int(head["ContentLength"]) != len(body):
        raise RuntimeError("Remote manifest size verification failed")
    if head.get("Metadata", {}).get("sha256") != hashlib.sha256(body).hexdigest():
        raise RuntimeError("Remote manifest SHA-256 metadata verification failed")

    print(f"RESULT=PASS snapshot_id={args.snapshot_id} verified_files={uploaded}")
    print(f"MANIFEST=s3://{bucket}/{manifest_key}")
    print(f"MANIFEST_SHA256_BASE64={expected}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
