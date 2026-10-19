#!/usr/bin/env python3
"""Download and verify a versioned S3-compatible snapshot into a new staging dir.

Never restores over existing files or original source paths.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

try:
    import boto3
except ImportError:
    print("Missing optional dependency. Install with: python -m pip install -r requirements-cloud.txt", file=sys.stderr)
    raise SystemExit(2)


def env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"Required environment variable is not set: {name}")
    return value


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    import re
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", args.snapshot_id):
        raise SystemExit("Invalid snapshot ID.")
    output = args.output.expanduser().resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"Refusing to restore into a non-empty directory: {output}")
    output.mkdir(parents=True, exist_ok=True)

    bucket = env("HF_S3_BUCKET")
    client = boto3.client(
        "s3",
        endpoint_url=env("HF_S3_ENDPOINT_URL"),
        region_name=os.environ.get("HF_S3_REGION", "us-east-1"),
        aws_access_key_id=env("HF_S3_ACCESS_KEY_ID"),
        aws_secret_access_key=env("HF_S3_SECRET_ACCESS_KEY"),
    )
    versioning = client.get_bucket_versioning(Bucket=bucket)
    if versioning.get("Status") != "Enabled":
        raise SystemExit("Refusing restore: source bucket versioning is not enabled.")

    manifest_key = f"snapshots/{args.snapshot_id}/manifest.json"
    response = client.get_object(Bucket=bucket, Key=manifest_key)
    body = response["Body"].read()
    expected_manifest_hash = response.get("Metadata", {}).get("sha256")
    actual_manifest_hash = hashlib.sha256(body).hexdigest()
    if not expected_manifest_hash or expected_manifest_hash != actual_manifest_hash:
        raise SystemExit("Remote manifest hash verification failed.")
    manifest = json.loads(body.decode("utf-8"))
    if manifest.get("schema_version") != 1 or manifest.get("snapshot_id") != args.snapshot_id:
        raise SystemExit("Remote manifest schema or snapshot ID mismatch.")

    restored = 0
    failures = []
    for item in manifest.get("files", []):
        rel = Path(item["path"])
        if rel.is_absolute() or ".." in rel.parts:
            failures.append(f"unsafe relative path rejected: {rel}")
            continue
        key = item.get("object_key", "")
        if not key.startswith(f"snapshots/{args.snapshot_id}/"):
            failures.append(f"object key outside snapshot prefix rejected: {key}")
            continue
        target = (output / rel).resolve()
        if output not in target.parents:
            failures.append(f"target path escapes staging directory: {rel}")
            continue
        if target.exists():
            failures.append(f"refusing overwrite: {rel}")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".hf-part")
        if temporary.exists():
            failures.append(f"temporary path already exists: {temporary.name}")
            continue
        try:
            client.download_file(bucket, key, str(temporary))
            if temporary.stat().st_size != int(item["size_bytes"]):
                raise RuntimeError("size mismatch")
            if sha256_file(temporary) != item["sha256"]:
                raise RuntimeError("SHA-256 mismatch")
            os.replace(temporary, target)
            restored += 1
            print(f"VERIFIED {rel}")
        except Exception as exc:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            failures.append(f"{rel}: {type(exc).__name__}: {exc}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        print(f"RESULT=FAIL restored_files={restored}")
        return 2
    if restored != int(manifest.get("file_count", -1)):
        print("FAIL: restored file count does not match manifest.", file=sys.stderr)
        return 2
    print(f"RESULT=PASS snapshot_id={args.snapshot_id} restored_files={restored}")
    print(f"STAGING={output}")
    print("Review staging contents before copying anything into a live project.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
