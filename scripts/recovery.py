#!/usr/bin/env python3
"""Portable, allowlist-based file snapshot planner and verifier.

This first version is intentionally local-only. It never uploads data, deletes
source files, follows symlinks, or restores over an existing path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_policy(path: Path) -> dict[str, Any]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    if policy.get("schema_version") != 1:
        raise ValueError("Unsupported or missing schema_version (expected 1).")
    roots = policy.get("source_roots")
    if not isinstance(roots, list) or not roots:
        raise ValueError("source_roots must be a non-empty list.")
    if not policy.get("destination_root"):
        raise ValueError("destination_root must be configured explicitly.")
    return policy


def excluded(path: Path, policy: dict[str, Any]) -> bool:
    if path.is_symlink():
        return True
    if path.name in set(policy.get("exclude_file_names", [])):
        return True
    if path.suffix.lower() in {s.lower() for s in policy.get("exclude_extensions", [])}:
        return True
    return False


def walk_policy(policy: dict[str, Any]):
    excluded_dirs = set(policy.get("exclude_directory_names", []))
    max_bytes = int(policy.get("max_file_size_mb", 512)) * 1024 * 1024
    for root_index, raw_root in enumerate(policy["source_roots"]):
        root = Path(raw_root).expanduser()
        if not root.exists() or not root.is_dir():
            print(f"WARNING missing source root: {root}", file=sys.stderr)
            continue
        root = root.resolve()
        for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            dirs[:] = [
                name for name in dirs
                if name not in excluded_dirs
                and not (current_path / name).is_symlink()
            ]
            for name in files:
                source = current_path / name
                try:
                    if excluded(source, policy):
                        continue
                    size = source.stat(follow_symlinks=False).st_size
                    if size > max_bytes:
                        continue
                    relative = source.relative_to(root)
                    yield root_index, root, source, relative, size
                except (OSError, ValueError):
                    continue


def build_plan(policy: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    entries: list[dict[str, Any]] = []
    total = 0
    for root_index, root, source, relative, size in walk_policy(policy):
        entries.append({
            "root_index": root_index,
            "source_root": str(root),
            "source": str(source),
            "relative_path": relative.as_posix(),
            "size_bytes": size,
        })
        total += size
    return entries, total


def snapshot(policy: dict[str, Any], output: Path) -> Path:
    output = output.expanduser().resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"Refusing to write into non-empty destination: {output}")
    output.mkdir(parents=True, exist_ok=True)
    entries, planned_bytes = build_plan(policy)
    free = shutil.disk_usage(output).free
    # Allow 15% headroom for metadata, filesystem behavior, and changing files.
    required = int(planned_bytes * 1.15) + 64 * 1024 * 1024
    if free < required:
        raise OSError(
            f"Insufficient destination space: need about {required} bytes, "
            f"have {free}. No files were copied."
        )

    records = []
    for entry in entries:
        rel = Path(f"root-{entry['root_index']}") / Path(entry["relative_path"])
        target = output / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        # Do not overwrite any file, including one created concurrently.
        if target.exists():
            raise FileExistsError(f"Refusing to overwrite {target}")
        before = entry["size_bytes"]
        source = Path(entry["source"])
        with source.open("rb") as src, tempfile.NamedTemporaryFile(
            mode="wb", dir=str(target.parent), prefix=".hf-part-", delete=False
        ) as dst:
            temporary = Path(dst.name)
            try:
                shutil.copyfileobj(src, dst, length=CHUNK)
                dst.flush()
                os.fsync(dst.fileno())
            except Exception:
                temporary.unlink(missing_ok=True)
                raise
        try:
            after = source.stat().st_size
            if before != after or temporary.stat().st_size != before:
                temporary.unlink(missing_ok=True)
                raise RuntimeError(f"Source changed during snapshot: {source}")
            expected_hash = sha256_file(source)
            copied_hash = sha256_file(temporary)
            if expected_hash != copied_hash:
                temporary.unlink(missing_ok=True)
                raise RuntimeError(f"Hash mismatch while copying: {source}")
            os.replace(temporary, target)
            shutil.copystat(source, target, follow_symlinks=False)
            records.append({
                "path": rel.as_posix(),
                "source_root": entry["source_root"],
                "source": entry["source"],
                "size_bytes": before,
                "sha256": expected_hash,
            })
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    manifest = {
        "schema_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "file_count": len(records),
        "total_bytes": sum(item["size_bytes"] for item in records),
        "hash_algorithm": "sha256",
        "files": records,
    }
    manifest_path = output / "manifest.json"
    fd, tmp_name = tempfile.mkstemp(prefix=".manifest-", dir=str(output))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, manifest_path)
    except Exception:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return manifest_path


def verify(snapshot_dir: Path) -> tuple[int, int, list[str]]:
    snapshot_dir = snapshot_dir.expanduser().resolve()
    manifest_path = snapshot_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or manifest.get("hash_algorithm") != "sha256":
        raise ValueError("Unsupported manifest schema or hash algorithm.")
    checked = 0
    verified_bytes = 0
    failures: list[str] = []
    for record in manifest.get("files", []):
        rel = Path(record["path"])
        if rel.is_absolute() or ".." in rel.parts:
            failures.append(f"unsafe manifest path rejected: {rel}")
            continue
        candidate = (snapshot_dir / rel).resolve()
        if snapshot_dir not in candidate.parents:
            failures.append(f"path escapes snapshot rejected: {rel}")
            continue
        try:
            if not candidate.is_file():
                failures.append(f"missing: {rel}")
                continue
            size = candidate.stat().st_size
            digest = sha256_file(candidate)
            if size != int(record["size_bytes"]):
                failures.append(f"size mismatch: {rel}")
            elif digest != record["sha256"]:
                failures.append(f"hash mismatch: {rel}")
            else:
                checked += 1
                verified_bytes += size
        except OSError as exc:
            failures.append(f"cannot read {rel}: {exc}")
    return checked, verified_bytes, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan_cmd = sub.add_parser("plan", help="inventory allowlisted files; copy nothing")
    plan_cmd.add_argument("--config", required=True, type=Path)
    snap_cmd = sub.add_parser("snapshot", help="create a new verified snapshot")
    snap_cmd.add_argument("--config", required=True, type=Path)
    snap_cmd.add_argument("--output", type=Path, help="override configured destination")
    snap_cmd.add_argument("--execute", action="store_true", help="required to copy files")
    verify_cmd = sub.add_parser("verify", help="verify snapshot hashes; write nothing")
    verify_cmd.add_argument("snapshot_dir", type=Path)
    args = parser.parse_args()

    try:
        if args.command == "verify":
            checked, size, failures = verify(args.snapshot_dir)
            print(f"verified_files={checked} verified_bytes={size}")
            for failure in failures:
                print(f"FAIL: {failure}")
            print("RESULT=PASS" if not failures else "RESULT=FAIL")
            return 0 if not failures else 2

        policy = load_policy(args.config)
        entries, total = build_plan(policy)
        print(f"planned_files={len(entries)} planned_bytes={total}")
        print(f"planned_gib={total / (1024 ** 3):.3f}")
        if args.command == "plan":
            print("PLAN_ONLY=true; no files copied.")
            return 0
        if not args.execute:
            print("PLAN_ONLY=true; pass --execute to create the snapshot.")
            return 0
        output = args.output or Path(policy["destination_root"])
        manifest_path = snapshot(policy, output)
        print(f"manifest={manifest_path}")
        checked, size, failures = verify(manifest_path.parent)
        print(f"verified_files={checked} verified_bytes={size}")
        for failure in failures:
            print(f"FAIL: {failure}")
        print("RESULT=PASS" if not failures else "RESULT=FAIL")
        return 0 if not failures else 2
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
