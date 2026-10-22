#!/usr/bin/env python3
"""Local-first, hash-chained event ledger for the HeavenzFire Unified Field.

This module uses only the Python standard library. It provides tamper-evident
local event history and portable JSON export; it is not a peer transport,
identity system, or cryptographic signature scheme.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
"""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def event_digest(event_id: str, created_at: str, kind: str,
                 payload_json: str, prev_hash: str) -> str:
    material = canonical_json({
        "event_id": event_id,
        "created_at": created_at,
        "kind": kind,
        "payload_json": payload_json,
        "prev_hash": prev_hash,
    })
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class Ledger:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(SCHEMA)

    def append(self, kind: str, payload: Any, event_id: str | None = None) -> dict[str, Any]:
        if not isinstance(kind, str) or not kind.strip():
            raise ValueError("kind must be a non-empty string")
        if len(kind) > 128:
            raise ValueError("kind must be at most 128 characters")
        payload_json = canonical_json(payload)
        identifier = event_id or str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_hash = previous["event_hash"] if previous else GENESIS
            digest = event_digest(identifier, created_at, kind, payload_json, prev_hash)
            connection.execute(
                """INSERT INTO events
                   (event_id, created_at, kind, payload_json, prev_hash, event_hash)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (identifier, created_at, kind, payload_json, prev_hash, digest),
            )
            row = connection.execute(
                "SELECT * FROM events WHERE event_id = ?", (identifier,)
            ).fetchone()
        return self._row_to_event(row)

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "seq": row["seq"],
            "event_id": row["event_id"],
            "created_at": row["created_at"],
            "kind": row["kind"],
            "payload": json.loads(row["payload_json"]),
            "prev_hash": row["prev_hash"],
            "event_hash": row["event_hash"],
        }

    def list_events(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM events ORDER BY seq").fetchall()
        return [self._row_to_event(row) for row in rows]

    def verify(self) -> dict[str, Any]:
        expected_previous = GENESIS
        checked = 0
        failures: list[dict[str, Any]] = []
        for event in self.list_events():
            checked += 1
            payload_json = canonical_json(event["payload"])
            expected_hash = event_digest(
                event["event_id"], event["created_at"], event["kind"],
                payload_json, expected_previous,
            )
            if event["prev_hash"] != expected_previous:
                failures.append({"seq": event["seq"], "reason": "previous_hash_mismatch"})
            if event["event_hash"] != expected_hash:
                failures.append({"seq": event["seq"], "reason": "event_hash_mismatch"})
            expected_previous = event["event_hash"]
        return {"ok": not failures, "events_checked": checked, "failures": failures,
                "head_hash": expected_previous}

    def export_json(self, output: str | Path) -> int:
        target = Path(output).expanduser()
        events = self.list_events()
        document = {
            "schema_version": 1,
            "format": "heavenzfire-unified-field-ledger",
            "events": events,
            "verification": self.verify(),
        }
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")
        return len(events)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, help="Path to the local SQLite ledger")
    sub = parser.add_subparsers(dest="command", required=True)
    append_parser = sub.add_parser("append", help="Append one JSON payload event")
    append_parser.add_argument("--kind", required=True)
    append_parser.add_argument("--payload", required=True,
                               help="JSON value, for example '{\"task\":\"started\"}'")
    sub.add_parser("verify", help="Verify the hash chain")
    export_parser = sub.add_parser("export", help="Export portable JSON evidence")
    export_parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    ledger = Ledger(args.db)
    try:
        if args.command == "append":
            event = ledger.append(args.kind, json.loads(args.payload))
            print(json.dumps(event, indent=2, ensure_ascii=False))
        elif args.command == "verify":
            result = ledger.verify()
            print(json.dumps(result, indent=2))
            return 0 if result["ok"] else 2
        elif args.command == "export":
            count = ledger.export_json(args.output)
            print(json.dumps({"exported_events": count, "output": str(Path(args.output))}))
    except (ValueError, sqlite3.Error, OSError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
