#!/usr/bin/env python3
"""Read-only local health endpoint for the HeavenzFire recovery fabric."""
from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


def status_payload() -> dict:
    root_text = os.environ.get("HF_SNAPSHOT_ROOT", "")
    result = {
        "service": "heavenzfire-guardian",
        "status": "ok",
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "snapshot_root_configured": bool(root_text),
        "latest_snapshot_age_seconds": None,
        "latest_manifest_valid_json": None,
        "disk_free_bytes": None,
    }
    if not root_text:
        result["status"] = "degraded"
        result["reason"] = "HF_SNAPSHOT_ROOT is not configured"
        return result

    root = Path(root_text).expanduser()
    try:
        root.mkdir(parents=True, exist_ok=True)
        result["disk_free_bytes"] = shutil.disk_usage(root).free
        manifests = list(root.glob("*/manifest.json"))
        if manifests:
            latest = max(manifests, key=lambda p: p.stat().st_mtime)
            json.loads(latest.read_text(encoding="utf-8"))
            result["latest_manifest_valid_json"] = True
            result["latest_snapshot_age_seconds"] = max(
                0, int(datetime.now().timestamp() - latest.stat().st_mtime)
            )
        else:
            result["latest_manifest_valid_json"] = False
            result["status"] = "degraded"
            result["reason"] = "No snapshot manifest found"
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result["status"] = "degraded"
        result["reason"] = f"snapshot status unavailable: {type(exc).__name__}"
    return result


class Handler(BaseHTTPRequestHandler):
    server_version = "HeavenzFireGuardian/0.1"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path not in ("/healthz", "/v1/status"):
            self.send_error(404)
            return
        body = {
            "status": "ok"
        } if path == "/healthz" else status_payload()
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(200 if body.get("status") == "ok" else 503)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:
        self.send_error(405, "read-only endpoint")

    def log_message(self, fmt: str, *args) -> None:
        # Keep concise server logs; avoid logging request headers or secrets.
        print("%s - %s" % (self.client_address[0], fmt % args))


def main() -> None:
    bind = os.environ.get("HF_STATUS_BIND", "127.0.0.1")
    port = int(os.environ.get("HF_STATUS_PORT", "8789"))
    if bind not in ("127.0.0.1", "::1", "localhost"):
        raise SystemExit(
            "Refusing non-loopback bind. Put an authenticated TLS reverse proxy "
            "in front of the service before exposing it on a network."
        )
    server = ThreadingHTTPServer((bind, port), Handler)
    print(f"Guardian status service listening on http://{bind}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
