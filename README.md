# Spirit Engine — HeavenzFire Recovery Fabric

A portable, auditable recovery system for HeavenzFire projects and services. It is designed to preserve source, configuration templates, deployment manifests, and recovery evidence across independent storage providers.

## Design rules

- **Portable, not evasive:** deploy only to machines, accounts, cloud projects, and networks you own or are authorized to administer. It does not escape host controls or conceal persistence.
- **Backup before repair:** create versioned snapshots and verify SHA-256 hashes before restore.
- **No secrets in Git:** configuration is a template. Credentials belong in an OS credential store or a cloud secret manager.
- **Least privilege:** separate backup writer, read-only verifier, and restore operator identities. Restore is an explicit action, not an automatic response to an alert.
- **No destructive retention by default:** no automatic pruning and no overwrite of existing snapshot files.
- **Independent recovery:** the restore procedure must not depend on Ollama, ChatGPT, or the service being restored.

## Current implementation

- `scripts/recovery.py`: allowlist-based file inventory, plan-only mode, snapshot copy, SHA-256 verification, and tamper/path-traversal checks.
- `services/guardian/server.py`: read-only health/status API, loopback-only by default (`127.0.0.1:8789`).
- `config/backup-policy.example.json`: sample policy with placeholder paths and secret/cache exclusions.
- `deploy/compose.yaml`: optional PostgreSQL metadata store and MinIO object store, with ports bound to loopback and credentials required through environment variables.
- `tests/test_recovery.py`: unit tests for exclusions, snapshot verification, tamper detection, and unsafe manifest paths.
- `.github/workflows/tests.yml`: CI test workflow.

This is a **local snapshot prototype**, not yet a complete cloud backup product. The MinIO/PostgreSQL services are not automatically launched. No cloud account, remote bucket, database, scheduled job, or restore-to-production flow is claimed to be connected.

## Safe first run (PowerShell 5.1 compatible)

1. Copy `config/backup-policy.example.json` to a local config file that is ignored by Git, then set only the project directories you actually want to preserve and a destination on a separate drive or server.
2. Review the plan before copying anything:

   ```powershell
   python .\scripts\recovery.py plan --config .\config\backup-policy.local.json
   ```

3. Choose a **new, empty, dedicated snapshot directory** on the destination volume. Snapshot mode checks available space, skips excluded files and files larger than the configured limit, refuses overwrites, and verifies SHA-256 hashes. It never deletes source data.

   ```powershell
   python .\scripts\recovery.py snapshot --config .\config\backup-policy.local.json --output 'E:\HeavenzFire-Recovery\snapshots\first' --execute
   ```

4. Verify again independently:

   ```powershell
   python .\scripts\recovery.py verify 'E:\HeavenzFire-Recovery\snapshots\first'
   ```

Do not run the copy step when the source or destination drive is critically full. The example policy intentionally excludes model blobs, caches, credentials, and dependency trees; add a path or file class only after deciding that it belongs in the backup and confirming the destination can hold it.

## Guardian status API

Set `HF_SNAPSHOT_ROOT` to a directory containing per-snapshot folders with `manifest.json`, then run:

```powershell
$env:HF_SNAPSHOT_ROOT = 'E:\HeavenzFire-Recovery\snapshots'
python .\services\guardian\server.py
```

- `GET http://127.0.0.1:8789/healthz` — process liveness.
- `GET http://127.0.0.1:8789/v1/status` — snapshot manifest presence/JSON validity and free space.

The service rejects non-loopback binds. It is intentionally read-only and does not trigger restores or deletion.

## Optional data services

`deploy/compose.yaml` defines PostgreSQL and MinIO with ports published only on `127.0.0.1`. Set `HF_DB_PASSWORD`, `HF_OBJECT_USER`, and `HF_OBJECT_PASSWORD` in the launching shell or a properly protected local secret manager before running Compose. Do not commit a `.env` file. Use unique strong secrets and do not expose these ports to the internet.

## Next milestones

- [ ] Run CI and fix any test failures.
- [ ] Test a snapshot and restore drill on a separate volume.
- [ ] Add a transactional metadata schema and structured audit log.
- [ ] Add S3-compatible uploads with object versioning and encryption.
- [ ] Add signed manifests and key-rotation instructions.
- [ ] Add scheduled backups and restore drills with alerts, not automatic destructive actions.

## Security

Do not commit API keys, access tokens, private archives, personal records, or raw `.env` files. Do not publish a backup bucket or database publicly. Use at least two independent copies and periodically prove recovery by restoring into a separate staging directory.
