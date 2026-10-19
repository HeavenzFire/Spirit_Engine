# Spirit Engine — HeavenzFire Recovery Fabric

A portable, auditable recovery system for HeavenzFire projects and services. It is designed to preserve source, configuration templates, deployment manifests, and recovery evidence across independent storage providers.

## Design rules

- **Portable, not evasive:** deploy only to machines, accounts, cloud projects, and networks you own or are authorized to administer. It does not escape host controls or conceal persistence.
- **Backup before repair:** capture versioned snapshots and verify SHA-256 hashes before restore.
- **No secrets in Git:** environment files are templates only. Credentials belong in an OS credential store or a cloud secret manager.
- **Least privilege:** separate backup writer, read-only verifier, and restore operator identities. Restore is an explicit action, not an automatic response to an alert.
- **No destructive retention by default:** never prune the last known-good snapshot; retention changes require configuration and logging.
- **Independent recovery:** the restore procedure must not depend on Ollama, ChatGPT, or the service being restored.

## Initial architecture

1. **Guardian API** — health and backup-job status, bound to loopback by default.
2. **Snapshot worker** — creates manifests and SHA-256 inventories for explicitly configured directories; excludes credentials, caches, model blobs, and temporary files unless deliberately opted in.
3. **Storage adapter** — pluggable local path first, then S3-compatible object storage or a separately administered backup host.
4. **Verifier** — validates manifest hashes and reports missing or changed objects without overwriting source data.
5. **Recovery controller** — restores into a new staging directory first; activation is a separate, reviewed step.
6. **Watchdog** — checks service health, free disk space, snapshot age, and restore-test age. It may alert but must not autonomously delete data or change security controls.

## Build status

This repository begins with the architecture and safety contract. The production backup/restore implementation, cloud credentials, database schema, and deployment environment are not yet configured. No cloud destination is claimed to be connected until a real upload and restore verification succeed.

## Roadmap

- [ ] Define an explicit allowlist of project paths and exclusions.
- [ ] Implement local manifest/snapshot creation with atomic writes and hash verification.
- [ ] Add read-only health/status API and structured audit log.
- [ ] Add restore-to-staging and test round-trip recovery.
- [ ] Add optional PostgreSQL metadata service.
- [ ] Add S3-compatible storage adapter with versioning and server-side encryption.
- [ ] Add signed manifests and key-rotation instructions.
- [ ] Add scheduled backup and restore-drill workflow.

## Security

Do not commit API keys, access tokens, private archives, personal records, or raw `.env` files. Do not publish a backup bucket or database publicly. Start with a private destination and a second independent copy.
