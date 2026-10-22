# Unified Field Local Ledger

This is the first concrete local-first state component for the HeavenzFire Unified Field. It lives in `scripts/unified_field_ledger.py` and uses only Python's standard library.

## What it does

- Stores local events in SQLite.
- Canonicalizes JSON payloads so equivalent objects serialize consistently.
- Links each event to the prior event hash using SHA-256.
- Detects payload edits, event-hash edits, and broken chain links during verification.
- Exports a portable JSON evidence file with the verification result.
- Keeps all operations local; it does not call a cloud API or open a network listener.

## What it does not claim

The hash chain is tamper-evident, not tamper-proof. An attacker able to rewrite the entire database can recompute the chain. This first version does not provide public-key signatures, peer discovery, network synchronization, access control for multiple local users, or guaranteed availability. Those are separate milestones and must not be inferred from a passing local ledger test.

## Run it

Python 3.10+ is recommended.

Append an event:

    python scripts/unified_field_ledger.py --db .\state\unified-field.sqlite3 append --kind task.created --payload "{\"task\":\"first-epoch\",\"status\":\"planned\"}"

Verify the chain:

    python scripts/unified_field_ledger.py --db .\state\unified-field.sqlite3 verify

Export evidence:

    python scripts/unified_field_ledger.py --db .\state\unified-field.sqlite3 export --output .\state\ledger-export.json

Run tests:

    python -m unittest tests.test_unified_field_ledger -v

## Acceptance criteria

- A new empty ledger verifies successfully.
- Appended events survive closing and reopening the database.
- The second event references the first event's hash.
- Editing a stored payload is detected.
- Export includes events and verification evidence.
- Empty event kinds are rejected.

## Next milestones

1. Add explicit node identity and signed event envelopes using a maintained cryptographic library.
2. Add an import protocol with duplicate handling, chain-fork detection, and deterministic reconciliation.
3. Add an authenticated, allowlisted peer transport only after threat modeling and tests.
4. Test two real processes on loopback; then test disconnection, restart, replay, tampering, and recovery.
5. Document key rotation, revocation, backup, and data-retention behavior before production use.
