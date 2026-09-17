# Render Free: encrypted configuration persistence

Opt-in for ONE running instance. Render Free removes local SQLite on sleep/redeploy.

Set server-only environment variables:
- `REMOTE_BACKUP_REPO`: private GitHub repository `owner/repo` (main branch)
- `REMOTE_BACKUP_TOKEN`: preferably fine-grained token scoped only to that repository, Contents read/write
- `REMOTE_BACKUP_KEY`: random 32 bytes, base64. Keep an independent secure recovery copy.

Before enabling, seed `config.enc.json` using `captureSnapshot` / `encodeSnapshot` from `src/lib/db/remoteBackup.js`. The JSON export is NOT the snapshot format: import it through the application's importDb logic into SQLite first. Never commit plaintext backups, tokens or encryption keys.

At database initialization, schema migration completes, then the encrypted snapshot is fetched and restored transactionally before callers get the adapter. Missing/inaccessible/corrupt snapshots fail closed rather than overwrite a good backup with an empty database. Restart after resolving an initialization failure.

Every 60 seconds the writer compares a deterministic configuration hash. Only changed configurations create an encrypted commit (AES-256-GCM with random nonce, authenticated format, gzip). No telemetry/request logs are included. Snapshot includes settings, provider connections/nodes, proxy pools, API keys, combos and all kv settings. Decryption and SQL constraints must succeed or restore rolls back. Built-in tests use real SQLite with fake GitHub responses.

Limitations:
- This is periodic backup, not a durable database. Changes since the last successful upload can be lost (normally up to 60 seconds plus upload latency; longer during outages).
- GitHub and valid credentials are required for cold start. Rate limits/outages interrupt persistence. Watch `[RemoteBackup]` logs for restore/save/error messages.
- On an optimistic-concurrency SHA conflict, uploads stop until restart. Never run two active writers. Avoid making changes during rolling deployment overlap.
- The initial snapshot restores exactly the supplied backup, not later dashboard changes.
- Usage history and request logs remain ephemeral. OAuth tokens in an old backup may need reconnecting.
- Compressed encrypted envelope capped at 900KB; decoded snapshot at 8MB.
- Retain the encryption key and private repository to recover. Key rotation requires re-encrypting the stored snapshot; do not simply replace the environment variable.
- Git history retains old encrypted configurations. Revoking provider credentials is separate from deleting backups.

Verify: `node --test tests/remote-backup.test.mjs`. Production verification should fetch /v1/models using a restored API key, then restart and verify restored counts plus startup restore log. Do not call this deployed until those checks succeed.
