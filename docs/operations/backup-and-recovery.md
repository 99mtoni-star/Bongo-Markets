# Backup and Recovery (PostgreSQL)

| Requirement | Control |
|---|---|
| NFR-007, NFR-M03: scheduled backups | `scripts/backup.py` runs daily (cron/systemd timer) |
| NFR-DR-004: daily full backup + PITR | Daily `pg_dump` plus continuous **WAL archiving** (the PostgreSQL equivalent of MariaDB binary logs); checked by `scripts/check_pitr.py` |
| SEC-KEY-005: encrypted backups | AES-256 (OpenSSL, PBKDF2 at 200k iterations); the plaintext dump is deleted immediately; the key lives in the secret manager |
| NFR-DR-005: 30-day retention, off-site copy | `BM_BACKUP_RETENTION_DAYS=30`; sync the encrypted files to off-site storage (finalized in M20) |
| NFR-DR-006: monthly restore test | `scripts/restore.py test <backup>` restores into a throw-away DB, verifies it, drops it, and writes a JSON report |
| NFR-DR-008: payment reconciliation after recovery | `scripts/restore.py restore` sets `payments_reconciliation_required=true`; stored payment status is non-authoritative until it is reconciled with the provider (M13) |

## postgresql.conf for PITR

```
wal_level = replica
archive_mode = on
archive_command = 'test ! -f /backup/wal/%f && cp %p /backup/wal/%f'   # use an encrypted, off-site target in production
```

Targets (finalized in M20): RPO ≤ 30 minutes and RTO ≤ 4 hours. To recover to a point in time, restore the latest base backup (`pg_basebackup`), set `restore_command` and `recovery_target_time`, and start the server.

## Daily schedule (example)

```
15 1 * * *  bm-backup  cd /srv/bongo-markets && python scripts/backup.py
30 2 1 * *  bm-backup  cd /srv/bongo-markets && python scripts/restore.py test "$(ls -t backups/*.dump.enc | head -1)"
```
