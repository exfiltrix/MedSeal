# MedSeal — production deployment and operations runbook

Audience: the team that runs MedSeal for hospitals. Everything here refers to files in this repository.
The offline demo (`./demo.sh`, SQLite, Hardhat) is **not** a deployment and cannot be configured into one:
with `MEDSEAL_ENV=production` the backend refuses to start on any unsafe setting.

## 1. What runs

| Service | Image / command | Role |
|---|---|---|
| `proxy` | `nginx:1.29-alpine`, `deploy/nginx/nginx.conf` | the only published ports (80→443, 443). TLS 1.2/1.3, HSTS, sign-in rate limit (10/min per IP), API rate limit |
| `frontend` | `by_billy/frontend/Dockerfile` (Next.js standalone) | website; personal sign-in; forwards the user's session to the API |
| `api` | `backend/Dockerfile`, `MEDSEAL_PROCESS_ROLE=api`, 4 uvicorn workers | HTTP API (`https://<domain>/backend/…`) |
| `worker` | same image, `python -m app.worker` | exactly one: folder watcher, blockchain anchoring, crash-test jobs, data retention |
| `db` | `postgres:17.6-alpine` | reachable only by `api` and `worker` (internal network) |

All containers run as non-root, read-only filesystems, `no-new-privileges`, all capabilities dropped
(nginx gets back only what binding 80/443 needs). Persistent state: volumes `pgdata`, `keys`, `storage`,
`anchors`, `home` (AI weights cache), plus the scanner drop folder `MEDSEAL_WATCH_HOST_DIR`.

## 2. Before the first start

1. **Secrets** — `cp deploy/env.prod.example deploy/.env.prod && chmod 600 deploy/.env.prod`, fill every value
   from the secret manager. Generate:
   - `MEDSEAL_DATA_KEY`: `python3 -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"`
   - `MEDSEAL_PATIENT_SALT`, `MEDSEAL_PG_PASSWORD`: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`
   - **Store `MEDSEAL_DATA_KEY` and `MEDSEAL_PATIENT_SALT` offline as well.** Lose the data key and every
     encrypted key file, sealed image and inbox result is gone; change the salt and patient binding of every
     existing seal stops matching.
2. **Signing keys** — preferred: an HSM over PKCS#11 (`MEDSEAL_KEY_BACKEND=pkcs11`, vendor module path,
   token label, PIN; mount the module into the `api`/`worker` containers). Keys are generated inside the HSM
   and never leave it. Without an HSM: `MEDSEAL_KEY_BACKEND=file` + `MEDSEAL_ALLOW_SOFTWARE_KEYS=1` (an
   explicit, documented risk decision; files are encrypted with the data key).
3. **Blockchain** — deploy `contracts/MedSealAnchor.sol` to the chosen network
   (`npx hardhat run scripts/deploy.js --network <net>`), set `RPC_URL`, `CONTRACT_ADDRESS`,
   `ANCHOR_PRIVATE_KEY` (a wallet used only for anchoring), `CHAIN_ID`, `EXPLORER_URL`.
4. **TLS** — `deploy/certs/fullchain.pem` and `privkey.pem` for `MEDSEAL_DOMAIN`.
5. **Data localisation** — personal data of citizens of Uzbekistan must be stored on servers in Uzbekistan:
   choose the host, the database volume location and the backup location accordingly.

Check a configuration without starting anything:
`docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env.prod run --rm api python -m app.hardening`

## 3. Start, first admin, first device

```bash
cd deploy
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
docker compose -f docker-compose.prod.yml --env-file .env.prod exec api python -m scripts.create_root_key
docker compose -f docker-compose.prod.yml --env-file .env.prod exec api \
    python -m scripts.create_user --username <you> --role admin --full-name "<Name>"
```

`create_user` asks for a temporary password and prints the MFA enrolment link once: add it to an
authenticator app, sign in at `https://<domain>/login`, set your own password. Create everyone else at
`/admin/users` (roles: doctor, operator, auditor, client, admin). Register each scanner gateway as a device
(`POST /backend/devices` as an admin); for web sealing put that device's token in `MEDSEAL_DEVICE_TOKEN`.

The schema is created and upgraded by the backend on start (Alembic). `GET /backend/health/ready` must say
`{"ok": true}` (database, schema, trust root).

## 4. Day-to-day checks

| What | How | Expected |
|---|---|---|
| Ledger integrity | `GET /backend/ledger/check` | `ok: true` |
| Audit trail integrity | `GET /backend/audit/check` (admin/auditor) | `ok: true` |
| Anchoring | `GET /backend/anchors` | `pending` small, batches every 10 min |
| Readiness | `GET /backend/health/ready` | `ok: true` |
| Logs | `docker compose logs api worker` | JSON lines with `request_id`; no image data, no patient identifiers |

Any `ok: false` above is a security incident until proven otherwise (§7).

## 5. Backups and restore

`deploy/backup.sh` (nightly from cron) writes `db.dump`, `anchors.tgz`, `keys.tgz`, `storage.tgz` and checksums
to `deploy/backups/`; keep copies off the host. Restore into an empty stack: `pg_restore -d medseal --clean db.dump`
inside `db`, untar the three volumes, start, then check §4. The data key and the HSM are **not** in the backup.

## 6. Upgrades and changes

- Upgrade: `git pull && docker compose … up -d --build`; migrations run on start. Back up first.
- Schema change in code: add an Alembic revision (`alembic revision --autogenerate`); `tests/test_migrations.py`
  fails while models and migrations differ.
- Moving an existing SQLite demo database: `python -m scripts.migrate_sqlite_to_postgres` (verifies the chain,
  the anchors and the audit chain on arrival; refuses a non-empty target).
- Data stored before encryption at rest: `python -m scripts.encrypt_keys` and `python -m scripts.encrypt_storage`.

## 7. Incidents

| Event | Action |
|---|---|
| A device token or gateway key leaked | revoke the device (`POST /backend/devices/{id}/revoke`); seals made after revocation verify as forged |
| A user account compromised | `/admin/users` → deactivate (all sessions revoked at once), audit `GET /backend/audit?action=…` |
| An admin lost the authenticator | another admin: reset with "re-issue MFA" |
| Anchoring wallet key leaked | `transferOwnership` on the contract to a new wallet, update `ANCHOR_PRIVATE_KEY` |
| `ledger/check` or `audit/check` not ok | freeze changes, take a backup of the current state as evidence, compare with the on-chain anchors (`/verify` reports `blockchain_mismatch` per seal) |
| Data key exposed | rotate: new key, re-encrypt (decrypt with old, encrypt with new) — plan it like a migration |

## 8. Known limits (state them to customers)
See `docs/SECURITY.md` → "Honest limits": the AI shield is a warning, not a security boundary; AI numbers come from
a public 300 px dataset; the detective is experimental; clinical validation is still required.
