# MedSeal — security model

Principle: **don't claim "unhackable" — prove each layer with a standard primitive and a live attack we catch.**

## Cryptographic primitives

| Purpose | Primitive | Standard | Strength |
|---|---|---|---|
| Fingerprints, Merkle trees | SHA-256 (domain-separated in the anchoring tree; the tile tree is frozen format v1 without it) | NIST FIPS 180-4 | 128-bit collision resistance |
| Seal signatures | Ed25519 | NIST FIPS 186-5 (EdDSA), RFC 8032 | ~128-bit security |
| Tamper-evident history | hash-chained ledger + blockchain anchoring | — | rewriting history requires rewriting the chain |
| Transport | TLS 1.3 + HSTS at the production reverse proxy (the demo runs plain http on a laptop) | RFC 8446 | — |

Keys: generated server-side, one key per device, stored outside the repo (`keys/`, env vars), never logged or returned. Production: HSM/TPM in the gateway, key rotation, revocation list (`devices.revoked`).

## Threat model

| # | Attack | Defense | Result shown in UI | Test |
|---|---|---|---|---|
| T1 | Change pixels (inject/remove tumor), or re-render them with a display chunk (PNG gAMA/ICC, DICOM VOI LUT/overlay) | tile hashes + signed display metadata | Tampered + location / metadata_changed | ✅ |
| T2 | Change 1 pixel by 1 | tile hashes | Tampered | ✅ |
| T3 | Edit image **and** ledger hashes | Ed25519 signature | Forged record | ✅ |
| T4 | Operator/DB admin rewrites history | hash chain + blockchain anchor | Blockchain mismatch (critical) | ✅ |
| T5 | Replace image with another real image | uid bound into every tile hash | Tampered / wrong uid | ✅ |
| T6 | Replay an old signed image as new | timestamp + device + uid in seal | shows original seal date/device | ✅ |
| T7 | Adversarial noise against diagnostic AI | shield (feature-squeezing ensemble) — stops standard FGSM/PGD; an attacker who knows the shield gets past it (measured, shown in every passport) | Attack suspected | ✅ |
| T8 | AI-generated image with no seal | detective (probability only) | Unsigned + probability | ✅ |
| T9 | Stolen device key | revocation; seals after revocation rejected | Revoked device | ✅ |
| T10 | Malicious upload (huge/malformed DICOM) | size limit 50 MB, type check, pydicom in try/except, no code execution, timeouts | 400 error | ✅ |
| T11 | Web attacks | OWASP Top 10: input validation, parameterized SQL (SQLAlchemy), security headers, rate limiting, CSRF same-site check, separate logins (gateway / doctor / client / admin) | — | basic |
| T12 | Patient data leak | DICOM PHI tags and PNG text chunks/EXIF stripped on sealing; blockchain holds only hashes; storage in Uzbekistan is a deployment requirement, not enforced by code | — | ✅ |

## Honest limits (say them if asked — it builds trust)
- An image altered **before** the seal (compromised scanner) is not detectable by the seal → that's why the gateway sits next to the scanner and the detective exists.
- Detective and shield are probabilistic, not proofs.
- The shield is **not** a security boundary against a knowledgeable attacker: optimising against it
  (`scripts/adaptive_attack.py`) gets most attacks through unnoticed. It also catches hiding a
  finding (sick → healthy) worse than adding one; calibration and the passport measure both
  directions and report the worse (review round 1).
- All AI numbers come from a public 300 px NIH subset; clinical X-rays are 2000–3000 px. The detective
  is trained on synthetic forgeries only and raises extra false alarms on routinely processed
  images (CLAHE, JPEG) — mitigated by training augmentation, not eliminated.
- The shield raises false alarms on ~1 in 5 clean full-resolution (1024 px) DICOMs, vs ~1% on the 300 px images it was calibrated on — tuned to miss no attack rather than to stay quiet (numbers: `ARCHITECTURE.md` §6).
- Ed25519/SHA-256 are not post-quantum; migration path: ML-DSA (NIST FIPS 204) signatures — the seal format has a `alg` field for this.

## Audit log
Every seal, verification, key change and anchor is logged (who, when, result) in an append-only table; admins cannot delete rows via the API.

## Security demo for the jury (live)
1. T2: change one pixel → caught.
2. T3: edit ledger without key → rejected.
3. T4: open SQLite, edit a seal row → verify shows **blockchain mismatch**.
4. T7: adversarial noise → shield flags it.

## As implemented
- Tests: one per threat, indexed in `backend/tests/test_threats.py` (`THREAT_TESTS`); `test_every_threat_has_a_test` fails if a ✅ row here has none.
- T4: `backend/tests/test_anchor.py` — an insider re-signs a doctored image with the real device key and repairs the hash chain; only the anchored root catches it (`scripts/rewrite_history_demo.py` for the live demo).
- T10: instead of timeouts, the decoded size is capped at 64 Mpx from the header, before any pixel is decoded (`MEDSEAL_MAX_PIXELS`) — PNG and DICOM "decompression bombs" get `413`. No request timeout in uvicorn itself.
- T11: security headers on every response (`nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, CSP `default-src 'none'` on JSON, `Cache-Control: no-store`; HSTS when served over https), per-IP rate limit 120/min on POSTs and on the expensive public GETs (`/ledger/check`, PDFs, QR images) (`MEDSEAL_RATE_LIMIT`, in memory: one backend process), failed tokens audited. Backend roles are bearer tokens (admin, device, doctor, client); the Next.js layer adds one Basic Auth login per area and refuses cross-site state-changing requests (CSRF) — still "basic": no per-person accounts.
- Transport: the demo runs over plain http on a laptop; TLS 1.3 + HSTS is a reverse-proxy setting in production.
- T4 (review round 1): deleting `anchors.jsonl` or cutting lines off its head used to switch the
  CRY-03 check off (`ok: true`). Every v2 row is now required to have its anchor line.
- T1 (review round 1): PNG display chunks (`gAMA`, `cHRM`, `sRGB`, `tRNS`, `iCCP`) are bound into the
  signed metadata (`meta_version` 3); before, adding one re-rendered the image while `/verify` said
  `authentic`.
- Audit log: table `audit_log`, `GET /api/audit` (admin). Rows are hash-chained like the ledger
  (`prev_hash`/`entry_hash`, linked right after each commit under a lock); `GET /api/audit/check`
  reports edited rows and rows whose predecessor was deleted. Not yet anchored externally: an insider
  who recomputes the whole chain, or deletes only the newest rows, is not caught by the chain alone.
- No `alg` field in the seal yet: the tile tree is frozen format v1; a version column comes with the post-quantum / domain-separated migration.
