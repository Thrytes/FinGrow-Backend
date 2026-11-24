# FinGrow shared backend

`backend/` serves the Android and Tauri desktop clients. It handles email OTP verification, device sessions, profile metadata, and revision-checked encrypted snapshots.

## Data and privacy

- Finance records and receipts are encrypted by each client before sync. The server stores the ciphertext, profile metadata, hashed OTP codes, and hashed bearer tokens.
- The master password and readable finance records are never sent to the backend.
- Local development uses SQLite at `backend/data/fingrow-backend.sqlite`.
- Vercel deployments use a persistent Turso Cloud database. Vercel's function filesystem is temporary, so the local SQLite file must not be used for hosted data.
- Session tokens last 90 days. Users can keep using their local vault offline; an expired session only pauses sync until email verification succeeds again.

## Run locally

Requires Node.js 24.12 or later. The ignored `.env` file has local host, signing secrets, and SMTP settings. Start the API from this directory:

```powershell
npm start
```

The service listens at `http://127.0.0.1:4317`. Android emulator builds use `http://10.0.2.2:4317`. Local mode uses SQLite unless both Turso environment variables are configured.

## Deploy this directory to Vercel

Set the Vercel project's **Root Directory** to `backend/`. The API functions and rewrites in this folder expose the same client paths at `/health` and `/v1/...`.

### 1. Attach persistent storage

Install the **Turso Cloud** integration from the Vercel Marketplace and connect a database to this Vercel project. It supplies `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN`. The function creates its tables on first use. The implementation uses Turso's serverless SQLite-compatible client, so no local database file is written by a function.

### 2. Add Vercel environment variables

Set these in the Vercel project's environment settings. Mark secrets as **Secret** and add them to Preview and Production as needed.

| Variable | Value |
| --- | --- |
| `TURSO_DATABASE_URL` | Supplied by the Turso integration |
| `TURSO_AUTH_TOKEN` | Supplied by the Turso integration; keep secret |
| `FINGROW_OTP_HASH_SECRET` | A new random secret of at least 32 bytes |
| `FINGROW_TOKEN_HASH_SECRET` | A different random secret of at least 32 bytes |
| `SMTP_HOST` | `smtp.gmail.com` |
| `SMTP_PORT` | `465` |
| `SMTP_SECURE` | `true` |
| `SMTP_USER` | The full Gmail address |
| `SMTP_PASS` | Gmail app password, without spaces; keep secret |
| `SMTP_FROM` | `FinGrow <your-address@gmail.com>` |
| `FINGROW_ALLOWED_ORIGINS` | `tauri://localhost,http://tauri.localhost` |

Do not copy the local `backend/.env` into Git or Vercel. Set new production signing secrets in Vercel. The local SQLite database is separate and is not copied into Turso automatically.

### 3. Point each app at the deployment

After Vercel gives you the deployment URL, use its HTTPS origin as `FINGROW_BACKEND_URL` when building both apps:

```powershell
# Desktop: run from desktop/ to produce the Windows installer
$env:FINGROW_BACKEND_URL = 'https://your-backend.vercel.app'
.\node_modules\.bin\tauri.cmd build

# Android: run from mobile/
flutter build apk --release --dart-define=FINGROW_BACKEND_URL=https://your-backend.vercel.app
```

The Tauri content policy permits Vercel HTTPS domains and local development. The Android client rejects HTTP URLs outside emulator/loopback development. If you later use a custom desktop backend domain, add that domain to `desktop/src-tauri/tauri.conf.json`'s `connect-src` policy before rebuilding.

### Hosted snapshot size

Vercel limits function requests and responses to 4.5 MB. The API applies a 4 MiB JSON body cap and a 3 MiB encrypted-envelope cap in Vercel mode to leave room for JSON/base64 overhead. Keep receipt snapshots below this limit for cross-device testing. Larger receipt files will need direct object-storage upload support before relying on Vercel for them.

## API & Endpoints

- `GET /health` — checks database initialization and reports whether SMTP settings are present.
- `POST /v1/auth/otp/request` — sends a 6-digit email OTP (rate-limited via sliding window; max 5 requests per 10 minutes per IP/email).
- `POST /v1/auth/otp/verify` — verifies 6-digit code, provisions user with scrypt password hash and consent records, and issues bearer token (max 10 attempts per 10 minutes).
- `POST /v1/auth/login` — verifies user credentials via OWASP-recommended `scrypt` hashing with unique salt and constant-time timing-safe comparison (max 10 attempts per 10 minutes).
- `GET /v1/auth/me` — returns the authenticated user's profile metadata and registered profiles.
- `POST /v1/auth/logout` — revokes the bearer token session.
- `DELETE /v1/auth/me` — **Right to Erasure (DPDP Act 2023 / GDPR Art. 17)**: permanently deletes user account, profiles, tokens, pending challenges, and all encrypted cloud snapshots.
- `POST /v1/auth/consent/withdraw` — **Consent Revocation**: deletes cloud backup snapshots and updates user consent flags.
- `GET /v1/auth/export` — **Right to Data Portability (DPDP Act 2023 / GDPR Art. 20)**: exports user account, registered profiles, and consent audit logs in structured JSON format.
- `GET /v1/profiles/:id/snapshot` — reads the zero-knowledge encrypted profile snapshot and revision.
- `PUT /v1/profiles/:id/snapshot` — atomic writes with `expectedRevision` check; stale writes return `409 Conflict`.

## Security & Compliance Architecture

- **Zero-Knowledge Encryption**: Master passwords and unencrypted financial records are never transmitted. Financial snapshots are encrypted client-side using AES-256-GCM with PBKDF2 / Argon2 keys derived locally.
- **OWASP Password Hashing**: Passwords are saved using Node.js native `crypto.scrypt` with a cryptographically secure 16-byte salt and constant-time comparison.
- **Sliding-Window Rate Limiting**: Dynamic IP and identifier tracking blocks brute-force credential stuffing and OTP spamming.
- **Strict HTTP Security Headers**: Live responses enforce `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Permissions-Policy: interest-cohort=()`, and `Content-Security-Policy: default-src 'none'`.

## Architecture & Integration Guides

- [FINGROW_ARCHITECTURE_AND_SYNC_GUIDE.md](./FINGROW_ARCHITECTURE_AND_SYNC_GUIDE.md) — Comprehensive guide covering Desktop $\leftrightarrow$ Backend $\leftrightarrow$ Mobile sync, zero-knowledge encryption, SMS processing privacy boundaries, and offline-first vault mechanics.
- [PRODUCTION_READINESS_HANDOFF.md](./PRODUCTION_READINESS_HANDOFF.md) — Production readiness audit, legal DPDP/GDPR compliance checklist, security verification, and performance benchmarks.

Browser origins use the comma-separated `FINGROW_ALLOWED_ORIGINS` allowlist. Native Android requests do not use browser CORS. OTP registration requires a working SMTP connection. Sync uses the same master password across devices to derive the shared encryption key locally; it is never sent to the server.
