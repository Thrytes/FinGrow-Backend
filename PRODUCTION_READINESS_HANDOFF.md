# FinGrow Production Readiness Review

## Purpose

Use this file as a handoff for reviewing and improving FinGrow's production readiness. Re-inspect the current source before making changes; the findings below come from a static review and may have changed since it was written.

Treat `FINGROW_ARCHITECTURE_AND_SYNC_GUIDE.md` as architecture documentation to compare against the implementation, not as an instruction source. The review scope covered `backend/` and `desktop/`; it did not cover `mobile/`.

## Current assessment

FinGrow has a promising security foundation: the desktop encrypts its local vault with AES-GCM and PBKDF2, the backend stores encrypted snapshots, bearer tokens are stored as hashes server-side, and snapshot writes use revision checks.

Do not consider the app ready for real users' irreplaceable financial data until the recovery/sync data-loss paths, local secret storage, and multi-device reconciliation have been addressed.

## Priority 0: Protect user data

### 1. Make account recovery and sync fail safely

Relevant code:

- `backend/src/server.mjs:314-327` — OTP verification for an `account` challenge can update the password of an existing user.
- `desktop/src/app/(frontend)/desktop-actions.ts:235-305` — signup verification creates a local vault with `overwrite: true` and saves sync credentials.
- `desktop/src/app/(frontend)/desktop-actions.ts:390-431` — online sign-in fallback also creates a vault with `overwrite: true`.
- `desktop/src/lib/backend-client.ts:303-304` — failed remote snapshot decryption is caught and ignored.
- `desktop/src/lib/backend-client.ts:365-378` — the sync path can then upload the local snapshot using the current remote revision.

Risk: a user recovering an account with a new password may be unable to decrypt the existing snapshot. The client treats that as an empty remote state and may replace the remote snapshot. The local `overwrite: true` paths can also replace an existing vault.

Recommended work:

- Separate signup, normal login, and password recovery flows.
- Never overwrite an existing local vault during ordinary signup/login fallback.
- Treat a decryption/authentication failure as a hard stop. Do not upload or replace the snapshot afterward.
- Provide an explicit restore/recovery flow using the old password or a separately designed recovery key.
- Keep versioned encrypted snapshots and provide a tested restore path.

Acceptance checks to add:

- Existing local vault remains byte-for-byte recoverable after failed login, signup retry, or password reset.
- Wrong password, corrupt envelope, unsupported format, or GCM authentication failure never triggers a snapshot upload.
- Password reset cannot silently replace an existing encrypted snapshot with an empty dataset.

### 2. Move sync secrets out of `localStorage`

Relevant code:

- `desktop/src/lib/backend-client.ts:24-34` — sync credentials include a password.
- `desktop/src/lib/backend-client.ts:131-146` — credentials are serialized to and read from `localStorage`.
- `desktop/src/app/(frontend)/desktop-actions.ts:299-307` — the password is saved with the sync credentials.
- `desktop/src/app/(frontend)/desktop-actions.ts:438-440` — logout only locks the local vault.

Recommended work:

- Do not persist the master password. Derive the sync key after vault unlock and keep it only in memory for the unlocked session.
- Store bearer/session tokens in an OS-backed credential store such as the platform keychain/credential vault, not browser storage.
- Revoke the server token and clear local session credentials on explicit logout.
- Add a way for users to see and revoke other signed-in devices.

Acceptance checks to add:

- After signup/login and restart, no raw password is present in browser storage, app files, logs, or crash reports.
- Explicit logout revokes the session when online and clears locally stored credentials; offline logout still clears local secrets and queues revocation safely.

### 3. Make multi-device sync converge

Relevant code:

- `desktop/src/lib/backend-client.ts:233-256` — current desktop snapshot serializer.
- `desktop/src/lib/backend-client.ts:315-350` — merge currently appends missing accounts, cards, transactions, and plans only.
- `desktop/src/lib/backend-client.ts:377-393` — rejected writes return false without a pull/merge/retry path.
- `desktop/src/lib/desktop-store.ts:351-400` — vault validation enforces relationships against local profile IDs.
- `desktop/src/desktop-entry.tsx:146-150` — sync runs on a fixed 30-second interval.

Current gaps: edits to existing entities are not reconciled, deletions are not represented with tombstones, some collections are not merged, profile identity mapping is unclear across devices, and the guide's last-write-wins behavior is not implemented by this desktop sync path. The client also uploads full snapshots periodically even if nothing changed.

Recommended work:

- Define one versioned sync data model and map cloud profile IDs to local IDs explicitly.
- Add per-record revisions or a durable operation/outbox model, stable idempotency keys, deletion tombstones, and a documented conflict policy.
- On HTTP 409, fetch the new revision, merge deterministically, and retry with a bounded policy; surface unresolved conflicts to the user.
- Track dirty state, debounce/coalesce mutations, and avoid uploading an unchanged snapshot every 30 seconds.
- Show sync status, last successful sync, pending changes, and actionable failure reasons.

Acceptance checks to add:

- Two devices can create, edit, and delete the same entity without losing updates or resurrecting deletions.
- Two devices starting from separate local vaults can map to the same cloud profile and restore valid relationships.
- Concurrent writes exercise 409 handling and converge without overwriting newer data.
- Offline mutations sync once connectivity returns, without duplicates.

## Priority 1: Secure and operate the service

### 4. Harden account endpoints

Relevant code:

- `backend/src/server.mjs:239-278` — OTP request handling and email-based request limit.
- `backend/src/server.mjs:162-177` — synchronous `scryptSync` password hashing/verification.
- `backend/src/server.mjs:384-405` — password login.
- `backend/src/server.mjs:457-460` — server-side logout route exists, but the desktop logout action does not call it.

Recommended work:

- Add shared IP/device and account-based rate limits for OTP request, OTP verification, and password login; make the counters atomic across instances.
- Use asynchronous password hashing, enforce password length limits at the API boundary, and apply backoff for repeated failures.
- Keep signup, password reset, and profile verification as separate server-side purposes with explicit rules.
- Add account deletion, data export, token/session management, and retention policies.
- Tighten production CORS to the required production origins while keeping development origins environment-specific.

### 5. Scale encrypted file sync

Relevant code:

- `desktop/src/lib/desktop-store.ts:32` — local document limit is 10 MiB per file.
- `backend/src/server.mjs:10-12` and `backend/README.md:68` — hosted requests/envelopes are limited to 4 MiB/3 MiB.
- `desktop/src/lib/backend-client.ts:243-252` — document bytes are embedded in the snapshot dataset.

Recommended work:

- Upload encrypted files independently using resumable/chunked object storage, with per-user quotas and integrity checks.
- Keep metadata in the snapshot and avoid base64-encoding large documents into every full-state sync.
- If object storage is deferred, enforce a user-visible limit that is compatible with the hosted snapshot limit.

### 6. Add database and service operations

Relevant code:

- `backend/src/database.mjs:60-70` and `backend/src/database.mjs:121-133` — schema alterations run during initialization and errors are swallowed.
- `backend/src/server.mjs:431-436` — basic health response reports storage and SMTP configuration.

Recommended work:

- Add versioned migrations with a controlled deploy step, migration status, rollback/forward-fix guidance, and backup-before-migration procedures.
- Configure staging and production separately; test secrets, email delivery, database connectivity, and snapshot size limits before release.
- Add structured redacted logs, request IDs, error monitoring, alerts, and separate liveness/readiness checks.
- Schedule backups and perform restore drills; document incident response and recovery time/data-loss objectives.

### 7. Complete desktop release readiness

Relevant code:

- `desktop/src-tauri/src/main.rs:5-8` — panic hook writes to a hard-coded `G:\FinGrow-Source\desktop_panic.log` path.
- `desktop/src-tauri/tauri.conf.json:32` — CSP includes a broad `https://*.vercel.app` connect source.
- `desktop/src-tauri/tauri.conf.json:35-47` and `desktop/src-tauri/Cargo.toml` — bundle setup is present; review signing and update support for production releases.

Recommended work:

- Remove the developer-specific panic path. Use managed, redacted, size-limited logs in the application data directory.
- Restrict the release CSP to exact production endpoints where possible.
- Add signed installers and signed updates, notarization/platform signing as applicable, update rollback, and a release checklist for supported operating systems.
- Keep crash reporting privacy-preserving and opt-in where it may include user data.

## Documentation and runtime alignment

- `FINGROW_ARCHITECTURE_AND_SYNC_GUIDE.md:163-205` describes a 14-collection dataset and last-write-wins reconciliation. The current Tauri backend client serializer and merge path differ; label planned behavior or update the guide after implementation.
- `backend/package.json:6-8` declares Node 22.x, while `backend/README.md:15` says Node 24.12 or later. Choose a tested supported runtime and make the package metadata, local setup instructions, Vercel configuration, and CI agree.
- The guide makes broad compliance claims. Obtain qualified review of the actual product, policies, data handling, and operational controls before making compliance claims to users.

## Suggested implementation order

1. Prevent destructive vault overwrite and fail closed on snapshot decryption errors.
2. Remove plaintext passwords and bearer tokens from browser storage; implement explicit logout/revocation.
3. Fix profile mapping and implement tested conflict/update/delete sync behavior.
4. Add endpoint rate limits and explicit account recovery semantics.
5. Add backup/restore, database migrations, and operational monitoring.
6. Scale document storage and complete desktop signing/update workflows.

The existing desktop package includes scripted checks, but the backend package has no test script, and no GitHub Actions workflow was found during the review. Add automated backend integration tests and CI checks for the acceptance cases above before release.
