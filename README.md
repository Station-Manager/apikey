# API key workflow and integrity rules

This document describes the recommended end‑to‑end flow for creating logbooks and API keys, how requests are authenticated, and what integrity constraints should be enforced so only authorised clients can create/update/delete QSOs for a given logbook.

Notes and goals
- The server stores only public-domain data but must prevent unauthorised modification.
- Every QSO belongs to exactly one logbook (FK).
- Each logbook has its own API key. Requests must present that API key together with the logbook’s callsign. The logging station callsign must match the logbook’s callsign.
- The contacted station callsign (the QSO "call") is separate and is not required to match the logbook’s callsign.

Terminology
- full key: the value the client uses, shaped as `prefix.secretHex`.
- prefix: short leading substring of the secret used for indexed lookup.
- digest: the server-stored hash (e.g., SHA‑512 hex) of the secret (or HMAC of secret with a server-side pepper).

Recommended workflow
1) User authenticates in a web UI and creates a logbook on the server.
2) Server generates an API key for that logbook:
   - secret = 32 random bytes; secretHex = hex(secret)
   - prefix = first N hex chars (e.g., 10)
   - digest = SHA‑512(secret) encoded as hex (128 chars). Optionally use HMAC‑SHA256/512 with a server-side pepper for extra protection.
   - Persist: api_keys(logbook_id, key_name, key_prefix, key_hash=digest, created_at, …)
   - Return full key = `prefix.secretHex` to the client over TLS (only once).
3) Client stores locally (SQLite) the logbook metadata and the full key:
   - name, description, callsign
   - full API key (keep secret locally only; don’t re-send to server except as per-request auth)
4) When the client pushes QSOs to the server, every request includes:
   - Authorization: `ApiKey <prefix>.<secretHex>`
   - Logbook identifier: either `logbook_id` or (`logbook_name` + `callsign`)
   - Each QSO is linked with `logbook_id`. If QSO also carries a logging station callsign, it must equal the logbook’s callsign.
5) Server verification (per request):
   - Parse `prefix` and `secretHex` from the Authorization header.
   - Find candidate api_keys by (logbook_id, key_prefix) where revoked_at IS NULL and (expires_at IS NULL or expires_at > now()).
   - Compute digest of the provided secret (SHA‑512 of raw secret bytes, or HMAC with pepper) and compare to stored `key_hash` using constant-time comparison.
   - Validate that the provided logbook callsign equals the stored logbook.callsign.
   - On QSO writes, enforce that the logging station callsign equals the logbook’s callsign (if the field is present); the contacted station callsign (`qso.call`) is unconstrained.
   - If all checks pass, authorise; update `use_count`, set `last_used_at`.
6) Rotation/revocation:
   - Keys can be revoked (set `revoked_at`). Optionally allow multiple keys per logbook; at most one active key can be enforced with a partial unique index.
   - On rotation, issue a new key, store its digest, return the new full key; the client replaces its stored key.

Why SHA‑512 (and when to consider HMAC)
- With 32 bytes of random secret, a fast cryptographic hash (SHA‑512) is sufficient to store server-side digests.
- To harden against DB compromise, consider computing and storing HMAC(secret, server_pepper) instead of a plain hash. The pepper is kept out of the database (env/secret manager). Both SHA‑512 and HMAC‑SHA256 are fine; HMAC‑SHA256 yields a 64‑char hex digest.

Database recommendations (PostgreSQL)
- api_keys should be linked to logbooks:
  - Add `logbook_id BIGINT NOT NULL REFERENCES logbook(id)`
  - Index `(logbook_id, key_prefix)` for efficient lookup
  - Optional: enforce at most one active key per logbook with a partial unique index:
    - `CREATE UNIQUE INDEX idx_api_keys_one_active_per_logbook ON api_keys (logbook_id) WHERE revoked_at IS NULL;`
- qso already references logbook via `logbook_id`.
  - If you need to persist the logging station callsign explicitly, add a `station_callsign` column to qso or normalize it via logbook; otherwise enforce the equality at the application layer since cross-table CHECKs aren’t supported.
- Keep `key_hash VARCHAR(128)` if using SHA‑512 hex; if you pick HMAC‑SHA256 hex, 64 chars suffice.

Client (SQLite) storage
- Store the full API key locally, associated with the logbook.
- Do not store a hash locally; it offers no benefit to the client.
- Never log the full key. Consider encrypting it at rest if the threat model includes local compromise.

What to fix in the previous draft
- Typo: “registed” → “registered”.
- Numbering/order and roles:
  - The server, not the client, generates the API key and stores only the digest.
  - The client stores the full key locally.
  - The client sends the API key on each request in the Authorization header; there is no separate “send once” registration step unless you choose a client-generated flow.
- Hashing algorithm consistency: use SHA‑512 (128‑char hex) as implemented, or explicitly state HMAC if adopted.
- Clarity on callsigns:
  - The logbook’s callsign must be supplied and must match the logging station.
  - The QSO’s contacted station callsign (`qso.call`) does not need to match the logbook’s callsign.

Optional enhancements
- Add `hash_algo` or `version` column to `api_keys` to support future migrations (e.g., from SHA‑512 to HMAC‑SHA256) without breaking existing keys.
- Add `allowed_ips` filtering and `scopes` checks in middleware for finer-grained authorisation (columns already exist).
- Emit structured audit logs on key verification and QSO writes.
