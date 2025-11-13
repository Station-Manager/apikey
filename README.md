# API key workflow and integrity rules

This document outlines a high‑level design for creating logbooks and API keys, how requests are authenticated and authorised, and the integrity constraints to ensure only authorised clients can create/update/delete QSOs for a given logbook.

Notes and goals
- The server stores only public‑domain data but must prevent unauthorised modification.
- Every QSO belongs to exactly one logbook (internal FK).
- Each logbook has its own API key. Clients must present that API key together with the logbook’s identifier. The logging station callsign must match the logbook’s callsign.
- The contacted station callsign (the QSO "call") is separate and does not need to match the logbook’s callsign.

Terminology
- full key: the client‑visible value shaped as `prefix.secretHex`.
- prefix: an independent random hex string (e.g., 12–16 hex chars) used for indexed lookup; it is not derived from `secretHex` and therefore leaks no information about it.
- secretHex: the 64‑character hex encoding of a 32‑byte random secret; it is the portion after the dot.
- digest: the server‑stored hash of the `secretHex` string (e.g., SHA‑512 hex), or an HMAC of that value with a server‑side pepper.
- uid: an immutable, opaque identifier on the logbook used in external protocols. Internally, a sequential `logbook_id` remains the PK/FK for joins.

Workflow (high level)
1) User creates a logbook in the desktop application.
   - If the user wants to upload QSOs to the server, they must register the logbook with the server first.
   - The desktop app can continue to function without registering the logbook with the server.
2) The desktop app registers the logbook with the server.
3) The server creates an API key and an immutable opaque `uid` for that logbook and returns both to the desktop app over TLS (only once).
4) The desktop app stores the logbook metadata, the full API key, and the `uid` locally.
5) The desktop app pushes QSOs with `Authorization: ApiKey <prefix>.<secretHex>` and the logbook `uid`. The server verifies the key, enforces callsign integrity, and updates usage counters.

Server‑side

Key generation (high level)
- Generate a 32‑byte random secret and encode as `secretHex` (64 hex characters).
- Generate an independent random `prefix` (e.g., 12–16 hex characters); do not derive it from `secretHex`.
- Compute a `digest` over `secretHex` (e.g., SHA‑512 hex). Optionally use HMAC with a server‑side pepper.
- Persist the API key information associated with the logbook (reference to the logbook, `key_prefix`, `key_hash`, metadata). The logbook’s `uid` is stored on the logbook, not on the key.
- Return the full key `prefix.secretHex` and the `uid` to the client over TLS (only once).

Key validation (high level)
- Parse `prefix` and `secretHex` from the Authorization header.
- Resolve `uid` (from the request) to the internal logbook.
- Locate the candidate API key by that logbook and `key_prefix` (must be active and unexpired).
- Compute the digest of the provided `secretHex` and compare to the stored `key_hash` using constant‑time comparison (or HMAC if adopted).
- On QSO writes, enforce that the QSO’s logging station callsign equals the logbook’s callsign; the contacted station callsign (`qso.call`) is unconstrained.
- If all checks pass, authorise the request, update usage counters (e.g., `use_count`, `last_used_at`).

Rotation and revocation (high level)
- Keys can be revoked. Optionally allow multiple active keys per logbook or enforce at most one active key, depending on operational needs.
- On rotation, issue a new key and provide its full value to the client; the client replaces the stored key.

Client‑side

Key storage and handling (high level)
- Store the full API key and the logbook `uid` locally with the logbook metadata.
- Do not store digests locally; they provide no client‑side benefit.
- Never log the full API key. Consider encrypting it at rest depending on the threat model.

Authentication and authorisation
- The API key is used both for authentication (proving possession of the secret) and for authorisation (scoping access to the specific logbook).
- Prefer using the logbook `uid` as the external identifier in requests, not names or callsigns.

Design choices (rationale)
- Independent random prefix: avoids leaking information about `secretHex`, keeps lookups efficient, and simplifies generation.
- Hashing vs HMAC: hashing `secretHex` with SHA‑512 provides strong server‑side secrecy for randomly generated secrets; HMAC with a server‑side pepper further hardens against database compromise.

See also
- Server component high‑level design: ../server/README.md
