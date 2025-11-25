# Station Mangaer: apikey package

## API keys and logbook identity — High‑level design

Purpose
- Authenticate and authorise QSO uploads per logbook.
- Keep clients simple: each logbook has one full API key and an opaque `uid`.
- Minimise leakage: the server stores only a digest of the secret, never the full key.

Identifiers
- uid: immutable, opaque ID for each logbook used externally by clients and APIs.
- logbook_id: internal sequential PK used for joins; resolved from `uid` server‑side.

API key model
- Full key format: `prefix.secretHex`.
- prefix: independent random hex string (e.g., 12–16 chars) used for indexed lookup; not derived from `secretHex`.
- secretHex: 64 hex chars (32 random bytes) shown to the client once.
- digest: server‑stored hash of `secretHex` (e.g., SHA‑512 hex) or HMAC(secretHex, PEPPER). Only the digest is stored.

Workflow (high level)
1) User creates a logbook in the desktop app.
2) Desktop app registers the logbook with the server.
3) Server generates an API key and a logbook `uid` and returns both to the client over TLS (only once).
4) Client stores the logbook metadata, full API key, and `uid` locally.
5) Client uploads QSOs with `Authorization: ApiKey <prefix>.<secretHex>` and the logbook `uid`. Server verifies and enforces integrity rules.

Server responsibilities
- Key generation: create a 32‑byte random secret, generate an independent random prefix, compute and store a digest (optionally HMAC with a server‑side pepper), associate with the logbook, and return only the full key and `uid` once.
- Key validation: parse prefix/secretHex, resolve `uid` to logbook, find an active key by prefix, recompute digest and compare in constant time, update usage metrics on success.
- Integrity on QSO writes: enforce that the logging station callsign equals the logbook’s callsign (the contacted station callsign is unconstrained).
- Rotation/revocation: support revocation; policy may enforce at most one active key per logbook.

Client responsibilities
- Store the full API key and `uid` locally with the logbook. Do not log the full key. Consider encrypting at rest.
- Include `Authorization: ApiKey <prefix>.<secretHex>` and the logbook `uid` on write requests.
- Replace the stored key when rotated.

Security notes
- Use TLS end‑to‑end.
- Prefer `uid` as the external logbook identifier.
- Consider HMAC with a server‑side pepper to harden digest storage; keep the pepper out of the database.

This document is intentionally high‑level; SQL schemas and code are documented elsewhere.
