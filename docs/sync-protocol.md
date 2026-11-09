# Encrypted synchronization — isolated phase-2 sandbox

Status: **prototype, NOT live collaboration, NOT production ready**. This does not change the local PWA's behaviour. No server deployment is configured. The QR join UI is intentionally absent.

## Boundaries

- A list has an owner-signed immutable genesis containing the owner's **ECDSA P-256** signing and **ECDH P-256** agreement public keys. Each browser generates non-extractable private keys via Web Crypto.
- The list's **32-byte secret never goes to the server**. Each epoch derives a distinct AES-GCM operation key via HKDF-SHA-256, bound to list ID and epoch. Fresh random 96-bit IVs and authenticated associated data bind the encrypted JSON to the list, membership checkpoint, operation ID and author.
- Each operation envelope is signed by the device's ECDSA key. Server verifies the member's signature and the **current** owner-signed membership checkpoint before appending opaque bytes. Clients must independently verify the membership history against a root pinned physically; trust obtained from server data alone is insufficient.
- ECDH key delivery produces a sender-signed one-recipient package, with a fresh ephemeral sender ECDH key, HKDF, random salt, fresh AES-GCM IV and explicit list, epoch, sender, recipient and membership checkpoint binding. The recipient must first independently trust the sender signing key.
- The owner signs every membership join/removal event in a linked hash chain. Removal increments the epoch. Clients reject observed rollback/forks against a checkpoint they previously persisted. Current server implementation stores genesis only; no remote joins or removals are exposed.

## Owner-only API sandbox

All API endpoints are same-origin, HTTPS only in any remote environment. A strong, server-secret `SETUP_CODE` (minimum 24 characters, high-entropy random) is required for list creation. Do not put it into any static asset. The Worker routes to a single SQLite-backed Durable Object per list.

- `POST /api/lists`: `X-Setup-Code`, `{ "genesis": ownerSignedEvent }`. Creates a new private log, never stores the list secret.
- `GET /api/lists/:id/membership`: requires signed request; returns `{ "events": [genesis] }`.
- `POST /api/lists/:id/changes`: requires signed request and **one** signed encrypted envelope (max 16 KiB ciphertext), enforces current membership head/epoch, returns `{ "seq", "duplicate" }`.
- `GET /api/lists/:id/changes?after=<n>`: signed request; returns at most 100 ordered opaque entries and a latest sequence, to support catch-up.
- `POST /api/lists/:id/ticket`: signed empty request; issues a 60-second, one-use random WebSocket ticket.
- `GET /api/lists/:id/live?ticket=...`: WebSocket upgrade using that ticket (not an epoch secret). Sends only `{ "seq" }` hints; clients MUST fetch and verify changes over HTTPS and recover gaps after reconnect.

Signed requests use header `X-SL-Auth` with `{v,listId,deviceId,time,nonce,signature}`. The signature covers the exact method, URL path + query, exact request-body bytes digest, random 128-bit nonce and millisecond timestamp. The server verifies owner membership before transactionally storing a nonce and recording the requested effect. Nonces are retained five minutes, allowing a maximum ±120-second signature window; per-device budget 60 requests/min, 16 live listeners/list, 32 MiB encrypted log/list. Uploads are idempotent by op ID if the canonical envelope is byte-identical, otherwise fail with a conflict. A client must retry with a **fresh request nonce** but the exact same saved ciphertext envelope.

## Client invariants (not implemented in PWA yet)

1. Persist local edit and pending operation in the same IndexedDB transaction before showing success.
2. Persist non-extractable device identity and owner-pinned genesis/checkpoint before syncing or claiming QR invites.
3. Verify membership against pinned owner and monotonic checkpoint **before and after** fetching encrypted changes.
4. Verify each encrypted envelope against the **author's verified member key** and correct acceptance-time checkpoint, decrypt, validate operation model, apply idempotently, and durably advance cursor together.
5. On reconnect, fetch ordered pages until caught up. Never trust WebSocket hints for content or completeness.
6. An offline edit rejected for stale epoch/head **remains in the outbox** until the user is proven still a member and the decrypted operation is explicitly re-encrypted/signed under a current key/checkpoint. Never silently drop or upload it under an old epoch.
7. QR invitations require physical scan, expiry, unique claim, recipient key proof, a short comparison code and approval by an existing member; join cannot be enabled by merely publishing the signed membership-chain functions.

## Known security limitations

- **No end-to-end running collaborative path**: The UI still edits local lists only. The owner sync client, durable identity store, QR claim registry, comparisons/approval, key rotation and offline rebase are not implemented.
- **Server freshness / equivocation:** a hostile server may suppress newer membership events, suppress changes, fork logs or erase lists. Pinning observes rollback/forks only after a client sees a conflicting history, not an unseen newer history. Envelopes bound to the head mitigate server-admitted stale-membership writes but do not produce an external global freshness guarantee.
- **No operational deployment:** node:sqlite tests exercise the pure SQL adapter but not live Cloudflare Durable Objects, actual WebSocket hibernation, browser IndexedDB CryptoKey persistence, mobile Safari, Firefox or production abuse controls.
- **No global anonymous-creation quota** beyond the high-entropy setup code; account-level WAF/cost limits needed before public deployment. This is an explicit tradeoff against fully anonymous create-list UX.
- **No owner recovery or key escrow**. Losing every browser/list secret loses access. Browser JavaScript from the same origin can read keys while running, even if signing keys are non-extractable; a malicious deployment is outside the E2EE promise.
- The operation log currently has no compaction or encrypted snapshot. Do not ship unbounded or destructive offline retention without a separately reviewed protocol.

## Testing and next work

`npm test` covers signed request binding, irreversible membership deletion, owner-root substitution, rollback/fork checks, encrypted envelopes, forged/tampered signatures, wrong epoch/secret, recipient-bound wrapped keys, SQLite log idempotence, replay/nonces, quotas, and ticket expiry. These are not a substitute for a real cross-browser or external cryptographic audit.

Next deliverable: non-extractable keys and trusted checkpoints stored safely in IndexedDB, signed owner-only catch-up/push client, and browser tests against local Wrangler. Only then implement QR claim/approval and revoke/rebase with a separate review.
