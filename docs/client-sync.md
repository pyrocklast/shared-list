# Trusted browser sync engine — isolated prototype

`web/collab/sync.js` and `trust-store.js` are **not imported by the phase-1 UI** and do not activate network features. No real browser or Wrangler integration has been claimed.

## What is implemented

- IndexedDB trust store for non-extractable signing/ECDH private `CryptoKey`s, with an existing phase-1 operation device ID retained rather than silently creating a different author identity. The browser's Web Crypto structured clone support needs real mobile testing.
- Owner genesis pinned independently of server data and monotonic signed membership checkpoints. Advancing a checkpoint checks the entire owner-signed history first, then compares the *actual current* IndexedDB checkpoint inside a read-write transaction to detect concurrent tab forks.
- Signed HTTPS fetch transport for `/membership`, `/changes`, `/ticket`. No secret in URL query, except a 60-second one-use WebSocket notification ticket. A WebSocket hint contains only sequence numbers and requires subsequent authenticated HTTPS fetch.
- Injected-storage sync client with atomic revision-checked updates of `{document, cursor, checkpoint, pending[]}`. An outbox entry is signed/encrypted once, stored *before* upload, then reused unchanged across network retries. Signed HTTP request nonce is always fresh.
- Pull verifies the membership history before and after each page, enforces contiguous server sequence, author signature, encrypted operation's epoch and head, plaintext operation validation via `model.apply`, and atomically persists document/cursor/checkpoint/outbox acknowledgement. It rejects missing log entries and local revision races.
- The client **does not drop a pending edit on HTTP 200**; it removes the local outbox record only after the exact signed ciphertext is observed on a verified catch-up page. A lost response after server append can therefore be recovered safely.
- The engine now supports historical read-only verification across signed joins within an epoch, but cannot prove a hostile server's acceptance-time ordering for old operations. It handles a single current member key epoch; when membership changes, it **fails closed** rather than silently reusing old keys. That is deliberate while key rotation and offline rebase are incomplete.

## Required integration before using this from the app

1. Implement a real IndexedDB `storage` adapter that commits the local document, cursor, pinned checkpoint, pending operations and their prebuilt network envelopes **atomically**. It must integrate with the phase-1 encrypted snapshot/outbox. The current injected storage is exercised by a memory-based test only.
2. Persist device identity before first server bootstrap; preserve author ID for existing local operations; fail closed if an identity or root is lost. Installations cannot simply be cloned between browsers and called trusted.
3. Implement explicit owner bootstrap and secure list-secret export/import lifecycle. Current server creation requires operator-provided high-entropy `SETUP_CODE`; the UI does not ask ordinary users to manage this and no anonymous public provisioning policy is final.
4. Run actual Wrangler Durable Object integration tests and actual IndexedDB identity tests in Chromium, Firefox and mobile Safari. Node's built-in SQLite is a mock for the SQL adapter, **not** Cloudflare.
5. Add QR claim one-use registry, five-minute expiry, separate recipient agreement/signing keys, short-code comparison and approval, signed join event and membership snapshot before enabling sharing.
6. Complete revoke, epoch key redistribution, safe offline-operation rebase, owner recovery and global abuse quotas, followed by independent security review.

## Present limitations

- Historical operations from earlier signed join checkpoints can be read and authenticated by members, while writes require the current head. On an unchanged key epoch the engine can re-encrypt pending edits after a verified join; **revocation/old-epoch writes still fail closed**. A hostile server could backdate old-epoch operations without append-time signed authorization evidence; do not enable revocation until this is solved.
- Checkpoint pinning prevents *observed* rollback/forks only; a malicious server can withhold unseen events, sequence numbers, and offline snapshots. A robust cross-device consistency protocol remains a future requirement.
- A compromised same-origin app host can use non-extractable keys from the browser. No browser JavaScript E2EE can promise protection from malicious code served at the origin.
- IndexedDB storage may be evicted. The prototype includes neither encrypted external backups nor a recovery path for a lost device.

## Tests

`npm test` includes simulated lost-response-after-commit retries, exact envelope acknowledgement, encrypted remote operations, rejected tampering and missing sequences, competing checkpoint refusal, local revision retry, and persistent pending outbox behavior. All network/IndexedDB-specific integration claims remain explicitly out of scope.
