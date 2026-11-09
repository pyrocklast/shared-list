# Shared List (working name)

A new, independent **local-first shopping-list PWA**. The current release is a **working phase-1 prototype**, not a collaborative or production-secure app.

## Implemented

- Installable, responsive web app with **no runtime dependencies, framework or build step**.
- Multiple lists, named and renameable.
- Editable, reorderable sections under unchecked items. Starts with one section; only empty sections can be removed.
- Add, edit, move, check, uncheck and delete items. Completed items live in one collapsible group and retain their section.
- Local persistence in IndexedDB, including after reload; offline app shell through a service worker.
- Small deterministic field-level merge model, deletion tombstones, and an atomic **encrypted** local operation outbox for future synchronization.
- Light/dark system theme, French/English UI, keyboard controls, reduced-motion support.

## Not implemented

**No server, real-time sync, invitations, QR codes, member removal or cross-device encryption yet.** The app is explicitly labelled as local-only in the UI. The local encryption key is stored alongside encrypted documents in the same browser origin and is extractable to allow a future enrollment protocol. It **does not protect against compromised JavaScript, device access or a malicious app host**. Never use this version for sensitive or irreplaceable data.

## Run

Requires a modern browser and Python 3 for the static development server:

```bash
python3 -m http.server 8080 --directory web
# Open http://localhost:8080
```

`localhost` is a secure browser context, so Web Crypto and service workers work without HTTPS. On a phone over the local network, use **HTTPS** (plain `http://LAN-IP` won't reliably support cryptography/PWA features).

Test the pure model with Node.js 20+:

```bash
npm test
```

Install the PWA using the browser's installation or *Add to Home Screen* action. Visit it once while online to cache its shell, then it can reopen offline. Browser storage remains subject to eviction: there is no encrypted export or recovery yet.

## How it works

```text
web/app.js                 UI, input validation and accessibility
web/model.js               Small deterministic operation reducer
web/db.js                  IndexedDB and atomic local outbox
web/crypto.js              AES-GCM local blob encoding and authentication
web/sw.js                  Offline shell only
web/i18n.js                French and English strings
web/style.css              Responsive system-theme styling
```

Every local edit gets a unique operation ID, a device ID and a logical clock; unrelated fields merge independently. The entire list snapshot and pending operation are encrypted with fresh AES-GCM nonces and committed to IndexedDB together. Concurrent tabs use a revision check and retry to avoid overwriting writes. Deletions are permanent tombstones for each entity ID. The on-device outbox is **not uploaded**: phase 2 introduces signed, epoch-bound network envelopes instead of pretending the local format is a deployable protocol.

## Next milestones

1. Define/test canonical signing encoding, per-device ECDSA/ECDH identities, epoch keys and encrypted network operation envelopes.
2. Add a single Cloudflare Worker + SQLite-backed Durable Object store with idempotent encrypted operations, authenticated WebSocket hints and HTTPS catch-up/retry.
3. Build one-use, five-minute physical QR enrollment with comparison code and explicit approval; do not put persistent list secrets in a QR.
4. Implement owner-root membership checks, revocation, epoch rotation, offline rebase, encrypted recovery and abuse controls.
5. Independent security review and cross-device Safari/Firefox/Chrome testing before public use.

A phase-1 manual QA checklist is in [`docs/checklist.md`](docs/checklist.md). Browser E2E has not yet been executed in this environment. The detailed architectural blueprint remains separate. These later phases are neither implemented nor claimed secure.

## Licence

[MIT](LICENSE). New code, created separately from `pyrocklast/panier`.
