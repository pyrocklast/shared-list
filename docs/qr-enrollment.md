# In-person QR admission — message protocol prototype

**Status:** Cryptographic messages, a transactional SQLite invitation registry and Cloudflare Worker routes are implemented in a **draft sandbox**. There is no browser UI, integrated invitation path, Cloudflare runtime test or production rollout. The application MUST NOT offer share/invite until every required step below is integrated and tested.

## Intent

An existing list member generates a **single-use, five-minute** invitation. The QR contains a fresh 256-bit random claim token, opaque list/invitation IDs, expiry, and the owner's public signing key and signed genesis hash as an independently observed trust root. **It does not contain the permanent list secret.** Never render a remotely shareable invitation link or copy/share button. URL fragments must be cleared immediately if a phone's native QR scanner opens the PWA.

The server stores only the SHA-256 token commitment and expiry. Scanned devices independently generate and persist their non-extractable signing/ECDH identities before claiming. They sign the invitation ID, token commitment and both device public keys with their own signing key as proof of possession. The registry must reject extra, expired, already-claimed and cancelled attempts *atomically*.

A claim is **pending**, not a membership grant. The existing member inspects the claimant and compares the eight-digit HMAC code **in person** with the recipient's screen, explicitly approves only if the codes match, then signs the next owner-rooted membership join event and a recipient-bound ECDH-encrypted copy of the list secret. The server must check that the signed join exactly matches the claimed public keys and consumes the invitation **once** when accepting the approved join/key-delivery package.

The recipient verifies the entire signed membership history against the owner identity scanned from QR, checks the genesis hash and its exact registered signing/ECDH identity, verifies the sender-signed recipient-only key package and decrypts the list secret. It must persist the owner pin, verified checkpoint, private keys and list secret before using the list or acknowledging success. This final persistence is still unimplemented.

## Security limitations and open work

- A QR code **cannot cryptographically prove physical proximity**. A photograph, live remote relay, malicious server or deceived approver can defeat the intended social boundary. The eight-digit code is a visual cross-check, not a security key. UI must require an independent human comparison; merely passing a computed code to the protocol function does not prove approval took place.
- The current 8-digit code is an HMAC truncated to about 27 bits: useful against accidental mismatches but not sufficient by itself for admission. It is not a substitute for server-enforced one-time token consumption and owner signature.
- A **prototype** SQLite one-use/expiry claim registry, approved join route, signed claim-result retrieval and same-device lost-response retry exist. These are tested against Node SQLite, **not live Cloudflare**. They are not integrated into the PWA and must not be treated as deployed security guarantees.
- The signed membership chain lacks global freshness proof. A malicious server can withhold new members/removals or fork histories; current pinning can only detect observed divergence.
- Revocation and key rotation are not yet connected to this path. Enrolled devices must not assume permanent access to the current secret across a key-epoch change.
- No independent cryptographic audit, tested browser private-key persistence, barcode scanning library, or deployment. The QR flow is **not production-ready**.

## Tests

`test/invite.test.mjs` covers token not containing list secrets, five-minute expiry, recipient proof of possession, modified claim rejection, matching comparison code, explicit confirmation guard, owner-signed joining, recipient-only secret delivery, substituted genesis and wrapped-key rejection. Server registry unit tests also cover five-invite cap, expiry, claim exhaustion, same-device retry, wrong-device rejection, approved membership and recipient-only result retrieval. Cloudflare runtime, actual QR scan, multi-phone and cross-browser end-to-end tests remain mandatory.
