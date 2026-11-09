# Security boundary — phase 1

This is a local-only prototype. It makes **no claims** of end-to-end multi-user encryption or safe QR onboarding.

- IndexedDB holds an encrypted document per list and AES-GCM-encrypted pending operations. Each encrypted blob gets a fresh 96-bit random IV and authenticated context.
- The associated extractable `CryptoKey` is stored **in the same IndexedDB origin**. This is a staging data format for future sharing, not a secure local vault. JavaScript from the origin, someone with the unlocked device or sufficiently privileged local access can get the data and key.
- Every UI edit must succeed as an atomic document+outbox transaction before it is called saved. A storage failure must be presented to the user.
- Revision-checked IndexedDB writes prevent two open tabs from silently overwriting each other. Changes from another tab are broadcast to refresh the projection.
- The service worker caches static code/assets only. It does not cache list data, keys, or API calls.
- No connection is made to a backend and no keys or list data are uploaded.
- The local operation format is **not** a signed server protocol. It must not be accepted as a production network envelope.

**Before enabling collaboration:** implement owner-anchored membership history, per-device non-extractable signing/agreement identities, signed replay-resistant API requests, one-time approved QR claims, epoch key rotation, old-epoch offline-write rebase, encrypted backups/recovery and global abuse controls. A QR scan cannot prove physical proximity, and a compromised application origin can deliver malicious JavaScript even with end-to-end encryption.
