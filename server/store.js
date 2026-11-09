// Per-list SQLite log: transactional and opaque to the server.
// The caller authenticates signatures before entering each synchronous transaction.
// SQLite operations and rate limits are deliberately small and bounded.
import { membershipHash } from '../web/collab/membership.js';
export const MAX_LOG_BYTES = 32 * 1024 * 1024;
const REQUESTS_PER_MINUTE = 60;
const NONCE_RETENTION_MS = 5 * 60_000;
const MAX_LISTENERS = 16;
export { MAX_LISTENERS };
const SCHEMA = `
CREATE TABLE IF NOT EXISTS lists (
  id INTEGER PRIMARY KEY CHECK (id = 1), list_id TEXT NOT NULL, genesis TEXT NOT NULL,
  owner_id TEXT NOT NULL, owner_public TEXT NOT NULL, epoch INTEGER NOT NULL,
  head TEXT NOT NULL, bytes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS changes (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, op_id TEXT NOT NULL UNIQUE,
  encoded TEXT NOT NULL, bytes INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces (
  device_id TEXT NOT NULL, nonce TEXT NOT NULL, seen_at INTEGER NOT NULL,
  PRIMARY KEY (device_id, nonce)
);
CREATE INDEX IF NOT EXISTS nonces_seen ON nonces(seen_at);
CREATE TABLE IF NOT EXISTS tickets (
  digest TEXT PRIMARY KEY, device_id TEXT NOT NULL, expires INTEGER NOT NULL
);
`;
export class SyncStore {
  constructor(storage) { this.storage = storage; this.sql = storage.sql; this.sql.exec(SCHEMA); }
  q(sql, ...params) { return this.sql.exec(sql, ...params).toArray(); }
  meta() { return this.q('SELECT * FROM lists WHERE id = 1')[0] || null; }
  bootstrap({ listId, genesis, ownerId, ownerPublic, head }) {
    return this.storage.transactionSync(() => {
      if (this.meta()) return false;
      this.sql.exec('INSERT INTO lists (id, list_id, genesis, owner_id, owner_public, epoch, head, bytes) VALUES (1, ?, ?, ?, ?, 0, ?, 0)', listId, JSON.stringify(genesis), ownerId, JSON.stringify(ownerPublic), head);
      return true;
    });
  }
  // Calls to reserveNonce must occur *within* a transaction with the operation.
  reserveNonce(auth, now) {
    this.sql.exec('DELETE FROM nonces WHERE seen_at < ?', now - NONCE_RETENTION_MS);
    const used = this.q('SELECT count(*) AS n FROM nonces WHERE device_id = ? AND seen_at > ?', auth.deviceId, now - 60_000)[0].n;
    if (used >= REQUESTS_PER_MINUTE) throw Error('rate-limit');
    const exists = this.q('SELECT 1 AS yes FROM nonces WHERE device_id = ? AND nonce = ?', auth.deviceId, auth.nonce).length;
    if (exists) throw Error('replay');
    this.sql.exec('INSERT INTO nonces (device_id, nonce, seen_at) VALUES (?, ?, ?)', auth.deviceId, auth.nonce, now);
  }
  assertMeta(expected) {
    const meta = this.meta();
    if (!meta || meta.list_id !== expected.listId) throw Error('not-found');
    if (meta.epoch !== expected.epoch || meta.head !== expected.membershipHash) throw Error('stale-epoch-or-membership');
  }
  append(auth, envelope, now) {
    return this.storage.transactionSync(() => {
      this.assertMeta(envelope);
      this.reserveNonce(auth, now);
      const encoded = JSON.stringify(envelope);
      const existing = this.q('SELECT seq, encoded FROM changes WHERE op_id = ?', envelope.opId)[0];
      if (existing) {
        if (existing.encoded !== encoded) throw Error('op-id-collision');
        return { seq: existing.seq, inserted: false };
      }
      const size = new TextEncoder().encode(encoded).length;
      const meta = this.meta();
      if (meta.bytes + size > MAX_LOG_BYTES) throw Error('list-storage-limit');
      this.sql.exec('INSERT INTO changes (op_id, encoded, bytes) VALUES (?, ?, ?)', envelope.opId, encoded, size);
      this.sql.exec('UPDATE lists SET bytes = bytes + ? WHERE id = 1', size);
      const seq = this.q('SELECT seq FROM changes WHERE op_id = ?', envelope.opId)[0].seq;
      return { seq, inserted: true };
    });
  }
  read(auth, after, now) {
    return this.storage.transactionSync(() => {
      if (!this.meta() || auth.listId !== this.meta().list_id) throw Error('not-found');
      this.reserveNonce(auth, now);
      return { changes: this.q('SELECT seq, encoded FROM changes WHERE seq > ? ORDER BY seq LIMIT 100', after).map(x => ({ seq: x.seq, envelope: JSON.parse(x.encoded) })), latest: this.latest() };
    });
  }
  readMembership(auth, now) {
    return this.storage.transactionSync(() => {
      const meta = this.meta();
      if (!meta || auth.listId !== meta.list_id) throw Error('not-found');
      this.reserveNonce(auth, now);
      return [JSON.parse(meta.genesis)];
    });
  }
  issueTicket(auth, digest, now) {
    return this.storage.transactionSync(() => {
      if (!this.meta() || auth.listId !== this.meta().list_id) throw Error('not-found');
      this.reserveNonce(auth, now);
      this.sql.exec('DELETE FROM tickets WHERE expires <= ?', now);
      this.sql.exec('INSERT INTO tickets (digest, device_id, expires) VALUES (?, ?, ?)', digest, auth.deviceId, now + 60_000);
    });
  }
  consumeTicket(digest, now) {
    return this.storage.transactionSync(() => {
      const t = this.q('SELECT device_id, expires FROM tickets WHERE digest = ?', digest)[0];
      this.sql.exec('DELETE FROM tickets WHERE digest = ?', digest);
      return t && t.expires > now ? t.device_id : null;
    });
  }
  latest() { return this.q('SELECT max(seq) AS n FROM changes')[0]?.n || 0; }
}
