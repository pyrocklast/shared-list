// Per-list SQLite log: transactional and opaque to the server.
// The caller authenticates signatures before entering each synchronous transaction.
// SQLite operations and rate limits are deliberately small and bounded.
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
CREATE TABLE IF NOT EXISTS member_events (
  seq INTEGER PRIMARY KEY, event TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
  invite_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, expires INTEGER NOT NULL,
  status TEXT NOT NULL, claim TEXT, wrapped TEXT, event TEXT, approved_at INTEGER
);
CREATE INDEX IF NOT EXISTS invites_active ON invites(status, expires);
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
  history() {
    const meta = this.meta();
    if (!meta) throw Error('not-found');
    return [JSON.parse(meta.genesis), ...this.q('SELECT event FROM member_events ORDER BY seq').map(x => JSON.parse(x.event))];
  }
  readMembership(auth, now) {
    return this.storage.transactionSync(() => {
      const meta = this.meta();
      if (!meta || auth.listId !== meta.list_id) throw Error('not-found');
      this.reserveNonce(auth, now);
      return this.history();
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
  registerInvite(auth, invite, now) {
    return this.storage.transactionSync(() => {
      const meta = this.meta();
      if (!meta || auth.deviceId !== meta.owner_id || invite.listId !== meta.list_id) throw Error('unauthorized');
      this.reserveNonce(auth, now);
      if (!Number.isSafeInteger(invite.expiresAt) || invite.expiresAt <= now || invite.expiresAt > now + 300_000) throw Error('invalid-invite-expiry');
      const active = this.q("SELECT count(*) AS n FROM invites WHERE status IN ('open','claimed') AND expires > ?", now)[0].n;
      if (active >= 5) throw Error('invite-limit');
      if (this.q('SELECT 1 AS yes FROM invites WHERE invite_id = ?', invite.invitationId).length) throw Error('invite-exists');
      this.sql.exec("INSERT INTO invites (invite_id, token_hash, expires, status) VALUES (?, ?, ?, 'open')", invite.invitationId, invite.tokenHash, invite.expiresAt);
      return { invitationId: invite.invitationId, expiresAt: invite.expiresAt };
    });
  }
  invite(invitationId) { return this.q('SELECT * FROM invites WHERE invite_id = ?', invitationId)[0] || null; }
  listInvites(auth, now) {
    return this.storage.transactionSync(() => {
      const meta = this.meta();
      if (!meta || meta.owner_id !== auth.deviceId) throw Error('unauthorized');
      this.reserveNonce(auth, now);
      return this.q("SELECT invite_id, expires, status, claim FROM invites WHERE expires > ? AND status IN ('open','claimed') ORDER BY expires LIMIT 5", now).map(i => ({ invitationId: i.invite_id, expiresAt: i.expires, status: i.status, claim: i.claim ? JSON.parse(i.claim) : null }));
    });
  }
  claimInvite(invitationId, tokenHash, claim, now) {
    return this.storage.transactionSync(() => {
      const invite = this.invite(invitationId);
      if (!invite || invite.token_hash !== tokenHash || invite.expires <= now) throw Error('invalid-invite');
      if (invite.status === 'claimed') {
        const original = JSON.parse(invite.claim);
        const identity = c => JSON.stringify([c.listId, c.invitationId, c.tokenHash, c.deviceId, c.signing, c.agreement]);
        if (identity(original) !== identity(claim)) throw Error('invite-already-claimed');
        // Same identity may retry after lost response, with fresh ECDSA signature.
        return { claimed: true, repeated: true };
      }
      if (invite.status !== 'open') throw Error('invite-already-used');
      this.sql.exec("UPDATE invites SET status = 'claimed', claim = ? WHERE invite_id = ?", JSON.stringify(claim), invitationId);
      return { claimed: true, repeated: false };
    });
  }
  approveInvite(auth, invitationId, join, wrapped, expectedHead, newHead, now) {
    return this.storage.transactionSync(() => {
      const meta = this.meta();
      const invite = this.invite(invitationId);
      if (!meta || meta.owner_id !== auth.deviceId || !invite || invite.status !== 'claimed' || invite.expires <= now) throw Error('approval-unavailable');
      if (meta.head !== expectedHead || join.prev !== expectedHead || join.seq !== this.history().length) throw Error('stale-epoch-or-membership');
      const claim = JSON.parse(invite.claim);
      if (join.deviceId !== claim.deviceId || JSON.stringify(join.signing) !== JSON.stringify(claim.signing) || JSON.stringify(join.agreement) !== JSON.stringify(claim.agreement)) throw Error('claim-substitution');
      this.reserveNonce(auth, now);
      this.sql.exec('INSERT INTO member_events (seq, event, hash) VALUES (?, ?, ?)', join.seq, JSON.stringify(join), newHead);
      this.sql.exec('UPDATE lists SET head = ? WHERE id = 1', newHead);
      this.sql.exec("UPDATE invites SET status = 'approved', wrapped = ?, event = ?, approved_at = ? WHERE invite_id = ?", JSON.stringify(wrapped), JSON.stringify(join), now, invitationId);
      return { head: newHead, joined: join.deviceId };
    });
  }
  cancelInvite(auth, invitationId, now) {
    return this.storage.transactionSync(() => {
      const meta = this.meta(); const invite = this.invite(invitationId);
      if (!meta || meta.owner_id !== auth.deviceId || !invite || !['open','claimed'].includes(invite.status)) throw Error('cancellation-unavailable');
      this.reserveNonce(auth, now);
      this.sql.exec("UPDATE invites SET status = 'cancelled' WHERE invite_id = ?", invitationId);
      return true;
    });
  }
  inviteResult(auth, invitationId, tokenHash, now) {
    return this.storage.transactionSync(() => {
      const invite = this.invite(invitationId);
      if (!invite || invite.token_hash !== tokenHash || !['claimed','approved'].includes(invite.status)) throw Error('invalid-invite');
      const claim = JSON.parse(invite.claim);
      if (auth.deviceId !== claim.deviceId || (invite.status === 'claimed' && invite.expires <= now)) throw Error('invalid-recipient');
      if (invite.status === 'approved' && now > invite.approved_at + 600_000) throw Error('result-expired');
      this.reserveNonce(auth, now);
      if (invite.status !== 'approved') return { status: 'pending' };
      return { status: 'approved', history: this.history(), wrapped: JSON.parse(invite.wrapped) };
    });
  }
  latest() { return this.q('SELECT max(seq) AS n FROM changes')[0]?.n || 0; }
}
