import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { SyncStore } from '../server/store.js';
import { generateDeviceKeys, newListSecret, encryptOperation, digest, randomToken } from '../web/collab/crypto.js';
import { createGenesis, verifyMembership, verifyAuthorizedEnvelope } from '../web/collab/membership.js';
import { operation } from '../web/model.js';
import { signRequest, verifyRequest } from '../web/collab/auth.js';

function storage() {
  const db = new DatabaseSync(':memory:');
  return {
    sql: {
      exec(sql, ...params) {
        if (!params.length && sql.includes('CREATE TABLE IF NOT EXISTS')) { db.exec(sql); return { toArray: () => [] }; }
        const statement = db.prepare(sql);
        const result = /^\s*SELECT/i.test(sql) ? statement.all(...params) : (statement.run(...params), []);
        return { toArray: () => result };
      },
    },
    transactionSync(fn) {
      db.exec('BEGIN IMMEDIATE');
      try { const x = fn(); db.exec('COMMIT'); return x; }
      catch (e) { db.exec('ROLLBACK'); throw e; }
    },
  };
}
const owner = await generateDeviceKeys();
const evil = await generateDeviceKeys();
const listId = randomUUID();
const genesis = await createGenesis(listId, owner);
const state = await verifyMembership([genesis], { listId, ownerId: owner.deviceId, ownerSigningPublic: owner.signing.publicKey });
const secret = newListSecret();
const store = new SyncStore(storage());
function auth(device = owner, now = 100_000, nonce = randomToken(16)) { return { v: 1, listId, deviceId: device.deviceId, time: now, nonce }; }
function makeOp() { return operation(owner.deviceId, 1, [{ entity: 'list', id: listId, field: 'name', value: 'Milk' }]); }

test('one owner genesis only, immutable server trust root', () => {
  const params = { listId, genesis, ownerId: owner.deviceId, ownerPublic: owner.signing.publicKey, head: state.head.hash };
  assert.equal(store.bootstrap(params), true);
  assert.equal(store.bootstrap(params), false);
  assert.equal(store.meta().head, state.head.hash);
  assert.ok(!JSON.stringify(store.meta()).includes('Milk'));
});
test('author verifies against owner-pinned membership and wrong signer fails', async () => {
  const envelope = await encryptOperation({ listSecret: secret, listId, epoch: 0, membershipHash: state.head.hash, operation: makeOp(), device: owner });
  await verifyAuthorizedEnvelope(envelope, state);
  const bad = { ...envelope, author: evil.deviceId };
  await assert.rejects(verifyAuthorizedEnvelope(bad, state));
});
test('opaque append, retry idempotency, concurrent sequence, bounded cursor paging', async () => {
  const env = await encryptOperation({ listSecret: secret, listId, epoch: 0, membershipHash: state.head.hash, operation: makeOp(), device: owner });
  const one = store.append(auth(), env, 100_000);
  assert.deepEqual(one, { seq: 1, inserted: true });
  const repeated = store.append(auth(), env, 100_001);
  assert.deepEqual(repeated, { seq: 1, inserted: false });
  const page = store.read(auth(), 0, 100_002);
  assert.equal(page.latest, 1);
  assert.deepEqual(page.changes, [{ seq: 1, envelope: env }]);
  assert.equal(store.read(auth(), 1, 100_003).changes.length, 0);
  assert.ok(!JSON.stringify(page).includes('Milk'));
  const newer = await encryptOperation({ listSecret: secret, listId, epoch: 0, membershipHash: state.head.hash, operation: makeOp(), device: owner });
  assert.deepEqual(store.append(auth(), newer, 100_004), { seq: 2, inserted: true });
  assert.equal(store.latest(), 2);
});
test('server replay, conflicting operation ID and stale membership are rejected', async () => {
  const env = await encryptOperation({ listSecret: secret, listId, epoch: 0, membershipHash: state.head.hash, operation: makeOp(), device: owner });
  const token = auth();
  assert.equal(store.append(token, env, 110_000).inserted, true);
  assert.throws(() => store.read(token, 0, 110_001), /replay/);
  const conflict = await encryptOperation({ listSecret: secret, listId, epoch: 0, membershipHash: state.head.hash, operation: { ...makeOp(), id: env.opId }, device: owner });
  assert.throws(() => store.append(auth(), conflict, 110_002), /op-id-collision/);
  const wrongHead = await digest('different head');
  assert.throws(() => store.append(auth(), { ...env, membershipHash: wrongHead }, 110_003), /stale-epoch-or-membership/);
  assert.throws(() => store.append(auth(), { ...env, epoch: 1 }, 110_004), /stale-epoch-or-membership/);
  assert.equal(store.latest(), 3);
});
test('single-use, time-bounded WebSocket tickets', async () => {
  const ticket = randomToken(32);
  const key = await digest(ticket);
  store.issueTicket(auth(), key, 120_000);
  assert.equal(store.consumeTicket(key, 120_050), owner.deviceId);
  assert.equal(store.consumeTicket(key, 120_051), null);
  const expired = randomToken(32);
  store.issueTicket(auth(), await digest(expired), 130_000);
  assert.equal(store.consumeTicket(await digest(expired), 191_000), null);
});
test('per-member request quota rejects request number 61 within one minute', () => {
  const isolated = new SyncStore(storage());
  isolated.bootstrap({ listId, genesis, ownerId: owner.deviceId, ownerPublic: owner.signing.publicKey, head: state.head.hash });
  for (let i = 0; i < 60; i++) isolated.read(auth(), 0, 200_000 + i);
  assert.throws(() => isolated.read(auth(), 0, 200_060), /rate-limit/);
  assert.equal(isolated.read(auth(), 0, 261_000).latest, 0);
});
