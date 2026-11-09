import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createSyncClient } from '../web/collab/sync.js';
import { generateDeviceKeys, newListSecret, encryptOperation } from '../web/collab/crypto.js';
import { createGenesis, verifyMembership } from '../web/collab/membership.js';
import { apply, emptyDocument, operation } from '../web/model.js';
const listId = randomUUID();
const device = await generateDeviceKeys();
const secret = newListSecret();
const genesis = await createGenesis(listId, device);
const trust = await verifyMembership([genesis], { listId, ownerId: device.deviceId, ownerSigningPublic: device.signing.publicKey });
let time = 1;
const makeOp = name => operation(device.deviceId, time++, [{ entity: 'list', id: listId, field: 'name', value: name }]);

class MemoryStorage {
  constructor(doc, pending = []) { this.state = { rev: 1, document: doc, cursor: 0, checkpoint: trust.head, pending }; this.failOnce = false; }
  async read() { return structuredClone(this.state); }
  async commit(rev, next) {
    if (this.failOnce) { this.failOnce = false; return false; }
    if (rev !== this.state.rev) return false;
    this.state = structuredClone({ ...next, rev: rev + 1 }); return true;
  }
}
class FakeTransport {
  constructor() { this.log = []; this.nextFailure = null; this.tries = []; this.events = [genesis]; }
  async membership() { return { events: this.events }; }
  async page(cursor) { return { latest: this.log.length, changes: this.log.map((envelope, i) => ({ seq: i + 1, envelope })).filter(x => x.seq > cursor).slice(0, 100) }; }
  async append(env) {
    this.tries.push(structuredClone(env));
    const existing = this.log.find(x => x.opId === env.opId);
    if (existing && JSON.stringify(existing) !== JSON.stringify(env)) throw Error('op-id-collision');
    if (!existing) this.log.push(structuredClone(env));
    if (this.nextFailure === 'after') { this.nextFailure = null; throw Error('network-disconnected'); }
    return { seq: this.log.findIndex(x => x.opId === env.opId) + 1, duplicate: !!existing };
  }
  async ticket() { return { ticket: 'not-used' }; }
}
function client(st, transport) { return createSyncClient({ listId, device, secret, ownerId: device.deviceId, ownerSigningPublic: device.signing.publicKey, storage: st, transport }); }

test('local offline changes upload once and only clear after verified catch-up', async () => {
  const a = makeOp('Groceries'); const b = makeOp('Updated groceries');
  const doc = apply(apply(emptyDocument(listId), a), b);
  const storage = new MemoryStorage(doc, [{ op: a }, { op: b }]);
  const t = new FakeTransport();
  const result = await client(storage, t).synchronize();
  assert.deepEqual(result, { received: 2, sent: 2 });
  assert.equal(t.log.length, 2);
  assert.equal((await storage.read()).pending.length, 0);
  assert.equal((await storage.read()).cursor, 2);
  assert.equal((await client(storage, t).synchronize()).sent, 0);
});
test('lost response after commit: next pull acknowledges identical saved encrypted op', async () => {
  const a = makeOp('Lemons');
  const storage = new MemoryStorage(apply(emptyDocument(listId), a), [{ op: a }]);
  const t = new FakeTransport();
  t.nextFailure = 'after';
  await assert.rejects(client(storage, t).synchronize(), /network-disconnected/);
  assert.equal(t.log.length, 1);
  const saved = (await storage.read()).pending[0].envelope;
  assert.ok(saved?.signature);
  assert.equal((await client(storage, t).synchronize()).sent, 0);
  assert.equal((await storage.read()).pending.length, 0);
  assert.equal(t.tries.length, 1);
});
test('encrypted remote update applies to local document and advances cursor atomically', async () => {
  const a = makeOp('Bread');
  const t = new FakeTransport();
  t.log.push(await encryptOperation({ listSecret: secret, listId, epoch: 0, membershipHash: trust.head.hash, operation: a, device }));
  const storage = new MemoryStorage(emptyDocument(listId));
  assert.equal(await client(storage, t).pull(), 1);
  assert.equal((await storage.read()).document.list.name.value, 'Bread');
  assert.equal((await storage.read()).cursor, 1);
  assert.equal(await client(storage, t).pull(), 0);
});
test('tampered encrypted operation or missing log sequence must not change cursor', async () => {
  const t = new FakeTransport();
  const a = makeOp('Flour');
  const env = await encryptOperation({ listSecret: secret, listId, epoch: 0, membershipHash: trust.head.hash, operation: a, device });
  t.log.push({ ...env, data: env.data.slice(0, -1) + (env.data.endsWith('A') ? 'B' : 'A') });
  const storage = new MemoryStorage(emptyDocument(listId));
  await assert.rejects(client(storage, t).pull());
  assert.equal((await storage.read()).cursor, 0);
  t.log = [env, env];
  const brokenTransport = { ...t, membership: t.membership.bind(t), page: async () => ({ latest: 2, changes: [{ seq: 2, envelope: env }] }) };
  await assert.rejects(client(storage, brokenTransport).pull(), /missing-or-reordered-operation/);
  assert.equal((await storage.read()).cursor, 0);
});
test('conflicting membership checkpoint rejects pending writes without discarding data', async () => {
  const a = makeOp('Tea');
  const storage = new MemoryStorage(apply(emptyDocument(listId), a), [{ op: a }]);
  const t = new FakeTransport();
  t.events = [genesis, { ...genesis, seq: 1 }];
  await assert.rejects(client(storage, t).synchronize());
  assert.equal((await storage.read()).pending.length, 1);
});
test('revision check retry handles simultaneous local mutation', async () => {
  const a = makeOp('Eggs');
  const storage = new MemoryStorage(emptyDocument(listId));
  storage.failOnce = true;
  const t = new FakeTransport();
  t.log.push(await encryptOperation({ listSecret: secret, listId, epoch: 0, membershipHash: trust.head.hash, operation: a, device }));
  assert.equal(await client(storage, t).pull(), 1);
  assert.equal((await storage.read()).cursor, 1);
});
