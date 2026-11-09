import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { generateDeviceKeys, digest } from '../web/collab/crypto.js';
import { createGenesis, createOwnerEvent, verifyMembership, membershipHash } from '../web/collab/membership.js';
const owner = await generateDeviceKeys();
const bob = await generateDeviceKeys();
const eve = await generateDeviceKeys();
const listId = randomUUID();
const genesis = await createGenesis(listId, owner);
const trusted = (history, checkpoint = null) => verifyMembership(history, { listId, ownerId: owner.deviceId, ownerSigningPublic: owner.signing.publicKey, checkpoint });

test('owner signed genesis is pinned, not trusted from a server-provided key', async () => {
  assert.equal((await trusted([genesis])).members.size, 1);
  const rogue = await generateDeviceKeys();
  const fake = await createGenesis(listId, rogue);
  await assert.rejects(trusted([fake]));
  const tampered = { ...genesis, ownerId: randomUUID() };
  await assert.rejects(trusted([tampered]));
});
test('owner-signed join and remove, with mandatory key epoch increment', async () => {
  const join = await createOwnerEvent({ history: [genesis], owner, action: 'join', device: bob });
  const withBob = await trusted([genesis, join]);
  assert.equal(withBob.epoch, 0);
  assert.ok(withBob.members.has(bob.deviceId));
  const remove = await createOwnerEvent({ history: [genesis, join], owner, action: 'remove', device: bob.deviceId });
  const result = await trusted([genesis, join, remove]);
  assert.equal(result.epoch, 1);
  assert.equal(result.members.has(bob.deviceId), false);
  await assert.rejects(trusted([genesis, join, { ...remove, epoch: 0 }]));
  await assert.rejects(createOwnerEvent({ history: [genesis], owner, action: 'remove', device: owner.deviceId }));
});
test('pinned checkpoints detect rollback, same-sequence fork, and missing events', async () => {
  const join = await createOwnerEvent({ history: [genesis], owner, action: 'join', device: bob });
  const checkpoint = { seq: 1, hash: await membershipHash(join) };
  await assert.rejects(trusted([genesis], checkpoint));
  const fork = await createOwnerEvent({ history: [genesis], owner, action: 'join', device: eve });
  await assert.rejects(trusted([genesis, fork], checkpoint));
  const remove = await createOwnerEvent({ history: [genesis, join], owner, action: 'remove', device: bob.deviceId });
  assert.deepEqual((await trusted([genesis, join, remove], checkpoint)).head, { seq: 2, hash: await membershipHash(remove) });
  await assert.rejects(trusted([genesis, remove]));
});
test('membership mutations require owner signature; device IDs cannot be reused', async () => {
  const join = await createOwnerEvent({ history: [genesis], owner, action: 'join', device: bob });
  const forged = { ...join, signing: eve.signing.publicKey };
  await assert.rejects(trusted([genesis, forged]));
  const remove = await createOwnerEvent({ history: [genesis, join], owner, action: 'remove', device: bob.deviceId });
  const secondJoin = await createOwnerEvent({ history: [genesis, join, remove], owner, action: 'join', device: bob });
  await assert.rejects(trusted([genesis, join, remove, secondJoin]));
  await assert.rejects(trusted([genesis, { ...join, prev: await digest('another branch') }]));
});
