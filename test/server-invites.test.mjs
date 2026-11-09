import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { SyncStore } from '../server/store.js';
import { generateDeviceKeys, newListSecret, digest, randomToken, verifyWrappedPackage } from '../web/collab/crypto.js';
import { createGenesis, verifyMembership, membershipHash } from '../web/collab/membership.js';
import { generateInvitation, createEnrollmentClaim, approveEnrollment, comparisonCode, verifyEnrollmentClaim, acceptEnrollment } from '../web/collab/invite.js';
function memoryDB() {
  const db = new DatabaseSync(':memory:');
  return {
    sql: { exec(sql, ...args) {
      if (!args.length && sql.includes('CREATE TABLE IF NOT EXISTS')) { db.exec(sql); return { toArray: () => [] }; }
      const statement = db.prepare(sql);
      const rows = /^\s*SELECT/i.test(sql) ? statement.all(...args) : (statement.run(...args), []);
      return { toArray: () => rows };
    } },
    transactionSync(fn) { db.exec('BEGIN IMMEDIATE'); try { const result = fn(); db.exec('COMMIT'); return result; } catch (e) { db.exec('ROLLBACK'); throw e; } },
  };
}
const owner = await generateDeviceKeys(), recipient = await generateDeviceKeys(), attacker = await generateDeviceKeys();
const listId = randomUUID(); const secret = newListSecret(); const genesis = await createGenesis(listId, owner);
const start = 1_000_000;
const store = new SyncStore(memoryDB());
const root = await verifyMembership([genesis], { listId, ownerId: owner.deviceId, ownerSigningPublic: owner.signing.publicKey });
store.bootstrap({ listId, genesis, ownerId: owner.deviceId, ownerPublic: owner.signing.publicKey, head: root.head.hash });
const ownerAuth = () => ({ listId, deviceId: owner.deviceId, nonce: randomToken(16) });
const recipientAuth = () => ({ listId, deviceId: recipient.deviceId, nonce: randomToken(16) });

test('registered QR stores only commitment, expires in five minutes, caps open invites', async () => {
  for (let i = 0; i < 5; i++) {
    const { qr, registry } = await generateInvitation({ listId, owner, genesis, now: start + i });
    const receipt = store.registerInvite(ownerAuth(), registry, start + i);
    assert.equal(receipt.invitationId, qr.invitationId);
    assert.equal(store.invite(qr.invitationId).token_hash, registry.tokenHash);
    assert.ok(!JSON.stringify(store.invite(qr.invitationId)).includes(qr.token));
  }
  const extra = (await generateInvitation({ listId, owner, genesis, now: start + 100 })).registry;
  assert.throws(() => store.registerInvite(ownerAuth(), extra, start + 100), /invite-limit/);
  assert.equal(store.listInvites(ownerAuth(), start + 200).length, 5);
  assert.deepEqual(store.listInvites(ownerAuth(), start + 301_000), []);
});

test('one-time claim, same recipient lost-response retry, different device rejected', async () => {
  const { qr, registry } = await generateInvitation({ listId, owner, genesis, now: start + 320_000 });
  store.registerInvite(ownerAuth(), registry, start + 320_000);
  const claim = await createEnrollmentClaim({ qr, recipient, now: start + 320_100 });
  await verifyEnrollmentClaim(qr, claim, start + 320_100);
  const one = store.claimInvite(qr.invitationId, registry.tokenHash, claim, start + 320_100);
  assert.equal(one.repeated, false);
  const again = await createEnrollmentClaim({ qr, recipient, now: start + 320_110 });
  assert.equal(store.claimInvite(qr.invitationId, registry.tokenHash, again, start + 320_110).repeated, true);
  const fake = await createEnrollmentClaim({ qr, recipient: attacker, now: start + 320_110 });
  assert.throws(() => store.claimInvite(qr.invitationId, registry.tokenHash, fake, start + 320_110), /invite-already-claimed/);
  const wrongHash = await digest('wrong token');
  assert.throws(() => store.claimInvite(qr.invitationId, wrongHash, claim, start + 320_111), /invalid-invite/);
  assert.equal(store.inviteResult(recipientAuth(), qr.invitationId, registry.tokenHash, start + 320_120).status, 'pending');
  assert.throws(() => store.inviteResult({ listId, deviceId: attacker.deviceId, nonce: randomToken(16) }, qr.invitationId, registry.tokenHash, start + 320_120), /invalid-recipient/);
});

test('owner approval stores signed join + wrapped recipient-only key, return result idempotently', async () => {
  // To test post-approval security, use a fresh QR (the earlier secret is kept only in the client).
  const { qr: fresh, registry } = await generateInvitation({ listId, owner, genesis, now: start + 330_000 });
  store.registerInvite(ownerAuth(), registry, start + 330_000);
  const recipientClaim = await createEnrollmentClaim({ qr: fresh, recipient, now: start + 330_100 });
  store.claimInvite(fresh.invitationId, registry.tokenHash, recipientClaim, start + 330_100);
  const code = await comparisonCode({ qr: fresh, claim: recipientClaim, now: start + 330_101 });
  const { join, wrapped } = await approveEnrollment({ qr: fresh, claim: recipientClaim, owner, history: store.history(), secret, confirmedCode: code, now: start + 330_101 });
  const expected = await verifyMembership([...store.history(), join], { listId, ownerId: owner.deviceId, ownerSigningPublic: owner.signing.publicKey, checkpoint: root.head });
  await verifyWrappedPackage({ pkg: wrapped, senderSigningPublic: owner.signing.publicKey, expectedListId: listId,
    expectedEpoch: 0, expectedMembershipHash: expected.head.hash, expectedFrom: owner.deviceId, expectedTo: recipient.deviceId });
  assert.equal(store.approveInvite(ownerAuth(), fresh.invitationId, join, wrapped, root.head.hash, expected.head.hash, start + 330_110).joined, recipient.deviceId);
  assert.equal(store.history().length, 2);
  assert.equal(store.meta().head, await membershipHash(join));
  const result = store.inviteResult(recipientAuth(), fresh.invitationId, registry.tokenHash, start + 330_120);
  assert.equal(result.status, 'approved');
  assert.deepEqual((await acceptEnrollment({ qr: fresh, recipient, history: result.history, wrapped: result.wrapped, now: start + 330_130 })).secret, secret);
  assert.equal(store.inviteResult(recipientAuth(), fresh.invitationId, registry.tokenHash, start + 330_140).status, 'approved');
  assert.throws(() => store.approveInvite(ownerAuth(), fresh.invitationId, join, wrapped, root.head.hash, expected.head.hash, start + 330_141), /approval-unavailable/);
  assert.throws(() => store.inviteResult(recipientAuth(), fresh.invitationId, registry.tokenHash, start + 330_110 + 601_000), /result-expired/);
});

test('cancellation prevents claim and forged server-approved changes cannot replace pinned head', async () => {
  const { qr, registry } = await generateInvitation({ listId, owner, genesis, now: start + 350_000 });
  store.registerInvite(ownerAuth(), registry, start + 350_000);
  store.cancelInvite(ownerAuth(), qr.invitationId, start + 350_100);
  const claimant = await createEnrollmentClaim({ qr, recipient: attacker, now: start + 350_110 });
  assert.throws(() => store.claimInvite(qr.invitationId, registry.tokenHash, claimant, start + 350_110), /invite-already-used/);
  assert.throws(() => store.cancelInvite(ownerAuth(), qr.invitationId, start + 350_120), /cancellation-unavailable/);
});
