import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { generateDeviceKeys, newListSecret, digest } from '../web/collab/crypto.js';
import { createGenesis, verifyMembership } from '../web/collab/membership.js';
import { generateInvitation, createEnrollmentClaim, verifyEnrollmentClaim, comparisonCode, approveEnrollment, acceptEnrollment } from '../web/collab/invite.js';
const owner = await generateDeviceKeys();
const recipient = await generateDeviceKeys();
const intruder = await generateDeviceKeys();
const listId = randomUUID(); const secret = newListSecret();
const genesis = await createGenesis(listId, owner);
const now = 100_000;
const { qr, registry } = await generateInvitation({ listId, owner, genesis, now });
const claim = await createEnrollmentClaim({ qr, recipient, now: now + 100 });

test('QR has short lived claim token and pinned owner fingerprint but never list key', () => {
  assert.equal(qr.expiresAt, now + 300_000);
  assert.equal(registry.invitationId, qr.invitationId);
  assert.ok(!JSON.stringify(qr).includes(Buffer.from(secret).toString('base64url')));
  assert.ok(!JSON.stringify(registry).includes(qr.token));
});
test('recipient proves own signing key, with tampered claims rejected', async () => {
  assert.equal(await verifyEnrollmentClaim(qr, claim, now + 100), true);
  const forged = { ...claim, deviceId: intruder.deviceId };
  await assert.rejects(verifyEnrollmentClaim(qr, forged, now + 100));
  await assert.rejects(createEnrollmentClaim({ qr, recipient, now: qr.expiresAt }));
});
test('both devices derive same eight-digit code; owner requires explicit matching confirmation', async () => {
  const code = await comparisonCode({ qr, claim, now: now + 100 });
  assert.match(code, /^[0-9]{8}$/);
  await assert.rejects(approveEnrollment({ qr, claim, owner, history: [genesis], secret, confirmedCode: '11111111', now: now + 100 }));
  const approved = await approveEnrollment({ qr, claim, owner, history: [genesis], secret, confirmedCode: code, now: now + 100 });
  const state = await verifyMembership([genesis, approved.join], { listId, ownerId: owner.deviceId, ownerSigningPublic: owner.signing.publicKey });
  assert.ok(state.members.has(recipient.deviceId));
  assert.deepEqual((await acceptEnrollment({ qr, recipient, history: [genesis, approved.join], wrapped: approved.wrapped, now: now + 200 })).secret, secret);
  await assert.rejects(acceptEnrollment({ qr, recipient: intruder, history: [genesis, approved.join], wrapped: approved.wrapped, now: now + 200 }));
});
test('server-supplied fake genesis and substituted wrapped key cannot silently enroll device', async () => {
  const code = await comparisonCode({ qr, claim, now: now + 100 });
  const approved = await approveEnrollment({ qr, claim, owner, history: [genesis], secret, confirmedCode: code, now: now + 100 });
  const rogue = await generateDeviceKeys();
  const rogueGenesis = await createGenesis(listId, rogue);
  await assert.rejects(acceptEnrollment({ qr, recipient, history: [rogueGenesis, approved.join], wrapped: approved.wrapped, now: now + 200 }));
  const changed = { ...approved.wrapped, membershipHash: await digest('fake') };
  await assert.rejects(acceptEnrollment({ qr, recipient, history: [genesis, approved.join], wrapped: changed, now: now + 200 }));
});
