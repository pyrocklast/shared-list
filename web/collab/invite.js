// Cryptographic QR claim/approval messages. NO server invite registry or UI yet.
// QR is only a transient enrollment capability; it never includes the list key.
import { b64u, fromB64u, randomId, randomToken, digest, sign, verify, wrapListSecret, unwrapListSecret } from './crypto.js';
import { createOwnerEvent, verifyMembership, membershipHash } from './membership.js';
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FIVE_MINUTES = 5 * 60_000;
const ownerKey = pub => ({ kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y });
function requiredId(x) { if (!ID.test(x || '')) throw Error('Invalid invitation identifier'); }
function claimFields(claim) {
  return [claim.listId, claim.invitationId, claim.tokenHash, claim.deviceId, ownerKey(claim.signing), ownerKey(claim.agreement)];
}
export async function generateInvitation({ listId, owner, genesis, now = Date.now() }) {
  requiredId(listId);
  const root = await verifyMembership([genesis], { listId, ownerId: owner.deviceId, ownerSigningPublic: owner.signing.publicKey });
  const token = randomToken(32);
  const invitationId = randomId();
  const tokenHash = await digest(fromB64u(token, 32, 32));
  const expiresAt = now + FIVE_MINUTES;
  const qr = { v: 1, listId, invitationId, token, expiresAt,
    ownerId: owner.deviceId, ownerSigningPublic: ownerKey(owner.signing.publicKey), genesisHash: root.head.hash };
  // Only tokenHash and expiry go into the server's pending invite registry.
  const registry = { listId, invitationId, tokenHash, expiresAt };
  return { qr, registry };
}
export async function createEnrollmentClaim({ qr, recipient, now = Date.now() }) {
  validateQr(qr, now);
  const claim = { v: 1, listId: qr.listId, invitationId: qr.invitationId,
    tokenHash: await digest(fromB64u(qr.token, 32, 32)), deviceId: recipient.deviceId,
    signing: ownerKey(recipient.signing.publicKey), agreement: ownerKey(recipient.agreement.publicKey) };
  claim.signature = await sign(recipient.signing.privateKey, 'qr-claim', claimFields(claim));
  return claim;
}
export function validateQr(qr, now = Date.now()) {
  if (qr?.v !== 1 || !Number.isSafeInteger(qr.expiresAt) || qr.expiresAt <= now || qr.expiresAt > now + FIVE_MINUTES || qr.genesisHash == null) throw Error('Invitation expired or invalid');
  requiredId(qr.listId); requiredId(qr.invitationId); requiredId(qr.ownerId);
  fromB64u(qr.token, 32, 32); fromB64u(qr.genesisHash, 32, 32);
  if (qr.ownerSigningPublic?.kty !== 'EC' || qr.ownerSigningPublic.crv !== 'P-256') throw Error('Invalid invitation owner public key');
}
export async function verifyEnrollmentClaim(qr, claim, now = Date.now()) {
  validateQr(qr, now);
  if (!claim || claim.v !== 1 || claim.listId !== qr.listId || claim.invitationId !== qr.invitationId || claim.deviceId === qr.ownerId) throw Error('Wrong QR claim');
  requiredId(claim.deviceId);
  const actual = await digest(fromB64u(qr.token, 32, 32));
  if (actual !== claim.tokenHash || !await verify(claim.signing, claim.signature, 'qr-claim', claimFields(claim))) throw Error('Invalid recipient proof of key possession');
  return true;
}
export async function comparisonCode({ qr, claim, now = Date.now() }) {
  await verifyEnrollmentClaim(qr, claim, now);
  // HMAC keyed by the 256-bit QR secret. The short code is a human comparison
  // aid, NOT a cryptographic proximity or authentication guarantee.
  const hmac = await crypto.subtle.importKey('raw', fromB64u(qr.token, 32, 32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const data = new TextEncoder().encode(JSON.stringify(['shared-list:qr-code:v1', ...claimFields(claim)]));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hmac, data));
  const value = new DataView(mac.buffer).getUint32(0, false) % 100_000_000;
  return String(value).padStart(8, '0');
}
export async function approveEnrollment({ qr, claim, owner, history, secret, confirmedCode, now = Date.now() }) {
  const expectedCode = await comparisonCode({ qr, claim, now });
  if (confirmedCode !== expectedCode) throw Error('Physical comparison was not confirmed');
  const state = await verifyMembership(history, { listId: qr.listId, ownerId: qr.ownerId, ownerSigningPublic: qr.ownerSigningPublic });
  if (state.ownerId !== owner.deviceId || state.members.has(claim.deviceId)) throw Error('Recipient already enrolled or wrong approver');
  const member = { deviceId: claim.deviceId, signing: { publicKey: claim.signing }, agreement: { publicKey: claim.agreement } };
  const join = await createOwnerEvent({ history, owner, action: 'join', device: member });
  const hash = await membershipHash(join);
  const wrapped = await wrapListSecret({ secret, listId: qr.listId, epoch: state.epoch, sender: owner,
    recipientId: claim.deviceId, recipientAgreementPublic: claim.agreement, membershipHash: hash });
  return { join, wrapped, invited: claim.deviceId, compareCode: expectedCode };
}
export async function acceptEnrollment({ qr, recipient, history, wrapped, now = Date.now() }) {
  validateQr(qr, now);
  // The root must come from the physically scanned QR, not server history.
  const state = await verifyMembership(history, { listId: qr.listId, ownerId: qr.ownerId, ownerSigningPublic: qr.ownerSigningPublic });
  if (history[0] == null || await membershipHash(history[0]) !== qr.genesisHash || !state.members.has(recipient.deviceId)) throw Error('Untrusted QR enrollment chain');
  const member = state.members.get(recipient.deviceId);
  if (JSON.stringify(member.signing) !== JSON.stringify(ownerKey(recipient.signing.publicKey)) || JSON.stringify(member.agreement) !== JSON.stringify(ownerKey(recipient.agreement.publicKey))) throw Error('Recipient key changed after claim');
  const secret = await unwrapListSecret({ pkg: wrapped, recipient, senderSigningPublic: qr.ownerSigningPublic,
    expectedListId: qr.listId, expectedEpoch: state.epoch, expectedMembershipHash: state.head.hash });
  return { secret, checkpoint: state.head, ownerId: qr.ownerId, ownerSigningPublic: qr.ownerSigningPublic };
}
