// An owner-signed membership chain. Clients MUST pin the owner key independently
// (e.g. via an in-person QR) and durably persist their last observed checkpoint.
// Detects observed rollback and forks, NOT newer events intentionally withheld by a server.
import { sign, verify, digest, importVerifyKey, importAgreementKey, verifyEnvelope } from './crypto.js';

const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isId = x => typeof x === 'string' && ID.test(x);
const isEpoch = x => Number.isSafeInteger(x) && x >= 0 && x < 1e7;
function pub(key) {
  if (key?.kty !== 'EC' || key?.crv !== 'P-256' || typeof key.x !== 'string' || typeof key.y !== 'string') throw Error('Invalid member public key');
  return { kty: 'EC', crv: 'P-256', x: key.x, y: key.y };
}
function fields(ev) {
  if (ev.kind === 'genesis') return ['genesis', ev.listId, ev.seq, ev.epoch, ev.ownerId, pub(ev.signing), pub(ev.agreement)];
  if (ev.kind === 'join') return ['join', ev.listId, ev.seq, ev.epoch, ev.prev, ev.deviceId, pub(ev.signing), pub(ev.agreement)];
  if (ev.kind === 'remove') return ['remove', ev.listId, ev.seq, ev.epoch, ev.prev, ev.deviceId];
  throw Error('Invalid membership event kind');
}
export async function membershipHash(ev) {
  return digest(JSON.stringify(['shared-list:member-hash:v1', ...fields(ev), ev.signature]));
}
export async function createGenesis(listId, owner) {
  if (!isId(listId) || !isId(owner.deviceId)) throw Error('Invalid genesis identifier');
  const ev = { v: 1, kind: 'genesis', listId, seq: 0, epoch: 0, ownerId: owner.deviceId, signing: pub(owner.signing.publicKey), agreement: pub(owner.agreement.publicKey) };
  ev.signature = await sign(owner.signing.privateKey, 'membership', fields(ev));
  return ev;
}
export async function verifyMembership(history, { listId, ownerId, ownerSigningPublic, checkpoint = null }) {
  if (!Array.isArray(history) || history.length < 1 || history.length > 10000 || !isId(listId) || !isId(ownerId)) throw Error('Invalid membership history');
  const first = history[0];
  if (first?.v !== 1 || first.kind !== 'genesis' || first.listId !== listId || first.seq !== 0 || first.epoch !== 0 || first.ownerId !== ownerId || JSON.stringify(pub(first.signing)) !== JSON.stringify(pub(ownerSigningPublic))) throw Error('Untrusted membership genesis');
  await importVerifyKey(first.signing);
  await importAgreementKey(first.agreement);
  if (!await verify(ownerSigningPublic, first.signature, 'membership', fields(first))) throw Error('Invalid signed genesis');
  const members = new Map([[ownerId, { signing: pub(first.signing), agreement: pub(first.agreement) }]]);
  const everUsed = new Set([ownerId]);
  let epoch = 0;
  let prev = await membershipHash(first);
  let checkpointMatched = checkpoint?.seq === 0 && checkpoint?.hash === prev;
  for (let i = 1; i < history.length; i++) {
    const ev = history[i];
    if (ev?.v !== 1 || ev.listId !== listId || !isId(ev.deviceId) || ev.seq !== i || ev.prev !== prev) throw Error('Membership fork, missing event or wrong order');
    if (ev.kind === 'join') {
      if (ev.epoch !== epoch || everUsed.has(ev.deviceId)) throw Error('Invalid member join');
      await importVerifyKey(ev.signing); await importAgreementKey(ev.agreement);
      members.set(ev.deviceId, { signing: pub(ev.signing), agreement: pub(ev.agreement) });
      everUsed.add(ev.deviceId);
    } else if (ev.kind === 'remove') {
      if (ev.epoch !== epoch + 1 || ev.deviceId === ownerId || !members.has(ev.deviceId)) throw Error('Invalid member removal');
      members.delete(ev.deviceId);
      epoch++;
    } else throw Error('Invalid membership action');
    if (!await verify(ownerSigningPublic, ev.signature, 'membership', fields(ev))) throw Error('Invalid owner membership signature');
    prev = await membershipHash(ev);
    if (checkpoint && ev.seq === checkpoint.seq && prev === checkpoint.hash) checkpointMatched = true;
  }
  if (checkpoint && (!Number.isSafeInteger(checkpoint.seq) || checkpoint.seq < 0 || !checkpointMatched)) throw Error('Membership rollback or fork from pinned checkpoint');
  return { epoch, head: { seq: history.length - 1, hash: prev }, members, ownerId };
}
export async function createOwnerEvent({ history, owner, action, device }) {
  if (action !== 'join' && action !== 'remove') throw Error('Unsupported owner action');
  const first = history?.[0];
  const state = await verifyMembership(history, { listId: first?.listId, ownerId: owner.deviceId, ownerSigningPublic: owner.signing.publicKey });
  const targetId = action === 'join' ? device.deviceId : device;
  if (!isId(targetId) || (action === 'join' && state.members.has(targetId)) || (action === 'remove' && (!state.members.has(targetId) || targetId === owner.deviceId))) throw Error('Invalid membership target');
  const ev = { v: 1, kind: action, listId: first.listId, seq: state.head.seq + 1, epoch: state.epoch + (action === 'remove' ? 1 : 0), prev: state.head.hash, deviceId: targetId };
  if (action === 'join') {
    ev.signing = pub(device.signing.publicKey);
    ev.agreement = pub(device.agreement.publicKey);
  }
  ev.signature = await sign(owner.signing.privateKey, 'membership', fields(ev));
  return ev;
}

// Never pass a public key provided by an untrusted envelope directly to verifyEnvelope.
// Authorization is bound to the current verified head/epoch, not to a device ID alone.
export async function verifyAuthorizedEnvelope(envelope, state) {
  if (envelope?.epoch !== state.epoch || envelope.membershipHash !== state.head.hash) throw Error('Stale membership checkpoint or key epoch');
  const member = state.members.get(envelope.author);
  if (!member) throw Error('Removed or unknown author');
  await verifyEnvelope(envelope, member.signing);
  return true;
}

// Historical read-only authorization. Caller MUST pin and verify the complete
// owner-signed history first. Server acceptance-time ordering is not proven;
// revocation needs separately signed append evidence before production use.
export async function verifyHistoricalEnvelope(envelope, events, trustRoot) {
  await verifyMembership(events, trustRoot);
  if (envelope?.listId !== trustRoot.listId) throw Error('Wrong historical list');
  let index = -1;
  for (let i = 0; i < events.length; i++) {
    if (await membershipHash(events[i]) === envelope.membershipHash) { index = i; break; }
  }
  if (index < 0) throw Error('Unknown signed membership checkpoint');
  const state = await verifyMembership(events.slice(0, index + 1), { listId: trustRoot.listId, ownerId: trustRoot.ownerId, ownerSigningPublic: trustRoot.ownerSigningPublic });
  const member = state.members.get(envelope.author);
  if (!member || envelope.epoch !== state.epoch) throw Error('Unauthorized historical author or epoch');
  await verifyEnvelope(envelope, member.signing);
  return member;
}
