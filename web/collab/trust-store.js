// IndexedDB persistence for the collaboration trust boundary.
// Isolated from phase-1 local documents, NOT yet used by the PWA UI.
// CryptoKey private keys are non-extractable but same-origin JS can still use them.
import { generateDeviceKeys } from './crypto.js';
import { membershipHash, verifyMembership } from './membership.js';
const NAME = 'shared-list-trust-v1';
const open = () => new Promise((resolve, reject) => {
  const req = indexedDB.open(NAME, 1);
  req.onupgradeneeded = () => {
    const db = req.result;
    db.createObjectStore('identity');
    db.createObjectStore('roots');
  };
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
  req.onblocked = () => reject(Error('Close other tabs to upgrade the identity store'));
});
const get = request => new Promise((resolve, reject) => { request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
const finish = tx => new Promise((resolve, reject) => { tx.oncomplete = resolve; tx.onabort = () => reject(tx.error || Error('Trust storage transaction aborted')); tx.onerror = () => reject(tx.error || Error('Trust storage failure')); });
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
export async function getOrCreateDeviceIdentity(localDeviceId) {
  // Existing phase-1 operation device IDs must be preserved when enrolling in sync.
  if (typeof localDeviceId !== 'string') throw Error('Missing local device ID');
  const db = await open();
  const first = db.transaction('identity', 'readonly');
  const existing = await get(first.objectStore('identity').get('main'));
  if (existing) {
    if (existing.deviceId !== localDeviceId || existing.signing.privateKey.extractable || existing.agreement.privateKey.extractable) throw Error('Device identity changed or is extractable');
    return existing;
  }
  const generated = await generateDeviceKeys(localDeviceId);
  const tx = db.transaction('identity', 'readwrite');
  const done = finish(tx);
  const store = tx.objectStore('identity');
  const concurrent = await get(store.get('main'));
  if (!concurrent) store.put(generated, 'main');
  await done;
  const resolved = concurrent || generated;
  if (resolved.deviceId !== localDeviceId) throw Error('Another tab registered a different device');
  return resolved;
}
export async function getPinnedRoot(listId) {
  const db = await open();
  const tx = db.transaction('roots', 'readonly');
  return get(tx.objectStore('roots').get(listId));
}
export async function pinRoot({ listId, ownerId, ownerSigningPublic, genesis }) {
  // Only call with an owner key independently established from local creation or
  // a verified in-person invitation, NEVER from an untrusted server reply.
  const state = await verifyMembership([genesis], { listId, ownerId, ownerSigningPublic });
  const record = { listId, ownerId, ownerSigningPublic, checkpoint: state.head };
  const db = await open();
  const tx = db.transaction('roots', 'readwrite');
  const done = finish(tx); const store = tx.objectStore('roots');
  const existing = await get(store.get(listId));
  if (existing) {
    if (existing.ownerId !== ownerId || !same(existing.ownerSigningPublic, ownerSigningPublic) || existing.checkpoint.seq < 0) { tx.abort(); try { await done; } catch {} throw Error('Existing pinned root cannot be replaced'); }
  } else store.put(record, listId);
  await done;
  return existing || record;
}
export async function advancePinnedRoot(listId, events) {
  // The expensive crypto validation is done *before* the IndexedDB transaction;
  // the final transaction also checks the current checkpoint atomically, to
  // prevent two tabs from overwriting one another's observed trust history.
  const baseline = await getPinnedRoot(listId);
  if (!baseline) throw Error('No independently pinned root');
  const state = await verifyMembership(events, { ...baseline, checkpoint: baseline.checkpoint });
  const prefixes = await Promise.all(events.map(membershipHash));
  const db = await open();
  const tx = db.transaction('roots', 'readwrite'); const done = finish(tx);
  const store = tx.objectStore('roots');
  const current = await get(store.get(listId));
  const expected = current?.checkpoint;
  if (!current || current.ownerId !== baseline.ownerId || !same(current.ownerSigningPublic, baseline.ownerSigningPublic) || !expected || expected.seq >= prefixes.length || prefixes[expected.seq] !== expected.hash) {
    tx.abort(); try { await done; } catch {} throw Error('Competing membership fork or trust replacement');
  }
  if (state.head.seq > expected.seq) store.put({ ...current, checkpoint: state.head }, listId);
  await done;
  return state;
}
