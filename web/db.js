// IndexedDB is the durable local source of truth. Both the document and the
// encrypted outbox entry are committed atomically, with revision-checked retries
// so concurrent tabs cannot silently overwrite each other's edits.
import { apply, emptyDocument, operation, id } from './model.js';
import { seal, unseal, docContext, opContext } from './crypto.js';
const DB_NAME = 'shared-list-local-v1';
let dbPromise;
function req(r) { return new Promise((resolve, reject) => { r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); }); }
function done(tx) { return new Promise((resolve, reject) => { tx.oncomplete = resolve; tx.onabort = () => reject(tx.error || Error('Transaction aborted')); tx.onerror = () => reject(tx.error || Error('Storage error')); }); }
function openDB() {
  return dbPromise ||= new Promise((resolve, reject) => {
    const r = indexedDB.open(DB_NAME, 1);
    r.onupgradeneeded = () => {
      const db = r.result;
      db.createObjectStore('documents', { keyPath: 'id' });
      db.createObjectStore('keys', { keyPath: 'id' });
      const box = db.createObjectStore('outbox', { keyPath: 'id' });
      box.createIndex('listId', 'listId');
      db.createObjectStore('meta');
    };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
    r.onblocked = () => reject(Error('Close other tabs to upgrade storage'));
  });
}
async function deviceId(db) {
  const tx = db.transaction('meta', 'readwrite');
  const finished = done(tx);
  const store = tx.objectStore('meta');
  let value = await req(store.get('deviceId'));
  if (!value) { value = id(); store.put(value, 'deviceId'); }
  await finished;
  return value;
}
async function records(db, listId) {
  const tx = db.transaction(['documents', 'keys'], 'readonly');
  const finished = done(tx);
  const stored = req(tx.objectStore('documents').get(listId));
  const key = req(tx.objectStore('keys').get(listId));
  const [record, keyRecord] = await Promise.all([stored, key]);
  await finished;
  if (!record || !keyRecord) throw Error('List not found on this device');
  return { record, key: keyRecord.key };
}
let serial = Promise.resolve();
function enqueue(task) {
  const p = serial.then(task);
  serial = p.catch(() => {});
  return p;
}
const channel = typeof BroadcastChannel === 'function' ? new BroadcastChannel('shared-list-changed') : null;
const listeners = new Set();
function signal() { channel?.postMessage('changed'); }
if (channel) channel.onmessage = () => listeners.forEach(fn => fn());
export function subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); }
export async function listDocuments() {
  const db = await openDB();
  const tx = db.transaction(['documents', 'keys'], 'readonly');
  const finished = done(tx);
  const [docs, keys] = await Promise.all([req(tx.objectStore('documents').getAll()), req(tx.objectStore('keys').getAll())]);
  await finished;
  const keyById = new Map(keys.map(k => [k.id, k.key]));
  const result = await Promise.all(docs.map(async record => {
    const key = keyById.get(record.id);
    if (!key) throw Error('Missing key for a local list');
    return { document: await unseal(key, record.blob, docContext(record.id)), updatedAt: record.updatedAt };
  }));
  return result.sort((a, b) => b.updatedAt - a.updatedAt);
}
export async function loadList(listId) {
  const db = await openDB();
  const { record, key } = await records(db, listId);
  return unseal(key, record.blob, docContext(listId));
}
export function createList(name, defaultSection) {
  return enqueue(async () => {
    const db = await openDB();
    const author = await deviceId(db);
    const listId = id(); const sectionId = id();
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const op = operation(author, 1, [
      { entity: 'list', id: listId, field: 'name', value: name },
      { entity: 'section', id: sectionId, field: 'name', value: defaultSection },
      { entity: 'section', id: sectionId, field: 'position', value: 1000 },
    ]);
    const doc = apply(emptyDocument(listId), op);
    const [blob, encryptedOp] = await Promise.all([seal(key, doc, docContext(listId)), seal(key, op, opContext(listId, op.id))]);
    const tx = db.transaction(['documents', 'keys', 'outbox'], 'readwrite');
    const finished = done(tx);
    tx.objectStore('keys').put({ id: listId, key });
    tx.objectStore('documents').put({ id: listId, rev: 1, updatedAt: Date.now(), blob });
    tx.objectStore('outbox').put({ id: op.id, listId, epoch: 0, blob: encryptedOp });
    await finished;
    signal();
    return listId;
  });
}
export function changeList(listId, changes) {
  return enqueue(async () => {
    const db = await openDB();
    const author = await deviceId(db);
    for (let attempt = 0; attempt < 8; attempt++) {
      const { record, key } = await records(db, listId);
      const before = await unseal(key, record.blob, docContext(listId));
      const op = operation(author, before.clock + 1, changes);
      const after = apply(before, op);
      const [blob, encryptedOp] = await Promise.all([seal(key, after, docContext(listId)), seal(key, op, opContext(listId, op.id))]);
      const tx = db.transaction(['documents', 'outbox'], 'readwrite');
      const finished = done(tx);
      const current = await req(tx.objectStore('documents').get(listId));
      if (!current || current.rev !== record.rev) {
        tx.abort();
        try { await finished; } catch { /* compare-and-swap miss */ }
        if (!current) throw Error('List deleted in another tab');
        continue;
      }
      tx.objectStore('documents').put({ id: listId, rev: record.rev + 1, updatedAt: Date.now(), blob });
      tx.objectStore('outbox').put({ id: op.id, listId, epoch: 0, blob: encryptedOp });
      await finished;
      signal();
      return after;
    }
    throw Error('This list is busy in another tab. Try again.');
  });
}
export function deleteList(listId) {
  return enqueue(async () => {
    const db = await openDB();
    const tx = db.transaction(['documents', 'keys', 'outbox'], 'readwrite');
    const finished = done(tx);
    tx.objectStore('documents').delete(listId);
    tx.objectStore('keys').delete(listId);
    const cursor = tx.objectStore('outbox').index('listId').openCursor(IDBKeyRange.only(listId));
    cursor.onsuccess = () => { const c = cursor.result; if (c) { c.delete(); c.continue(); } };
    await finished;
    signal();
  });
}
// The encrypted outbox is intentionally NOT uploaded: phase 2 will introduce
// signed, epoch-bound envelopes, server-authoritative sequence and acknowledgements.
