// Client-side encrypted synchronization engine. NOT activated in the PWA.
// `storage` must implement atomic revision-checked read()/commit(rev, state).
// State: { rev, document, cursor, checkpoint, pending: [{ op, envelope? }] }.
// Decrypted local operations remain available for explicit rebase after epoch rotation.
import { signRequest } from './auth.js';
import { encryptOperation, decryptOperation } from './crypto.js';
import { verifyMembership, verifyAuthorizedEnvelope } from './membership.js';
import { apply } from '../model.js';
const MAX_PAGE = 100;
const MAX_RETRY = 8;
export class SyncError extends Error {
  constructor(reason, status = 0) { super(reason); this.name = 'SyncError'; this.status = status; }
}
export function createFetchTransport({ baseUrl = '', device, listId, fetcher = fetch }) {
  const listPath = `/api/lists/${listId}`;
  const origin = new URL(baseUrl || (typeof location !== 'undefined' ? location.origin : 'https://localhost'));
  if (origin.protocol !== 'https:' && origin.hostname !== 'localhost' && origin.hostname !== '127.0.0.1') throw Error('Sync transport requires HTTPS');
  const send = async (method, suffix, payload) => {
    const path = `${listPath}/${suffix}`;
    const body = payload === undefined ? '' : JSON.stringify(payload);
    const auth = await signRequest({ device, listId, method, path, body });
    const response = await fetcher(baseUrl + path, {
      method, cache: 'no-store', credentials: 'same-origin',
      headers: { 'X-SL-Auth': JSON.stringify(auth), ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(method === 'POST' ? { body } : {}),
    });
    if (!response.ok) {
      let detail = {};
      try { detail = await response.json(); } catch { /* keep status */ }
      throw new SyncError(detail.error || `http-${response.status}`, response.status);
    }
    return response.json();
  };
  return {
    membership: () => send('GET', 'membership'),
    page: after => send('GET', `changes?after=${after}`),
    append: envelope => send('POST', 'changes', envelope),
    ticket: () => send('POST', 'ticket'),
    connect: ticket => {
      const base = new URL(baseUrl || location.origin, typeof location === 'undefined' ? 'https://localhost' : location.href);
      if (base.protocol !== 'https:' && base.hostname !== 'localhost' && base.hostname !== '127.0.0.1') throw Error('Insecure sync WebSocket origin');
      const url = new URL(`${listPath}/live`, base);
      url.protocol = base.protocol === 'https:' ? 'wss:' : 'ws:';
      url.searchParams.set('ticket', ticket);
      return new WebSocket(url);
    },
  };
}
export function createSyncClient({ listId, device, secret, ownerId, ownerSigningPublic, storage, transport }) {
  let flight = null;
  function oneAtATime(task) {
    if (flight) return flight;
    const running = task();
    flight = running;
    running.finally(() => { if (flight === running) flight = null; }).catch(() => {});
    return running;
  }
  async function history(checkpoint) {
    const response = await transport.membership();
    const events = response?.events;
    return verifyMembership(events, { listId, ownerId, ownerSigningPublic, checkpoint });
  }
  async function pull() {
    let count = 0;
    for (let pageNo = 0; pageNo < 10_000; pageNo++) {
      let successful = false;
      let complete = false;
      for (let tries = 0; tries < MAX_RETRY; tries++) {
        const before = await storage.read();
        const trust = await history(before.checkpoint);
        const page = await transport.page(before.cursor);
        const afterTrust = await history(before.checkpoint);
        if (trust.head.hash !== afterTrust.head.hash || trust.head.seq !== afterTrust.head.seq) throw new SyncError('membership-changed-during-pull');
        if (!Array.isArray(page?.changes) || page.changes.length > MAX_PAGE || !Number.isSafeInteger(page.latest) || page.latest < before.cursor) throw new SyncError('invalid-or-rolled-back-log');
        let seq = before.cursor;
        let doc = before.document;
        const acknowledgements = new Set();
        for (const entry of page.changes) {
          if (!Number.isSafeInteger(entry?.seq) || entry.seq !== seq + 1) throw new SyncError('missing-or-reordered-operation');
          const env = entry.envelope;
          if (env?.listId !== listId) throw new SyncError('wrong-list-operation');
          await verifyAuthorizedEnvelope(env, trust);
          const op = await decryptOperation({ envelope: env, listSecret: secret, memberPublicKey: trust.members.get(env.author).signing });
          doc = apply(doc, op);
          for (const pending of before.pending) {
            if (pending.op.id === op.id) {
              // Ack only EXACT ciphertext already persisted locally; never trust an
              // unauthenticated "200 accepted" response as durability proof.
              if (!pending.envelope || JSON.stringify(pending.envelope) !== JSON.stringify(env)) throw new SyncError('conflicting-self-operation');
              acknowledgements.add(op.id);
            }
          }
          seq++;
        }
        if (seq > page.latest || (!page.changes.length && page.latest !== before.cursor)) throw new SyncError('server-suppressed-operations');
        const next = { ...before, document: doc, cursor: seq, checkpoint: trust.head, pending: before.pending.filter(p => !acknowledgements.has(p.op.id)) };
        if (!await storage.commit(before.rev, next)) continue;
        count += page.changes.length;
        successful = true;
        complete = seq >= page.latest;
        break;
      }
      if (!successful) throw new SyncError('concurrent-local-edits');
      if (complete) return count;
    }
    throw new SyncError('too-many-pages');
  }
  async function push() {
    let pushed = 0;
    const processedIds = new Set();
    for (let index = 0; index < 10_000; index++) {
      let entry;
      for (let tries = 0; tries < MAX_RETRY; tries++) {
        const before = await storage.read();
        const nextPending = before.pending.find(p => !processedIds.has(p.op.id));
        if (!nextPending) return pushed;
        const trust = await history(before.checkpoint);
        if (!trust.members.has(device.deviceId)) throw new SyncError('device-no-longer-member');
        const p = nextPending;
        if (p.envelope) {
          if (p.envelope.epoch !== trust.epoch || p.envelope.membershipHash !== trust.head.hash) throw new SyncError('stale-pending-operation');
          entry = p; break;
        }
        const env = await encryptOperation({ listSecret: secret, listId, epoch: trust.epoch, membershipHash: trust.head.hash, operation: p.op, device });
        const next = { ...before, checkpoint: trust.head, pending: before.pending.map(x => x.op.id === p.op.id ? { ...x, envelope: env } : x) };
        if (!await storage.commit(before.rev, next)) continue;
        entry = { ...p, envelope: env }; break;
      }
      if (!entry) throw new SyncError('concurrent-local-edits');
      // One operation per request. Retries use an entirely fresh HTTP auth nonce
      // but exactly the same persisted operation envelope.
      try { await transport.append(entry.envelope); }
      catch (e) {
        if (e.status === 409) throw new SyncError('stale-or-conflicting-server-state', e.status);
        throw e;
      }
      pushed++;
      // Do not resend this row within the same pass. It remains pending until a
      // verified catch-up page confirms the exact encrypted envelope.
      processedIds.add(entry.op.id);
    }
    throw new SyncError('too-many-pending-operations');
  }
  async function synchronize() {
    return oneAtATime(async () => {
      const receivedBefore = await pull();
      const sent = await push();
      const receivedAfter = await pull();
      return { received: receivedBefore + receivedAfter, sent };
    });
  }
  // A WebSocket is a performance hint only. Recovery must always call sync() on
  // reopen/reconnect, and callers handle close/offline with backoff themselves.
  async function openLive(onUpdate = () => {}) {
    const { ticket } = await transport.ticket();
    const ws = transport.connect(ticket);
    ws.addEventListener('message', async event => {
      try {
        const data = JSON.parse(event.data);
        if (Number.isSafeInteger(data.seq)) await synchronize();
        onUpdate(null);
      } catch (err) { onUpdate(err); }
    });
    return ws;
  }
  return { pull, push, synchronize, openLive };
}
