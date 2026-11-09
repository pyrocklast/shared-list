// One Cloudflare Worker + SQLite-backed Durable Object for opaque encrypted sync.
// SINGLE-OWNER sandbox only: no QR enrollment, member join or production rollout.
// The application still remains local-only until a trusted browser sync client exists.
import { DurableObject } from 'cloudflare:workers';
import { verifyMembership } from '../web/collab/membership.js';
import { verifyAuthorizedEnvelope } from '../web/collab/membership.js';
import { verifyRequest } from '../web/collab/auth.js';
import { digest, randomToken, fromB64u, normalizeEnvelope } from '../web/collab/crypto.js';
import { SyncStore, MAX_LISTENERS } from './store.js';
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEADERS = { 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'", 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
const json = (status, obj) => new Response(JSON.stringify(obj), { status, headers: { ...HEADERS, 'Content-Type': 'application/json; charset=utf-8' } });
const error = (status, reason) => json(status, { error: reason });
function errorStatus(e) {
  if (e.message === 'not-found') return 404;
  if (e.message === 'rate-limit') return 429;
  if (e.message === 'stale-epoch-or-membership' || e.message === 'op-id-collision') return 409;
  if (e.message === 'list-storage-limit') return 507;
  if (e.message === 'replay' || e.message === 'Stale membership checkpoint or key epoch') return 409;
  return 400;
}
async function bodyText(request, maxBytes) {
  if (Number(request.headers.get('Content-Length')) > maxBytes) throw Error('body-too-large');
  const reader = request.body?.getReader();
  if (!reader) return '';
  const parts = []; let bytes = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > maxBytes) { await reader.cancel(); throw Error('body-too-large'); }
    parts.push(value);
  }
  const out = new Uint8Array(bytes); let at = 0;
  for (const part of parts) { out.set(part, at); at += part.byteLength; }
  return new TextDecoder('utf-8', { fatal: true }).decode(out);
}
async function setupAllowed(request, secret) {
  if (!secret || secret.length < 24) return false;
  const provided = request.headers.get('X-Setup-Code') || '';
  if (provided.length > 512) return false;
  const [a, b] = await Promise.all([crypto.subtle.digest('SHA-256', new TextEncoder().encode(provided)), crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret))]);
  // Tiny fixed comparison; setup secret must be long and random and never embedded in web assets.
  const x = new Uint8Array(a), y = new Uint8Array(b); let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/lists' && request.method === 'POST') {
      if (!await setupAllowed(request, env.SETUP_CODE)) return error(403, 'creation-unavailable');
      try {
        const payload = JSON.parse(await bodyText(request, 8 * 1024));
        const listId = payload.genesis?.listId;
        if (!ID.test(listId || '')) return error(400, 'invalid-list');
        // A self-signed owner genesis is not a server trust root: an independent
        // recipient must still pin it from a physical, approved invitation.
        await verifyMembership([payload.genesis], { listId, ownerId: payload.genesis.ownerId, ownerSigningPublic: payload.genesis.signing });
        return env.LISTS.get(env.LISTS.idFromName(listId)).fetch(new Request(`https://list-internal.invalid/${listId}/bootstrap`, { method: 'POST', body: JSON.stringify(payload.genesis) }));
      } catch { return error(400, 'invalid-bootstrap'); }
    }
    const match = url.pathname.match(/^\/api\/lists\/([^/]+)\/(changes|membership|ticket|live)$/);
    if (match) {
      if (!ID.test(match[1])) return error(404, 'not-found');
      return env.LISTS.get(env.LISTS.idFromName(match[1])).fetch(request);
    }
    if (url.pathname.startsWith('/api/')) return error(404, 'not-found');
    return env.ASSETS.fetch(request);
  },
};
export class List extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.store = new SyncStore(ctx.storage);
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }
  async authenticate(request, body) {
    const meta = this.store.meta();
    if (!meta) throw Error('not-found');
    const url = new URL(request.url);
    const authHeader = request.headers.get('X-SL-Auth') || '';
    if (authHeader.length > 1024) throw Error('bad-auth');
    const auth = JSON.parse(authHeader);
    if (auth.listId !== meta.list_id || auth.deviceId !== meta.owner_id) throw Error('unauthorized');
    await verifyRequest({ auth, memberPublicKey: JSON.parse(meta.owner_public), method: request.method, path: url.pathname + url.search, body });
    return auth;
  }
  async fetch(request) {
    const url = new URL(request.url);
    const bootstrap = url.pathname.match(/^\/([0-9a-f-]+)\/bootstrap$/);
    if (bootstrap && request.method === 'POST') {
      try {
        const genesis = JSON.parse(await bodyText(request, 8 * 1024));
        if (genesis.listId !== bootstrap[1]) return error(400, 'invalid-list');
        const state = await verifyMembership([genesis], { listId: genesis.listId, ownerId: genesis.ownerId, ownerSigningPublic: genesis.signing });
        const created = this.store.bootstrap({ listId: genesis.listId, genesis, ownerId: genesis.ownerId, ownerPublic: genesis.signing, head: state.head.hash });
        return created ? json(201, { head: state.head, epoch: 0 }) : error(409, 'list-exists');
      } catch { return error(400, 'invalid-bootstrap'); }
    }
    const id = url.pathname.match(/^\/api\/lists\/([^/]+)\/([^/]+)$/);
    if (!id || id[1] !== this.store.meta()?.list_id) return error(404, 'not-found');
    const endpoint = id[2];
    if (endpoint === 'live' && request.method === 'GET') {
      if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return error(426, 'expected-websocket');
      const ticket = url.searchParams.get('ticket');
      try {
        if (!ticket) throw Error('missing-ticket');
        fromB64u(ticket, 32, 32);
        const who = this.store.consumeTicket(await digest(ticket), Date.now());
        if (!who) throw Error('invalid-ticket');
        if (this.ctx.getWebSockets().length >= MAX_LISTENERS) return error(429, 'too-many-listeners');
        const pair = new WebSocketPair();
        const [client, server] = Object.values(pair);
        this.ctx.acceptWebSocket(server);
        server.serializeAttachment({ deviceId: who });
        server.send(JSON.stringify({ seq: this.store.latest() }));
        return new Response(null, { status: 101, webSocket: client });
      } catch { return error(401, 'invalid-ticket'); }
    }
    let text = '';
    try {
      if (request.method === 'POST') text = await bodyText(request, 32 * 1024);
      const auth = await this.authenticate(request, text);
      const now = Date.now();
      if (endpoint === 'membership' && request.method === 'GET') return json(200, { events: this.store.readMembership(auth, now) });
      if (endpoint === 'changes' && request.method === 'GET') {
        const after = url.searchParams.get('after') || '0';
        if (!/^(0|[1-9][0-9]{0,12})$/.test(after)) return error(400, 'invalid-cursor');
        return json(200, this.store.read(auth, Number(after), now));
      }
      if (endpoint === 'changes' && request.method === 'POST') {
        const env = JSON.parse(text);
        if (env.listId !== auth.listId || env.author !== auth.deviceId || !env.signature) throw Error('unauthorized-envelope');
        const meta = this.store.meta();
        const genesis = JSON.parse(meta.genesis);
        const state = await verifyMembership([genesis], { listId: genesis.listId, ownerId: genesis.ownerId, ownerSigningPublic: genesis.signing });
        await verifyAuthorizedEnvelope(env, state);
        const result = this.store.append(auth, normalizeEnvelope(env), now);
        if (result.inserted) this.broadcast(result.seq);
        return json(200, { seq: result.seq, duplicate: !result.inserted });
      }
      if (endpoint === 'ticket' && request.method === 'POST') {
        if (text !== '') throw Error('unexpected-ticket-body');
        const ticket = randomToken(32);
        this.store.issueTicket(auth, await digest(ticket), now);
        return json(200, { ticket, expiresIn: 60 });
      }
      return error(405, 'method-not-allowed');
    } catch (e) { return error(errorStatus(e), (e.message === 'stale-epoch-or-membership' || e.message === 'Stale membership checkpoint or key epoch') ? 'stale-membership' : 'invalid-request'); }
  }
  broadcast(seq) {
    for (const ws of this.ctx.getWebSockets()) {
      try { ws.send(JSON.stringify({ seq })); } catch { try { ws.close(1011, 'unavailable'); } catch {} }
    }
  }
  webSocketMessage(ws, message) {
    // Clients never send content over WS; only a server-to-client "new seq" hint.
    if (message !== 'ping') try { ws.close(1008, 'not-supported'); } catch {}
  }
  webSocketClose(ws, code, reason) { try { ws.close(code, reason); } catch {} }
}
