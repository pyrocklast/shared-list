// Request authentication for the future sync API. Transport is HTTPS only.
// The request body must be signed as *bytes* (not parsed/re-serialized JSON).
import { randomToken, digest, sign, verify, fromB64u } from './crypto.js';
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const METHODS = new Set(['GET', 'POST']);
export const AUTH_SKEW_MS = 120_000;
function validPath(listId, path) {
  if (typeof path !== 'string' || !path.startsWith(`/api/lists/${listId}/`) || /[#\s]/.test(path) || path.length > 256) throw Error('Wrong signed request path');
}
function fields(auth, method, path, bodyHash) { return [auth.listId, auth.deviceId, method, path, auth.time, auth.nonce, bodyHash]; }
function checkBase(auth, method, path, now, requireSignature = true) {
  if (!auth || !ID.test(auth.listId || '') || !ID.test(auth.deviceId || '') || !METHODS.has(method)) throw Error('Invalid authenticated request');
  validPath(auth.listId, path);
  if (!Number.isSafeInteger(auth.time) || Math.abs(now - auth.time) > AUTH_SKEW_MS || auth.time < 0) throw Error('Expired signed request');
  fromB64u(auth.nonce, 16, 16);
  if (requireSignature) fromB64u(auth.signature, 64, 64);
}
export async function signRequest({ device, listId, method, path, body = '', time = Date.now() }) {
  if (typeof body !== 'string') throw Error('Request body must be raw UTF-8 string');
  const auth = { v: 1, listId, deviceId: device.deviceId, time, nonce: randomToken(16) };
  // Validate all untrusted caller inputs even when producing signatures.
  checkBase(auth, method, path, time, false);
  const bodyHash = await digest(body);
  auth.signature = await sign(device.signing.privateKey, 'request', fields(auth, method, path, bodyHash));
  return auth;
}
export async function verifyRequest({ auth, memberPublicKey, method, path, body = '', now = Date.now() }) {
  if (auth?.v !== 1 || typeof body !== 'string') throw Error('Invalid request signature format');
  checkBase(auth, method, path, now);
  if (!await verify(memberPublicKey, auth.signature, 'request', fields(auth, method, path, await digest(body)))) throw Error('Invalid request signature');
  return true;
}
// Server must reserve (listId, deviceId, nonce) atomically with the requested
// operation, and enforce bounded replay storage + request budgets. A verified
// signature by itself does NOT prevent replay.
