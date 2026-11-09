import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { generateDeviceKeys } from '../web/collab/crypto.js';
import { AUTH_SKEW_MS, signRequest, verifyRequest } from '../web/collab/auth.js';
const device = await generateDeviceKeys();
const impostor = await generateDeviceKeys();
const listId = randomUUID();
const path = `/api/lists/${listId}/changes?after=0`;
const body = JSON.stringify({ count: 5 });

test('signed request binds list, device, method, URL, byte-exact body and time', async () => {
  const auth = await signRequest({ device, listId, method: 'POST', path, body, time: 50_000_000 });
  const ok = { auth, memberPublicKey: device.signing.publicKey, method: 'POST', path, body, now: 50_000_050 };
  assert.equal(await verifyRequest(ok), true);
  await assert.rejects(verifyRequest({ ...ok, body: body + ' ' }));
  await assert.rejects(verifyRequest({ ...ok, method: 'GET' }));
  await assert.rejects(verifyRequest({ ...ok, path: path.replace('after=0', 'after=1') }));
  await assert.rejects(verifyRequest({ ...ok, memberPublicKey: impostor.signing.publicKey }));
  await assert.rejects(verifyRequest({ ...ok, now: 50_000_000 + AUTH_SKEW_MS + 1 }));
});
test('new signatures have unique nonces and cannot sign another list URL', async () => {
  const x = await signRequest({ device, listId, method: 'GET', path });
  const y = await signRequest({ device, listId, method: 'GET', path });
  assert.notEqual(x.nonce, y.nonce);
  await assert.rejects(signRequest({ device, listId, method: 'GET', path: '/api/lists/not-this/changes' }));
});
