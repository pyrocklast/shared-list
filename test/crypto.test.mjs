import test from 'node:test';
import assert from 'node:assert/strict';
import { seal, unseal, docContext, opContext } from '../web/crypto.js';

async function key() { return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']); }
test('round-trip encrypted local document, with randomized IV', async () => {
  const k = await key(); const data = { name: 'Sensitive shopping items', qty: 2 };
  const a = await seal(k, data, docContext('list-a'));
  const b = await seal(k, data, docContext('list-a'));
  assert.deepEqual(await unseal(k, a, docContext('list-a')), data);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.data, b.data);
  assert.ok(!JSON.stringify(a).includes(data.name));
});
test('wrong list context, wrong operation ID and tampering fail authentication', async () => {
  const k = await key();
  const ciphertext = await seal(k, { changes: [{ value: 'Milk' }] }, opContext('a', 'op-1'));
  await assert.rejects(unseal(k, ciphertext, opContext('b', 'op-1')));
  await assert.rejects(unseal(k, ciphertext, opContext('a', 'op-2')));
  const altered = { ...ciphertext, data: ciphertext.data.slice(0, -2) + 'AA' };
  await assert.rejects(unseal(k, altered, opContext('a', 'op-1')));
});
