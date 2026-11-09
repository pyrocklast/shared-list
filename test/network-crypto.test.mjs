import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { generateDeviceKeys, newListSecret, encryptOperation, decryptOperation, verifyEnvelope, wrapListSecret, unwrapListSecret, digest, b64u, fromB64u } from '../web/collab/crypto.js';
import { operation, apply, emptyDocument } from '../web/model.js';

const listId = randomUUID();
const alice = await generateDeviceKeys();
const bob = await generateDeviceKeys();
const secret = newListSecret();
const membershipHash = await digest('membership-genesis');
const makeOp = () => operation(alice.deviceId, 1, [{ entity: 'list', id: listId, field: 'name', value: 'Milk & eggs' }]);

test('non-extractable device identities: public verification and agreement keys export, not private keys', async () => {
  assert.equal(alice.signing.privateKey.extractable, false);
  assert.equal(alice.agreement.privateKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('jwk', alice.signing.privateKey));
  assert.equal(alice.signing.publicKey.kty, 'EC');
});
test('encrypted and signed operation round trips and applies to the model', async () => {
  const op = makeOp();
  const env = await encryptOperation({ listSecret: secret, listId, epoch: 0, membershipHash, operation: op, device: alice });
  assert.equal(await verifyEnvelope(env, alice.signing.publicKey), true);
  const recovered = await decryptOperation({ envelope: env, listSecret: secret, memberPublicKey: alice.signing.publicKey });
  assert.deepEqual(recovered, op);
  assert.equal(apply(emptyDocument(listId), recovered).list.name.value, 'Milk & eggs');
  assert.ok(!JSON.stringify(env).includes('Milk'));
});
test('modified signature, encrypted bytes and origin/epoch are refused', async () => {
  const env = await encryptOperation({ listSecret: secret, listId, epoch: 0, membershipHash, operation: makeOp(), device: alice });
  for (const patch of [{ author: bob.deviceId }, { epoch: 1 }, { membershipHash: await digest('wrong history') }, { listId: randomUUID() }, { iv: b64u(crypto.getRandomValues(new Uint8Array(12))) }, { data: b64u(crypto.getRandomValues(new Uint8Array(40))) }]) {
    await assert.rejects(verifyEnvelope({ ...env, ...patch }, alice.signing.publicKey));
  }
  await assert.rejects(decryptOperation({ envelope: env, listSecret: newListSecret(), memberPublicKey: alice.signing.publicKey }));
  await assert.rejects(verifyEnvelope(env, bob.signing.publicKey));
});
test('AES-GCM uses distinct IVs for identical plaintext and wrong epoch key fails', async () => {
  const op = makeOp();
  const first = await encryptOperation({ listSecret: secret, listId, epoch: 0, membershipHash, operation: op, device: alice });
  const second = await encryptOperation({ listSecret: secret, listId, epoch: 0, membershipHash, operation: op, device: alice });
  assert.notEqual(first.iv, second.iv);
  const newEpoch = await encryptOperation({ listSecret: secret, listId, epoch: 1, membershipHash, operation: op, device: alice });
  assert.notEqual(newEpoch.data, first.data);
  await assert.rejects(decryptOperation({ envelope: newEpoch, listSecret: newListSecret(), memberPublicKey: alice.signing.publicKey }));
});
test('strict base64url canonical encoding', () => {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  assert.deepEqual(fromB64u(b64u(bytes), 32), bytes);
  for (const str of ['AA=', 'AB', '', '$$', 'A']) assert.throws(() => fromB64u(str, 1));
});
test('authenticated recipient-only ECDH key wrapping; signed by sender', async () => {
  const hash = await digest('signed membership checkpoint');
  const pkg = await wrapListSecret({ secret, listId, epoch: 2, sender: alice, recipientId: bob.deviceId, recipientAgreementPublic: bob.agreement.publicKey, membershipHash: hash });
  assert.ok(!JSON.stringify(pkg).includes(b64u(secret)));
  assert.deepEqual(await unwrapListSecret({ pkg, recipient: bob, senderSigningPublic: alice.signing.publicKey, expectedListId: listId, expectedEpoch: 2, expectedMembershipHash: hash }), secret);
  await assert.rejects(unwrapListSecret({ pkg, recipient: alice, senderSigningPublic: alice.signing.publicKey, expectedListId: listId, expectedEpoch: 2, expectedMembershipHash: hash }));
  await assert.rejects(unwrapListSecret({ pkg, recipient: bob, senderSigningPublic: bob.signing.publicKey, expectedListId: listId, expectedEpoch: 2, expectedMembershipHash: hash }));
  await assert.rejects(unwrapListSecret({ pkg, recipient: bob, senderSigningPublic: alice.signing.publicKey, expectedListId: listId, expectedEpoch: 1, expectedMembershipHash: hash }));
  await assert.rejects(unwrapListSecret({ pkg: { ...pkg, from: randomUUID() }, recipient: bob, senderSigningPublic: alice.signing.publicKey, expectedListId: listId, expectedEpoch: 2, expectedMembershipHash: hash }));
});

test('unknown unencrypted network envelope fields are rejected', async () => {
  const env = await encryptOperation({ listSecret: secret, listId, epoch: 0, membershipHash, operation: makeOp(), device: alice });
  await assert.rejects(verifyEnvelope({ ...env, cleartext: 'secret leak' }, alice.signing.publicKey));
});
