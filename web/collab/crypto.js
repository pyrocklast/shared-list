// Network cryptography, separate from the phase-1 local storage format.
// No dynamic evaluation, external crypto library, or secret in a URL is required.
const subtle = crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });
export const NETWORK_VERSION = 1;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const B64 = /^[A-Za-z0-9_-]+$/;
const MAX_CIPHERTEXT = 16 * 1024;
const utf8 = value => enc.encode(value);
export function b64u(value) {
  const buf = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (const b of buf) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
export function fromB64u(value, exactLength = null, maxLength = MAX_CIPHERTEXT) {
  if (typeof value !== 'string' || !B64.test(value) || value.length > Math.ceil(maxLength * 4 / 3) + 4) throw Error('Invalid base64url');
  let decoded;
  try { decoded = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0)); }
  catch { throw Error('Invalid base64url'); }
  if (decoded.length > maxLength || (exactLength !== null && decoded.length !== exactLength) || b64u(decoded) !== value) throw Error('Invalid base64url length or encoding');
  return decoded;
}
function requireId(id) { if (typeof id !== 'string' || !UUID.test(id)) throw Error('Invalid identifier'); }
function requireEpoch(epoch) { if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch > 1e7) throw Error('Invalid epoch'); }
function requireHash(hash) { fromB64u(hash, 32, 32); }
function publicJwk(jwk) {
  if (jwk?.kty !== 'EC' || jwk.crv !== 'P-256') throw Error('Invalid P-256 public key');
  fromB64u(jwk.x, 32, 32); fromB64u(jwk.y, 32, 32);
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}
export async function exportPublic(key) { return publicJwk(await subtle.exportKey('jwk', key)); }
export async function importVerifyKey(jwk) { return subtle.importKey('jwk', publicJwk(jwk), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']); }
export async function importAgreementKey(jwk) { return subtle.importKey('jwk', publicJwk(jwk), { name: 'ECDH', namedCurve: 'P-256' }, true, []); }
export function randomId() { return crypto.randomUUID(); }
export function randomToken(length = 32) { if (length < 16 || length > 64) throw Error('Invalid token size'); return b64u(crypto.getRandomValues(new Uint8Array(length))); }
export async function generateDeviceKeys(existingId = randomId()) {
  requireId(existingId);
  const signing = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const agreement = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  return { deviceId: existingId, signing: { privateKey: signing.privateKey, publicKey: await exportPublic(signing.publicKey) }, agreement: { privateKey: agreement.privateKey, publicKey: await exportPublic(agreement.publicKey) } };
}
export async function digest(value) { return b64u(await subtle.digest('SHA-256', typeof value === 'string' ? utf8(value) : value)); }
export async function sign(privateKey, domain, fields) {
  return b64u(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, utf8(JSON.stringify([`shared-list:${domain}:v1`, ...fields]))));
}
export async function verify(publicKey, signature, domain, fields) {
  const signatureBytes = fromB64u(signature, 64, 64); // P-256 Web Crypto raw r||s
  const key = publicKey instanceof CryptoKey ? publicKey : await importVerifyKey(publicKey);
  return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signatureBytes, utf8(JSON.stringify([`shared-list:${domain}:v1`, ...fields])));
}
async function networkKey(listSecret, listId, epoch) {
  const raw = listSecret instanceof Uint8Array ? listSecret : fromB64u(listSecret, 32, 32);
  if (raw.length !== 32) throw Error('Invalid list secret');
  requireId(listId); requireEpoch(epoch);
  const hkdf = await subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: utf8('shared-list:envelope-salt:v1'), info: utf8(JSON.stringify(['operation', listId, epoch])) }, hkdf, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
function envelopeFields(e) { return [e.listId, e.epoch, e.membershipHash, e.opId, e.author, e.iv, e.data]; }
function validateEnvelope(e) {
  if (!e || e.v !== NETWORK_VERSION || Array.isArray(e)) throw Error('Invalid network envelope');
  const expected = ['v', 'listId', 'epoch', 'membershipHash', 'opId', 'author', 'iv', 'data', 'signature'].sort().join(',');
  if (Object.keys(e).sort().join(',') !== expected) throw Error('Unsupported envelope fields');
  requireId(e.listId); requireEpoch(e.epoch); requireHash(e.membershipHash); requireId(e.opId); requireId(e.author);
  fromB64u(e.iv, 12, 12);
  fromB64u(e.data, null, MAX_CIPHERTEXT);
  if (typeof e.signature !== 'string') throw Error('Missing envelope signature');
  fromB64u(e.signature, 64, 64);
}
export async function encryptOperation({ listSecret, listId, epoch, membershipHash, operation, device }) {
  requireId(listId); requireEpoch(epoch); requireHash(membershipHash);
  if (!operation || operation.v !== 1 || operation.device !== device.deviceId) throw Error('Operation author mismatch');
  requireId(operation.id);
  const key = await networkKey(listSecret, listId, epoch);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = utf8(JSON.stringify(['shared-list:aad:v1', listId, epoch, membershipHash, operation.id, device.deviceId]));
  const plain = utf8(JSON.stringify(operation));
  if (plain.length > MAX_CIPHERTEXT - 16) throw Error('Operation too large');
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plain);
  const envelope = { v: 1, listId, epoch, membershipHash, opId: operation.id, author: device.deviceId, iv: b64u(iv), data: b64u(ciphertext) };
  envelope.signature = await sign(device.signing.privateKey, 'envelope', envelopeFields(envelope));
  return envelope;
}
export function normalizeEnvelope(e) {
  return { v: e.v, listId: e.listId, epoch: e.epoch, membershipHash: e.membershipHash, opId: e.opId, author: e.author, iv: e.iv, data: e.data, signature: e.signature };
}
export async function verifyEnvelope(envelope, memberPublicKey) {
  validateEnvelope(envelope);
  if (!await verify(memberPublicKey, envelope.signature, 'envelope', envelopeFields(envelope))) throw Error('Invalid operation signature');
  return true;
}
export async function decryptOperation({ envelope, listSecret, memberPublicKey }) {
  await verifyEnvelope(envelope, memberPublicKey);
  const key = await networkKey(listSecret, envelope.listId, envelope.epoch);
  const aad = utf8(JSON.stringify(['shared-list:aad:v1', envelope.listId, envelope.epoch, envelope.membershipHash, envelope.opId, envelope.author]));
  const clear = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64u(envelope.iv, 12, 12), additionalData: aad }, key, fromB64u(envelope.data));
  const op = JSON.parse(dec.decode(clear));
  if (op?.v !== 1 || op.id !== envelope.opId || op.device !== envelope.author) throw Error('Decrypted operation identifiers do not match');
  return op;
}
function packageFields(pkg) {
  return [pkg.listId, pkg.epoch, pkg.from, pkg.to, pkg.membershipHash, pkg.ephemeral, pkg.salt, pkg.iv, pkg.data];
}
async function wrapKey(sharedBits, salt, fields) {
  const hkdf = await subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: utf8(JSON.stringify(['shared-list:wrap:v1', ...fields])) }, hkdf, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
export async function wrapListSecret({ secret, listId, epoch, sender, recipientId, recipientAgreementPublic, membershipHash }) {
  requireId(listId); requireEpoch(epoch); requireId(sender.deviceId); requireId(recipientId); requireHash(membershipHash);
  const raw = secret instanceof Uint8Array ? secret : fromB64u(secret, 32, 32);
  if (raw.length !== 32) throw Error('Invalid list secret');
  const ephemeral = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const target = await importAgreementKey(recipientAgreementPublic);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: target }, ephemeral.privateKey, 256);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const fields = [listId, epoch, sender.deviceId, recipientId, membershipHash];
  const key = await wrapKey(shared, salt, fields);
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(JSON.stringify(fields)) }, key, raw);
  const pkg = { v: 1, listId, epoch, from: sender.deviceId, to: recipientId, membershipHash, ephemeral: await exportPublic(ephemeral.publicKey), salt: b64u(salt), iv: b64u(iv), data: b64u(ciphertext) };
  pkg.signature = await sign(sender.signing.privateKey, 'wrapped-key', packageFields(pkg));
  return pkg;
}
export async function verifyWrappedPackage({ pkg, senderSigningPublic, expectedListId, expectedEpoch, expectedMembershipHash, expectedFrom, expectedTo }) {
  if (pkg?.v !== 1 || pkg.listId !== expectedListId || pkg.epoch !== expectedEpoch ||
      pkg.membershipHash !== expectedMembershipHash || pkg.from !== expectedFrom || pkg.to !== expectedTo) throw Error('Wrong wrapped key context');
  requireId(pkg.listId); requireEpoch(pkg.epoch); requireId(pkg.from); requireId(pkg.to); requireHash(pkg.membershipHash);
  fromB64u(pkg.salt, 16, 16); fromB64u(pkg.iv, 12, 12); fromB64u(pkg.data, 48, 48);
  await importAgreementKey(pkg.ephemeral);
  if (!await verify(senderSigningPublic, pkg.signature, 'wrapped-key', packageFields(pkg))) throw Error('Forged wrapped key');
  return true;
}
export async function unwrapListSecret({ pkg, recipient, senderSigningPublic, expectedListId, expectedEpoch, expectedMembershipHash }) {
  await verifyWrappedPackage({ pkg, recipient: recipient.deviceId, senderSigningPublic, expectedListId, expectedEpoch, expectedMembershipHash, expectedFrom: pkg.from, expectedTo: recipient.deviceId });
  const ephemeral = await importAgreementKey(pkg.ephemeral);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: ephemeral }, recipient.agreement.privateKey, 256);
  const fields = [pkg.listId, pkg.epoch, pkg.from, pkg.to, pkg.membershipHash];
  const key = await wrapKey(shared, fromB64u(pkg.salt, 16, 16), fields);
  const secret = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: fromB64u(pkg.iv, 12, 12), additionalData: utf8(JSON.stringify(fields)) }, key, fromB64u(pkg.data)));
  if (secret.length !== 32) throw Error('Invalid key delivery size');
  return secret;
}
export function newListSecret() { return crypto.getRandomValues(new Uint8Array(32)); }
