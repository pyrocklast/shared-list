// Local sealed blobs. These are NOT signed network envelopes.
// AAD binds a blob to its purpose and list/operation identifiers.
const encoder = new TextEncoder();
const decoder = new TextDecoder();
function b64(bytes) {
  let text = '';
  for (const byte of new Uint8Array(bytes)) text += String.fromCharCode(byte);
  return btoa(text);
}
function unb64(text) { return Uint8Array.from(atob(text), c => c.charCodeAt(0)); }
export const docContext = id => `shared-list:local-document:v1:${id}`;
export const opContext = (listId, opId) => `shared-list:pending-operation:v1:${listId}:${opId}`;
export async function seal(key, value, context) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(context) }, key, plaintext);
  return { iv: b64(iv), data: b64(ciphertext) };
}
export async function unseal(key, blob, context) {
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv), additionalData: encoder.encode(context) }, key, unb64(blob.data));
  return JSON.parse(decoder.decode(plaintext));
}
