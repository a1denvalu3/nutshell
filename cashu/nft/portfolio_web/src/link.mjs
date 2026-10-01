// Transfer links. The bearer token is encrypted in the sender's browser with a
// random key that only travels in the URL fragment (never sent to a server).
// An optional password is stretched with PBKDF2 and mixed into the key, so the
// link alone is not enough to claim. The server only ever stores ciphertext.
const enc = new TextEncoder();
const DOMAIN = 'Cashu_NFT_Link_v1';
export const LINK_ITERATIONS = 600000;

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s) => Uint8Array.from(s.match(/../g) || [], (x) => parseInt(x, 16));
const concat = (a, b) => { const out = new Uint8Array(a.length + b.length); out.set(a); out.set(b, a.length); return out; };
const b64url = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function unb64url(s) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(s || '')) throw new Error('This link is incomplete. Ask the sender for the full link.');
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='), (c) => c.charCodeAt(0));
}
const aad = (id, h, locked) => enc.encode(`${DOMAIN}\n${id}\n${h}\n${locked ? 1 : 0}`);

async function deriveKey(secret, id, h, password, kdf) {
  let ikm = secret;
  if (kdf) {
    if (kdf.name !== 'PBKDF2-SHA256') throw new Error('Unsupported link protection.');
    const pw = await crypto.subtle.importKey('raw', enc.encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
    const stretched = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unhex(kdf.salt), iterations: kdf.iterations }, pw, 256));
    ikm = concat(secret, stretched);
  }
  const material = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(`${DOMAIN}\n${id}\n${h}`) },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export const newLinkId = () => hex(crypto.getRandomValues(new Uint8Array(16)));
export const linkUrl = (origin, id, fragment) => `${origin}/claim/${id}#${fragment}`;

export async function sealLink(token, { id, h, password = '', iterations = LINK_ITERATIONS }) {
  if (!/^[0-9a-f]{32}$/.test(id) || !/^[0-9a-f]{64}$/.test(h)) throw new Error('Invalid link parameters.');
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const kdf = password ? { name: 'PBKDF2-SHA256', iterations, salt: hex(crypto.getRandomValues(new Uint8Array(16))) } : null;
  const key = await deriveKey(secret, id, h, password, kdf);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(id, h, !!kdf) }, key, enc.encode(token)));
  return { fragment: b64url(secret), envelope: { version: 1, kdf, nonce: hex(nonce), ciphertext: hex(ciphertext) } };
}

export async function openLink(envelope, { id, h, fragment, password = '' }) {
  const secret = unb64url(fragment);
  if (envelope.kdf && !password) throw new Error('Enter the password for this link.');
  const key = await deriveKey(secret, id, h, password, envelope.kdf);
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unhex(envelope.nonce), additionalData: aad(id, h, !!envelope.kdf) }, key, unhex(envelope.ciphertext));
    return new TextDecoder().decode(plain);
  } catch {
    throw new Error(envelope.kdf ? 'That password doesn’t unlock this link.' : 'This link is damaged. Ask the sender for the full link.');
  }
}
