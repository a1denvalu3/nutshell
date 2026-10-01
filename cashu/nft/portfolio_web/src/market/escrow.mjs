// Preimage escrow envelope (esc1), browser side. Must match
// cashu/nft/market_protocol.py: ephemeral P-256 ECDH to the NFT mint's escrow
// key, HKDF-SHA256(salt = epk || rpk, info = domain || version || manifest
// hash) and AES-256-GCM with the same AAD. Only the NFT mint can open it.
const enc = new TextEncoder();
const DOMAIN = 'Cashu_NFT_Escrow_v1';

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s) => Uint8Array.from(s.match(/../g) || [], (x) => parseInt(x, 16));
const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0; for (const p of parts) { out.set(p, i); i += p.length; } return out; };
const aad = (version, mhash) => concat(enc.encode(DOMAIN), enc.encode('\n'), enc.encode(version), enc.encode('\n'), mhash);

export async function sealPreimage(publicKeyHex, version, preimage, mhash) {
  if (preimage.length !== 32 || mhash.length !== 32) throw new Error('Invalid escrow input');
  const rpk = unhex(publicKeyHex);
  const recipient = await crypto.subtle.importKey('raw', rpk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const epk = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: recipient }, eph.privateKey, 256));
  const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: concat(epk, rpk), info: aad(version, mhash) },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(version, mhash) }, key, preimage));
  return { v: version, epk: hex(epk), nonce: hex(nonce), ct: hex(ct) };
}
