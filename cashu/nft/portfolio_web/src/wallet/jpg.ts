import { concatBytes } from '@noble/hashes/utils.js';
import { utf8, integer } from './ps.ts';

const commentPrefix = new Uint8Array([65, 83, 67, 73, 73, 0, 0, 0]);
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => b[i] === v);
const le = (n: number, width: number) => integer(BigInt(n), width).reverse();
function envelope(token: string) {
  if (!/^psnft1[0-9a-f]{386}$/.test(token)) throw new Error('Invalid NFT transfer token');
  const comment = concatBytes(commentPrefix, utf8(token));
  const tiff = concatBytes(utf8('II'), le(42, 2), le(8, 4), le(1, 2), le(0x8769, 2), le(4, 2), le(1, 4), le(26, 4), le(0, 4), le(1, 2), le(0x9286, 2), le(7, 2), le(comment.length, 4), le(44, 4), le(0, 4), comment);
  const payload = concatBytes(new Uint8Array([69, 120, 105, 102, 0, 0]), tiff);
  return concatBytes(new Uint8Array([255, 225]), integer(BigInt(payload.length + 2), 2), payload);
}
export function splitJpg(bytes: Uint8Array): { jpg: Uint8Array; token: string | null } {
  if (bytes[0] !== 255 || bytes[1] !== 216) throw new Error('Choose a JPG file');
  let pos = 2, token: string | null = null;
  const chunks = [bytes.slice(0, 2)];
  while (pos < bytes.length) {
    const start = pos;
    if (bytes[pos] !== 255) throw new Error('Invalid JPG marker');
    while (bytes[pos] === 255) pos++;
    const marker = bytes[pos++];
    if (marker === 218 || marker === 217) { chunks.push(bytes.slice(start)); return { jpg: concatBytes(...chunks), token }; }
    if (marker === 1 || (marker >= 208 && marker <= 215)) { chunks.push(bytes.slice(start, pos)); continue; }
    if (pos + 2 > bytes.length) throw new Error('Truncated JPG');
    const length = bytes[pos] * 256 + bytes[pos + 1], end = pos + length;
    if (length < 2 || end > bytes.length) throw new Error('Truncated JPG segment');
    const segment = bytes.slice(start, end);
    // Only our exact, canonical APP1 envelope is removable. Other EXIF bytes
    // remain part of the JPG's identity, matching the Python parser.
    const candidate = new TextDecoder('ascii').decode(segment.slice(62));
    if (candidate.startsWith('psnft1') && /^psnft1[0-9a-f]{386}$/.test(candidate) && equal(segment, envelope(candidate))) {
      if (token) throw new Error('This JPG contains multiple transfer tokens');
      token = candidate;
    } else chunks.push(segment);
    pos = end;
  }
  throw new Error('Truncated JPG');
}
export function transferJpg(jpg: Uint8Array, token: string) {
  if (splitJpg(jpg).token) throw new Error('The public JPG already contains a transfer token');
  return concatBytes(jpg.slice(0, 2), envelope(token), jpg.slice(2));
}
