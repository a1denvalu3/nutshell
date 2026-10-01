// Transfer-link encryption: the fragment key (and optional password) are both
// required, and ciphertexts are bound to their link ID and asset hash.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { newLinkId, openLink, sealLink, linkUrl } from '../src/link.mjs';

const token = 'psnft1' + '03' + 'ab'.repeat(32) + 'cd'.repeat(48) + 'ef'.repeat(48) + '11'.repeat(32) + '22'.repeat(32);
const h = '11'.repeat(32);
const fast = { iterations: 100000 };

test('unprotected link round-trips with the fragment key only', async () => {
  const id = newLinkId();
  const { fragment, envelope } = await sealLink(token, { id, h });
  assert.equal(envelope.kdf, null);
  assert.match(envelope.nonce, /^[0-9a-f]{24}$/);
  assert.match(fragment, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(await openLink(envelope, { id, h, fragment }), token);
  assert.ok(!envelope.ciphertext.includes(Buffer.from(token).toString('hex')), 'ciphertext must not contain the token');
});

test('password-protected link needs both the fragment and the password', async () => {
  const id = newLinkId();
  const { fragment, envelope } = await sealLink(token, { id, h, password: 'correct horse', ...fast });
  assert.equal(envelope.kdf.name, 'PBKDF2-SHA256');
  assert.match(envelope.kdf.salt, /^[0-9a-f]{32}$/);
  assert.equal(await openLink(envelope, { id, h, fragment, password: 'correct horse' }), token);
  await assert.rejects(openLink(envelope, { id, h, fragment }), /Enter the password/);
  await assert.rejects(openLink(envelope, { id, h, fragment, password: 'wrong horse' }), /password doesn/);
  const other = (await sealLink(token, { id, h })).fragment;
  await assert.rejects(openLink(envelope, { id, h, fragment: other, password: 'correct horse' }), /password doesn/);
});

test('default protection uses 600k PBKDF2 iterations', async () => {
  const { envelope } = await sealLink(token, { id: newLinkId(), h, password: 'pw' });
  assert.equal(envelope.kdf.iterations, 600000);
});

test('ciphertext is bound to the link id, asset hash and protection flag', async () => {
  const id = newLinkId();
  const { fragment, envelope } = await sealLink(token, { id, h });
  await assert.rejects(openLink(envelope, { id: newLinkId(), h, fragment }), /damaged/);
  await assert.rejects(openLink(envelope, { id, h: '22'.repeat(32), fragment }), /damaged/);
  const flipped = { ...envelope, ciphertext: (envelope.ciphertext[0] === 'a' ? 'b' : 'a') + envelope.ciphertext.slice(1) };
  await assert.rejects(openLink(flipped, { id, h, fragment }), /damaged/);
  // Stripping the password requirement from the stored envelope doesn't help an attacker.
  const locked = await sealLink(token, { id, h, password: 'pw', ...fast });
  await assert.rejects(openLink({ ...locked.envelope, kdf: null }, { id, h, fragment: locked.fragment }), /damaged/);
});

test('missing or malformed fragments are rejected clearly', async () => {
  const id = newLinkId();
  const { envelope } = await sealLink(token, { id, h });
  await assert.rejects(openLink(envelope, { id, h, fragment: '' }), /incomplete/);
  await assert.rejects(openLink(envelope, { id, h, fragment: 'abc' }), /incomplete/);
});

test('link URLs carry the key only in the fragment', () => {
  const url = new URL(linkUrl('https://jpg.example', 'a'.repeat(32), 'K'.repeat(43)));
  assert.equal(url.pathname, '/claim/' + 'a'.repeat(32));
  assert.equal(url.search, '');
  assert.equal(url.hash, '#' + 'K'.repeat(43));
});
