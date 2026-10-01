import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import 'fake-indexeddb/auto';
import { bytesToHex } from '@noble/hashes/utils.js';
import { EncryptedVault, walletSeed } from '../src/wallet/vault.ts';
import { hashAsset, integer, encodeToken, decodeToken, verifyCredential, publicCard } from '../src/wallet/ps.ts';
import { splitJpg, transferJpg } from '../src/wallet/jpg.ts';
import { profileKey, verifyCard } from '../src/crypto.mjs';
import { openWallet } from '../src/wallet/index.ts';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/wallet.json', import.meta.url)));
const jpg = Uint8Array.from(Buffer.from(fixture.jpg, 'base64'));
const secret = '33'.repeat(32), pubkey = profileKey(secret);

test('Python credentials and EXIF transfers match the browser implementation', () => {
  const token = encodeToken(fixture.credential);
  assert.deepEqual(decodeToken(token), fixture.credential);
  verifyCredential(fixture.credential, fixture.config);
  assert.equal(bytesToHex(integer(hashAsset(jpg))), fixture.credential.h);
  const wrapped = transferJpg(jpg, token);
  assert.deepEqual(wrapped, Uint8Array.from(Buffer.from(fixture.transfer, 'base64')));
  assert.deepEqual(splitJpg(wrapped), {jpg, token});
  assert.deepEqual(splitJpg(jpg), {jpg, token:null});
  const segment = wrapped.slice(2, wrapped.length - jpg.length + 2);
  const duplicate = new Uint8Array([...wrapped.slice(0,2), ...segment, ...wrapped.slice(2)]);
  assert.throws(() => splitJpg(duplicate), /multiple/);
  assert.throws(() => decodeToken(token.slice(0,-2)), /Invalid/);
});

test('browser-generated showings bind the collector and fail for another profile', () => {
  const card = {pubkey, h:fixture.credential.h, ...publicCard(fixture.credential, secret, pubkey)};
  assert.equal(verifyCard(card, pubkey, fixture.config).valid, true);
  assert.equal(verifyCard(card, profileKey('44'.repeat(32)), fixture.config).valid, false);
  assert.throws(() => verifyCredential({...fixture.credential, s:'00'.repeat(32)}, fixture.config));
  assert.throws(() => verifyCredential({...fixture.credential, h:'01'.repeat(32)}, fixture.config));
});

test('authenticated encryption binds owner, keyset and card and survives another vault', async () => {
  const vault = new EncryptedVault(secret, fixture.config.keyset_id);
  const other = new EncryptedVault('44'.repeat(32), fixture.config.keyset_id);
  const restored = new EncryptedVault(secret, fixture.config.keyset_id);
  try {
    const envelope = await vault.encrypt(fixture.credential, 'card:example');
    assert.equal(JSON.stringify(envelope).includes(fixture.credential.s), false);
    assert.notDeepEqual(envelope, await vault.encrypt(fixture.credential, 'card:example'));
    await vault.put('example', envelope);
    assert.deepEqual(await restored.decrypt(await restored.get('example'), 'card:example'), fixture.credential);
    await assert.rejects(other.decrypt(envelope, 'card:example'));
    await assert.rejects(restored.decrypt(envelope, 'card:another'));
    const tampered = {...envelope, ciphertext:(envelope.ciphertext.startsWith('00') ? '01':'00') + envelope.ciphertext.slice(2)};
    await assert.rejects(restored.decrypt(tampered, 'card:example'));
    const seed = await walletSeed(secret, fixture.config.keyset_id);
    assert.equal(seed.length, 64);
    assert.deepEqual(seed, await walletSeed(secret, fixture.config.keyset_id));
    assert.notDeepEqual(seed, await walletSeed('44'.repeat(32), fixture.config.keyset_id));
  } finally {await vault.close();await other.close();await restored.close();}
});

test('real Coco initializes the PS extension with the overridden cashu-ts rc.11', async () => {
  globalThis.location = {origin:'https://wallet.test'};
  const {manager, wallet} = await openWallet(secret, fixture.config);
  assert.equal(manager.ext.nft, wallet);
  assert.equal(wallet.pubkey, pubkey);
  await manager.dispose();
});
