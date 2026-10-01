import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { profileKey } from '../crypto.mjs';
import { utf8 } from './ps.ts';

export interface Envelope { version: 1; nonce: string; ciphertext: string; }
const copy = (bytes: Uint8Array) => Uint8Array.from(bytes);
export async function walletSeed(secret: string, keyset: string) {
  const material = await crypto.subtle.importKey('raw', copy(hexToBytes(secret)), 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: copy(hexToBytes(keyset)), info: copy(utf8('Cashu_NFT_Coco_Seed_v1')) }, material, 512));
}
export class EncryptedVault {
  private key: Promise<CryptoKey>;
  private database: Promise<IDBDatabase>;
  constructor(private secret: string, private keyset: string) {
    this.key = (async () => {
      const material = await crypto.subtle.importKey('raw', copy(hexToBytes(secret)), 'HKDF', false, ['deriveKey']);
      return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: copy(hexToBytes(keyset)), info: copy(utf8('Cashu_NFT_Credential_Encryption_v1')) }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    })();
    this.database = new Promise((resolve, reject) => {
      const request = indexedDB.open(`cashu-nft-vault-v2:${profileKey(secret)}:${keyset}`, 1);
      request.onupgradeneeded = () => request.result.createObjectStore('encrypted', { keyPath: 'id' });
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
      request.onblocked = () => reject(new Error('Close other portfolio tabs to upgrade the wallet'));
    });
  }
  private aad(scope: string) { return copy(utf8(`Cashu_NFT_Encrypted_v1\n${profileKey(this.secret)}\n${this.keyset}\n${scope}`)); }
  async encrypt(value: unknown, scope: string): Promise<Envelope> {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: this.aad(scope), tagLength: 128 }, await this.key, copy(utf8(JSON.stringify(value))));
    return { version: 1, nonce: bytesToHex(nonce), ciphertext: bytesToHex(new Uint8Array(ciphertext)) };
  }
  async decrypt<T>(envelope: Envelope, scope: string): Promise<T> {
    if (envelope.version !== 1 || !/^[0-9a-f]{24}$/.test(envelope.nonce) || !/^(?:[0-9a-f]{2}){16,}$/.test(envelope.ciphertext)) throw new Error('Invalid encrypted wallet backup');
    const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: copy(hexToBytes(envelope.nonce)), additionalData: this.aad(scope), tagLength: 128 }, await this.key, copy(hexToBytes(envelope.ciphertext)));
    return JSON.parse(new TextDecoder().decode(raw)) as T;
  }
  async put(id: string, envelope: Envelope) { await this.transaction('readwrite', store => store.put({ id, envelope })); }
  async get(id: string): Promise<Envelope | null> {
    const row = await this.transaction<{ id: string; envelope: Envelope } | undefined>('readonly', store => store.get(id));
    return row?.envelope || null;
  }
  async remove(id: string) { await this.transaction('readwrite', store => store.delete(id)); }
  private async transaction<T>(mode: IDBTransactionMode, operation: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    const db = await this.database;
    return new Promise((resolve, reject) => {
      const tx = db.transaction('encrypted', mode), request = operation(tx.objectStore('encrypted'));
      tx.oncomplete = () => resolve(request.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('Wallet storage transaction aborted'));
    });
  }
  async close() { (await this.database).close(); }
}
