/**
 * Kryptographie: Schlüsselgenerierung, Signatur, Adresse
 * secp256k1 + SHA-256 + RIPEMD-160
 */

import { createHash } from 'crypto';
import * as secp from '@noble/secp256k1';

// Wir nutzen @noble/secp256k1 oder native crypto je nach Verfügbarkeit

export type Hash32 = Uint8Array;  // 32 Bytes
export type Bytes  = Uint8Array;

/** sha256(data) */
export function sha256(data: Uint8Array): Hash32 {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/** sha256(sha256(data)) */
export function doubleSha256(data: Uint8Array): Hash32 {
  return sha256(sha256(data));
}

/** RIPEMD-160 */
export function ripemd160(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('ripemd160').update(data).digest());
}

/** Hex → Uint8Array */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Uint8Array → Hex */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** ATLAS Adresse: "ATL:" + hex(RIPEMD160(SHA256(pubkey))) */
export function publicKeyToAddress(publicKey: Uint8Array): string {
  const sha    = sha256(publicKey);
  const ripe   = ripemd160(sha);
  return `ATL:${toHex(ripe)}`;
}

/** ATLAS Schlüsselpaar */
export interface KeyPair {
  privateKey:  Uint8Array;
  publicKey:   Uint8Array;   // 33 Bytes, komprimiert
  address:     string;        // ATL:...
}

/** Generiert ein neues Schlüsselpaar */
export function generateKeyPair(): KeyPair {
  const privateKey = secp.utils?.randomPrivateKey?.() ?? (() => {
    // Fallback: node crypto
    const { randomBytes } = require('crypto');
    return randomBytes(32) as Uint8Array;
  })();
  const publicKey = secp.getPublicKey(privateKey, true);
  const address   = publicKeyToAddress(publicKey);
  return { privateKey, publicKey, address };
}

/** Signiert eine Nachricht */
export async function sign(messageHash: Hash32, privateKey: Uint8Array): Promise<Uint8Array> {
  const sig = await secp.sign(messageHash, privateKey, { der: false });
  return sig;
}

/** Verifiziert eine Signatur */
export async function verify(
  signature:   Uint8Array,
  messageHash: Hash32,
  publicKey:   Uint8Array,
): Promise<boolean> {
  try {
    return secp.verify(signature, messageHash, publicKey);
  } catch {
    return false;
  }
}

/** Privaten Schlüssel aus Hex laden */
export function keyPairFromPrivateKey(privateKeyHex: string): KeyPair {
  const privateKey = fromHex(privateKeyHex);
  const publicKey  = secp.getPublicKey(privateKey, true);
  const address    = publicKeyToAddress(publicKey);
  return { privateKey, publicKey, address };
}
