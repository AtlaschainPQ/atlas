/**
 * ATLAS Wallet
 *
 * Verwaltet Schlüsselpaare, Adressen und erstellt Transaktionen.
 */

import { Amount, MIN_FEE_ATOM, MAX_FEE_ATOM, splitReward } from './amount';
import {
  KeyPair,
  generateKeyPair,
  keyPairFromPrivateKey,
  sign,
  doubleSha256,
  sha256,
  toHex,
  fromHex,
} from './crypto';

// ── TX-Stamp (Mini PoW) ────────────────────────────────────────────────────

export interface TxStamp {
  nonce:      bigint;
  difficulty: number;
  hash:       Uint8Array;  // 32 Bytes
}

function stampHash(txHash: Uint8Array, nonce: bigint): Uint8Array {
  const buf = new Uint8Array(40);
  buf.set(txHash, 0);
  // nonce als 8-Byte Little-Endian
  let n = nonce;
  for (let i = 0; i < 8; i++) {
    buf[32 + i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return sha256(buf);
}

function leadingZeroBits(hash: Uint8Array): number {
  let count = 0;
  for (const byte of hash) {
    const z = Math.clz32(byte << 24);
    count += z;
    if (z < 8) break;
  }
  return count;
}

/** Berechnet TX-Stamp (Mini-PoW) */
export function mineStamp(txHash: Uint8Array, difficulty = 16): TxStamp {
  for (let nonce = 0n; nonce <= BigInt(Number.MAX_SAFE_INTEGER); nonce++) {
    const hash = stampHash(txHash, nonce);
    if (leadingZeroBits(hash) >= difficulty) {
      return { nonce, difficulty, hash };
    }
  }
  throw new Error('TX-Stamp: nonce overflow');
}

/** Verifiziert TX-Stamp */
export function verifyStamp(stamp: TxStamp, txHash: Uint8Array): boolean {
  const computed = stampHash(txHash, stamp.nonce);
  if (toHex(computed) !== toHex(stamp.hash)) return false;
  return leadingZeroBits(computed) >= stamp.difficulty;
}

// ── Transaktions-Typen ─────────────────────────────────────────────────────

export interface TxOutput {
  address: string;    // ATL:...
  value:   Amount;    // in ATOM
}

export interface TxInput {
  prevTxid:   string;   // hex
  prevIndex:  number;
  sequence:   number;
  signature?: string;   // hex, nach Signierung gesetzt
  publicKey?: string;   // hex
}

export interface Transaction {
  version:    number;
  inputs:     TxInput[];
  outputs:    TxOutput[];
  fee:        Amount;
  timestamp:  number;
  stamp?:     TxStamp;
  txType:     'transfer' | 'coinbase' | 'settlement_bid';
}

// ── Serialisierung für TXID-Berechnung ────────────────────────────────────

export function serializeForSigning(tx: Transaction): Uint8Array {
  const obj = {
    version:  tx.version,
    inputs:   tx.inputs.map(i => ({
      prevTxid:  i.prevTxid,
      prevIndex: i.prevIndex,
      sequence:  i.sequence,
    })),
    outputs:  tx.outputs.map(o => ({
      address: o.address,
      value:   o.value.atom.toString(),
    })),
    fee:      tx.fee.atom.toString(),
    timestamp: tx.timestamp,
    txType:   tx.txType,
  };
  const json = JSON.stringify(obj);
  return new TextEncoder().encode(json);
}

export function computeTxId(tx: Transaction): string {
  const data = serializeForSigning(tx);
  return toHex(doubleSha256(data));
}

// ── Wallet ─────────────────────────────────────────────────────────────────

export interface WalletState {
  keyPair:  KeyPair;
  utxos:    Map<string, { value: Amount; address: string }>;  // outpoint → utxo
  label?:   string;
}

export class AtlasWallet {
  private state: WalletState;

  constructor(keyPair?: KeyPair, label?: string) {
    this.state = {
      keyPair: keyPair ?? generateKeyPair(),
      utxos:   new Map(),
      label,
    };
  }

  get address(): string  { return this.state.keyPair.address; }
  get publicKey(): string { return toHex(this.state.keyPair.publicKey); }

  get privateKeyHex(): string {
    return toHex(this.state.keyPair.privateKey);
  }

  /** Erstellt Wallet aus privatem Schlüssel (hex) */
  static fromPrivateKey(hex: string, label?: string): AtlasWallet {
    return new AtlasWallet(keyPairFromPrivateKey(hex), label);
  }

  /** Generiert neues Wallet */
  static generate(label?: string): AtlasWallet {
    return new AtlasWallet(undefined, label);
  }

  // ── UTXO-Verwaltung ──────────────────────────────────────────────────────

  addUtxo(txid: string, index: number, value: Amount): void {
    const key = `${txid}:${index}`;
    this.state.utxos.set(key, { value, address: this.address });
  }

  removeUtxo(txid: string, index: number): void {
    this.state.utxos.delete(`${txid}:${index}`);
  }

  balance(): Amount {
    let total = Amount.zero();
    for (const utxo of this.state.utxos.values()) {
      total = total.add(utxo.value);
    }
    return total;
  }

  // ── Transaktion erstellen ─────────────────────────────────────────────────

  async createTransfer(
    toAddress:  string,
    amount:     Amount,
    fee?:       Amount,
    stampDifficulty = 16,
  ): Promise<Transaction> {
    const feeToUse = fee ?? Amount.fromAtom(10n); // Default: 10 ATOM

    if (!feeToUse.isValidFee()) {
      throw new Error(`Fee out of range: ${feeToUse.atom} ATOM (min=${MIN_FEE_ATOM}, max=${MAX_FEE_ATOM})`);
    }

    const needed   = amount.add(feeToUse);
    const selected = this.selectUtxos(needed);

    if (!selected) {
      throw new Error(
        `Insufficient funds: need ${needed}, have ${this.balance()}`
      );
    }

    const { inputs, total } = selected;
    const change            = total.sub(needed);

    const outputs: TxOutput[] = [
      { address: toAddress, value: amount },
    ];
    if (!change.isZero()) {
      outputs.push({ address: this.address, value: change });
    }

    const tx: Transaction = {
      version:   1,
      inputs,
      outputs,
      fee:       feeToUse,
      timestamp: Date.now(),
      txType:    'transfer',
    };

    // Signieren
    await this.signTransaction(tx);

    // TX-Stamp berechnen
    const txId   = computeTxId(tx);
    const txHash = fromHex(txId);
    tx.stamp     = mineStamp(txHash, stampDifficulty);

    return tx;
  }

  private selectUtxos(needed: Amount): { inputs: TxInput[]; total: Amount } | null {
    let total  = Amount.zero();
    const inputs: TxInput[] = [];

    for (const [key, utxo] of this.state.utxos) {
      const [txid, idx] = key.split(':');
      inputs.push({
        prevTxid:  txid,
        prevIndex: parseInt(idx),
        sequence:  0xFFFFFFFF,
      });
      total = total.add(utxo.value);
      if (total.gte(needed)) {
        return { inputs, total };
      }
    }

    return total.gte(needed) ? { inputs, total } : null;
  }

  private async signTransaction(tx: Transaction): Promise<void> {
    const data = serializeForSigning(tx);
    const hash = doubleSha256(data);
    const sig  = await sign(hash, this.state.keyPair.privateKey);

    for (const input of tx.inputs) {
      input.signature = toHex(sig);
      input.publicKey = toHex(this.state.keyPair.publicKey);
    }
  }

  // ── Info ─────────────────────────────────────────────────────────────────

  info(): WalletInfo {
    return {
      address:    this.address,
      balance:    this.balance().toAtlDecimal() + ' ATL',
      balanceRaw: this.balance().atom.toString() + ' ATOM',
      utxoCount:  this.state.utxos.size,
      label:      this.state.label,
    };
  }

  /** Zeigt Fee-Tabelle bei verschiedenen ATL-Preisen */
  static feeTable(): void {
    console.log('\n=== ATLAS Fee-Tabelle ===');
    console.log('100 ATOM bei verschiedenen ATL-Preisen:\n');
    console.log('ATL-Preis €  | 100 ATOM Fee');
    console.log('-------------|----------------');
    const fee    = Amount.fromAtom(100n);
    const prices = [1000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000];
    for (const price of prices) {
      const feeStr = fee.feeInEuros(price);
      console.log(`${price.toString().padStart(12)} | ${feeStr}`);
    }
  }

  /** Zeigt Emission-Schedule */
  static emissionSchedule(): void {
    console.log('\n=== ATLAS Emissionsplan ===');
    let subsidy = 64n;
    const HALVING = 210_240n;
    let cumulative = Amount.zero();
    for (let era = 0; era < 10 && subsidy > 0n; era++) {
      const sub        = Amount.fromAtl(subsidy);
      const eraTotal   = sub.mul(HALVING);
      cumulative       = cumulative.add(eraTotal);
      const startBlock = BigInt(era) * HALVING;
      console.log(
        `Era ${era}: Block ${startBlock.toString().padStart(8)} | ` +
        `${subsidy} ATL/Block | Era-Gesamt: ${eraTotal.toAtlFloor().toString().padStart(10)} ATL`
      );
      subsidy /= 2n;
    }
    console.log(`\nKumulativ (10 Eras): ~${cumulative.toAtlFloor()} ATL`);
    console.log(`Max Supply: ~26.910.720 ATL`);
  }
}

export interface WalletInfo {
  address:    string;
  balance:    string;
  balanceRaw: string;
  utxoCount:  number;
  label?:     string;
}
