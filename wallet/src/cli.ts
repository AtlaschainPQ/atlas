#!/usr/bin/env ts-node
/**
 * ATLAS Wallet CLI
 */

import { AtlasWallet, mineStamp, verifyStamp } from './wallet';
import { Amount } from './amount';
import { toHex } from './crypto';

const args = process.argv.slice(2);
const cmd  = args[0] ?? 'help';

async function main(): Promise<void> {
  switch (cmd) {
    case 'new':
      cmdNew();
      break;
    case 'info':
      cmdInfo();
      break;
    case 'fees':
      AtlasWallet.feeTable();
      break;
    case 'emission':
      AtlasWallet.emissionSchedule();
      break;
    case 'stamp-test':
      await cmdStampTest();
      break;
    case 'demo':
      await cmdDemo();
      break;
    default:
      printHelp();
  }
}

function cmdNew(): void {
  const wallet = AtlasWallet.generate(args[1]);
  console.log('\n=== Neues ATLAS Wallet ===');
  console.log(`Adresse:     ${wallet.address}`);
  console.log(`Public Key:  ${wallet.publicKey}`);
  console.log(`Private Key: ${wallet.privateKeyHex}`);
  console.log('\n⚠  Private Key sicher aufbewahren!');
}

function cmdInfo(): void {
  const key = args[1];
  if (!key) {
    console.error('Verwendung: atlas-wallet info <private-key-hex>');
    process.exit(1);
  }
  try {
    const wallet = AtlasWallet.fromPrivateKey(key);
    const info   = wallet.info();
    console.log('\n=== ATLAS Wallet Info ===');
    console.log(`Adresse:  ${info.address}`);
    console.log(`Balance:  ${info.balance}`);
    console.log(`UTXOs:    ${info.utxoCount}`);
  } catch (e) {
    console.error('Ungültiger Private Key:', e);
    process.exit(1);
  }
}

async function cmdStampTest(): Promise<void> {
  const difficulty = parseInt(args[1] ?? '16', 10);
  console.log(`\n=== TX-Stamp Test (Difficulty: ${difficulty} Bits) ===`);

  const testData = new TextEncoder().encode('ATLAS test transaction');
  const crypto   = require('crypto');
  const txHash   = new Uint8Array(crypto.createHash('sha256').update(testData).digest());

  console.log(`TX-Hash: ${toHex(txHash)}`);
  console.log('Mining TX-Stamp...');

  const t0    = Date.now();
  const stamp = mineStamp(txHash, difficulty);
  const ms    = Date.now() - t0;

  console.log(`Nonce:    ${stamp.nonce}`);
  console.log(`Hash:     ${toHex(stamp.hash)}`);
  console.log(`Zeit:     ${ms} ms`);
  console.log(`Gültig:   ${verifyStamp(stamp, txHash)}`);
}

async function cmdDemo(): Promise<void> {
  console.log('\n=== ATLAS Wallet Demo ===\n');

  // Wallets erstellen
  const alice = AtlasWallet.generate('Alice');
  const bob   = AtlasWallet.generate('Bob');

  console.log(`Alice: ${alice.address}`);
  console.log(`Bob:   ${bob.address}`);

  // Alice erhält UTXO (simuliert eingehende TX)
  const incomingValue = Amount.fromAtl(100n);
  alice.addUtxo('0000000000000000000000000000000000000000000000000000000000000000', 0, incomingValue);

  console.log(`\nAlice Balance: ${alice.balance().toAtlDecimal()} ATL`);

  // Alice sendet 10 ATL an Bob
  const sendAmount = Amount.fromAtl(10n);
  const fee        = Amount.fromAtom(50n);

  console.log(`\nSende ${sendAmount.toAtlDecimal()} ATL an Bob (Fee: ${fee.atom} ATOM)...`);
  console.log('(TX-Stamp wird berechnet, ca. 20-50ms)');

  const t0 = Date.now();
  const tx = await alice.createTransfer(bob.address, sendAmount, fee, 14);
  const ms = Date.now() - t0;

  console.log(`\nTransaktion erstellt in ${ms} ms:`);
  console.log(`  Inputs:   ${tx.inputs.length}`);
  console.log(`  Outputs:  ${tx.outputs.length}`);
  console.log(`  Fee:      ${tx.fee.atom} ATOM`);
  console.log(`  Stamp:    Nonce=${tx.stamp?.nonce}, Difficulty=${tx.stamp?.difficulty}`);
  console.log(`  Gültig:   ${tx.stamp ? verifyStamp(tx.stamp, Buffer.from(toHex(tx.stamp.hash), 'hex')) : 'n/a'}`);

  // Fee-Tabelle
  AtlasWallet.feeTable();

  // Emissionsplan
  AtlasWallet.emissionSchedule();
}

function printHelp(): void {
  console.log('\n=== ATLAS Wallet CLI ===');
  console.log('Befehle:');
  console.log('  new [label]           — Neues Wallet generieren');
  console.log('  info <private-key>    — Wallet-Info anzeigen');
  console.log('  fees                  — Fee-Tabelle anzeigen');
  console.log('  emission              — Emissionsplan anzeigen');
  console.log('  stamp-test [bits]     — TX-Stamp testen (default: 16 Bits)');
  console.log('  demo                  — Demo ausführen');
  console.log('  help                  — Diese Hilfe');
}

main().catch(console.error);
