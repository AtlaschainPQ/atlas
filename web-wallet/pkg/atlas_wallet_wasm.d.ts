/* tslint:disable */
/* eslint-disable */

/**
 * Stellt ein Konto aus einer BIP39-Mnemonic wieder her.
 */
export function account_from_mnemonic(phrase: string): string;

/**
 * Leitet pubkey/address aus einem bestehenden Secret (Hex) ab.
 */
export function account_from_secret(secret_hex: string): string;

/**
 * Baut die Parameter für den Node-RPC `forcel2tx` (Forced Inclusion / Escape-Hatch).
 * `sender_index` = Index des Kontos im L2-Baum (aus den On-Chain-Calldata ableitbar).
 */
export function build_forced_tx(secret_hex: string, to_hex: string, amount: string, fee: string, nonce: bigint, sender_index: bigint): string;

/**
 * Baut die signierte L2-Transaktion als JSON für `POST /submit` (Aggregator).
 * Beträge als Strings, da JS-`number` keine u128 sicher hält.
 */
export function build_submit_tx(secret_hex: string, to_hex: string, amount: string, fee: string, nonce: bigint): string;

/**
 * Erzeugt einen neuen L2-Account aus 32 Byte OS-Entropie.
 */
export function generate_account(): string;

/**
 * Erzeugt einen neuen Account MIT 24-Wort-BIP39-Mnemonic (256-bit Entropie).
 * Die Mnemonic ist das kanonische Backup: `account_from_mnemonic` stellt exakt
 * dasselbe Konto wieder her. Rückgabe enthält zusätzlich `mnemonic`.
 */
export function generate_mnemonic(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly account_from_mnemonic: (a: number, b: number) => [number, number, number, number];
    readonly account_from_secret: (a: number, b: number) => [number, number, number, number];
    readonly build_forced_tx: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: bigint) => [number, number, number, number];
    readonly build_submit_tx: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint) => [number, number, number, number];
    readonly generate_account: () => [number, number, number, number];
    readonly generate_mnemonic: () => [number, number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
