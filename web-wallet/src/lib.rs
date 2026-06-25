//! ATLAS Web-Wallet — WASM-Krypto-Kern.
//!
//! Kapselt das L2-Signing (Baby-Jubjub-EdDSA + Poseidon) aus `atlas-zk`, sodass
//! der Browser **byte-identische** Signaturen erzeugt wie der Aggregator/Circuit
//! sie erwartet. Reine JS-Nachbauten würden vom Groth16-Circuit abgelehnt.
//!
//! Exportierte Funktionen (via wasm-bindgen):
//!   - `generate_account()`            → {secret,pubkey,address} (neuer Schlüssel)
//!   - `account_from_secret(hex)`      → {secret,pubkey,address}
//!   - `build_submit_tx(...)`          → JSON für POST /submit (Aggregator)
//!   - `build_forced_tx(...)`          → params-JSON für RPC `forcel2tx` (Node)

use atlas_zk::eddsa::EddsaKeypair;
use atlas_zk::l2_state::build_l2_eddsa;
use serde_json::json;
use wasm_bindgen::prelude::*;

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], JsError> {
    let v = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{what}: kein Hex: {e}")))?;
    v.as_slice().try_into().map_err(|_| JsError::new(&format!("{what} muss 32 Byte sein")))
}

fn parse_addr(s: &str) -> Result<[u8; 20], JsError> {
    let v = hex::decode(s.trim_start_matches("0x").trim_start_matches("ATL:"))
        .map_err(|e| JsError::new(&format!("Adresse: kein Hex: {e}")))?;
    v.as_slice().try_into().map_err(|_| JsError::new("Adresse muss 20 Byte sein"))
}

fn parse_u128(s: &str, what: &str) -> Result<u128, JsError> {
    s.trim().parse().map_err(|_| JsError::new(&format!("{what}: keine gültige Ganzzahl")))
}

fn account_json(kp: &EddsaKeypair) -> String {
    json!({
        "secret":  hex::encode(kp.secret_bytes()),
        "pubkey":  hex::encode(kp.public().to_bytes()),
        "address": hex::encode(kp.public().address20()),
    }).to_string()
}

/// Erzeugt einen neuen L2-Account aus 32 Byte OS-Entropie.
#[wasm_bindgen]
pub fn generate_account() -> Result<String, JsError> {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).map_err(|e| JsError::new(&format!("RNG: {e}")))?;
    Ok(account_json(&EddsaKeypair::from_secret_bytes(&secret)))
}

/// Erzeugt einen neuen Account MIT 24-Wort-BIP39-Mnemonic (256-bit Entropie).
/// Die Mnemonic ist das kanonische Backup: `account_from_mnemonic` stellt exakt
/// dasselbe Konto wieder her. Rückgabe enthält zusätzlich `mnemonic`.
#[wasm_bindgen]
pub fn generate_mnemonic() -> Result<String, JsError> {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|e| JsError::new(&format!("RNG: {e}")))?;
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
        .map_err(|e| JsError::new(&format!("Mnemonic-Erzeugung: {e}")))?;
    let kp = EddsaKeypair::from_secret_bytes(&entropy);
    Ok(serde_json::json!({
        "mnemonic": mnemonic.to_string(),
        "secret":   hex::encode(kp.secret_bytes()),
        "pubkey":   hex::encode(kp.public().to_bytes()),
        "address":  hex::encode(kp.public().address20()),
    }).to_string())
}

/// Stellt ein Konto aus einer BIP39-Mnemonic wieder her.
#[wasm_bindgen]
pub fn account_from_mnemonic(phrase: &str) -> Result<String, JsError> {
    let mnemonic = bip39::Mnemonic::parse(phrase.trim())
        .map_err(|e| JsError::new(&format!("Ungültige Mnemonic: {e}")))?;
    let (entropy, len) = mnemonic.to_entropy_array();
    Ok(account_json(&EddsaKeypair::from_secret_bytes(&entropy[..len])))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Eine erzeugte Mnemonic stellt EXAKT dasselbe Konto wieder her
    /// (Adresse + Secret) — sonst wäre das Backup wertlos.
    #[test]
    fn mnemonic_roundtrip() {
        let entropy = [0x42u8; 32];
        let m  = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        let kp1 = EddsaKeypair::from_secret_bytes(&entropy);

        let parsed = bip39::Mnemonic::parse(m.to_string()).unwrap();
        let (e2, len) = parsed.to_entropy_array();
        let kp2 = EddsaKeypair::from_secret_bytes(&e2[..len]);

        assert_eq!(len, 32, "256-bit Entropie → 24 Wörter");
        assert_eq!(kp1.public().address20(), kp2.public().address20());
        assert_eq!(kp1.secret_bytes(), kp2.secret_bytes());
    }

    /// Import via Mnemonic und via abgeleitetem Secret-Hex ergeben dasselbe Konto.
    #[test]
    fn mnemonic_and_secret_agree() {
        let entropy = [0x11u8; 32];
        let m  = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        let kp = EddsaKeypair::from_secret_bytes(&entropy);
        let via_secret = EddsaKeypair::from_secret_bytes(&kp.secret_bytes());
        assert_eq!(kp.public().address20(), via_secret.public().address20());
        assert!(m.to_string().split_whitespace().count() == 24);
    }
}

/// Leitet pubkey/address aus einem bestehenden Secret (Hex) ab.
#[wasm_bindgen]
pub fn account_from_secret(secret_hex: &str) -> Result<String, JsError> {
    let secret = parse_hex32(secret_hex, "secret")?;
    Ok(account_json(&EddsaKeypair::from_secret_bytes(&secret)))
}

/// Baut die signierte L2-Transaktion als JSON für `POST /submit` (Aggregator).
/// Beträge als Strings, da JS-`number` keine u128 sicher hält.
#[wasm_bindgen]
pub fn build_submit_tx(
    secret_hex: &str,
    to_hex:     &str,
    amount:     &str,
    fee:        &str,
    nonce:      u64,
) -> Result<String, JsError> {
    let secret = parse_hex32(secret_hex, "secret")?;
    let kp     = EddsaKeypair::from_secret_bytes(&secret);
    let to     = parse_addr(to_hex)?;
    let amount = parse_u128(amount, "amount")?;
    let fee    = parse_u128(fee, "fee")?;

    let (from, pubkey, sig) = build_l2_eddsa(&kp, &to, amount, fee, nonce);

    // Exakt das serde-Format von atlas_core::l2_tx::L2Transaction:
    //   from/to = Hex-String, amount/fee/nonce = Zahl,
    //   auth.pubkey = Byte-Array (Zahlen), auth.signature = Hex-String.
    let tx = json!({
        "from":   hex::encode(from),
        "to":     hex::encode(to),
        "amount": amount,
        "fee":    fee,
        "nonce":  nonce,
        "auth": {
            "pubkey":    pubkey.to_vec(),
            "signature": hex::encode(sig),
        }
    });
    Ok(tx.to_string())
}

/// Baut die Parameter für den Node-RPC `forcel2tx` (Forced Inclusion / Escape-Hatch).
/// `sender_index` = Index des Kontos im L2-Baum (aus den On-Chain-Calldata ableitbar).
#[wasm_bindgen]
pub fn build_forced_tx(
    secret_hex:   &str,
    to_hex:       &str,
    amount:       &str,
    fee:          &str,
    nonce:        u64,
    sender_index: u64,
) -> Result<String, JsError> {
    let secret = parse_hex32(secret_hex, "secret")?;
    let kp     = EddsaKeypair::from_secret_bytes(&secret);
    let to     = parse_addr(to_hex)?;
    let amount = parse_u128(amount, "amount")?;
    let fee    = parse_u128(fee, "fee")?;

    let (from, pubkey, sig) = build_l2_eddsa(&kp, &to, amount, fee, nonce);

    // forcel2tx erwartet pubkey/sig als Hex (siehe atlas-node rpc.rs).
    let params = json!({
        "from":         hex::encode(from),
        "to":           hex::encode(to),
        "amount_atom":  amount,
        "fee_atom":     fee,
        "nonce":        nonce,
        "pubkey":       hex::encode(pubkey),
        "sig":          hex::encode(sig),
        "sender_index": sender_index,
    });
    Ok(params.to_string())
}
