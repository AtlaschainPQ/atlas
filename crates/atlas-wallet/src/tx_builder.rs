//! Transaction Builder — erstellt und signiert Transfers (klassisch + Post-Quantum)

use atlas_core::amount::Amount;
use atlas_core::crypto::{Address, KeyPair};
use atlas_core::hash::Hash;
use atlas_core::pq_crypto::PqKeyPair;
use atlas_core::transaction::{Transaction, TxInput, TxOutput, TxType, Witness, OutputAddress};
use atlas_core::tx_stamp::TxStamp;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TxBuilderError {
    #[error("Insufficient funds: available {available}, required {required}")]
    InsufficientFunds { available: Amount, required: Amount },
    #[error("No UTXOs provided")]
    NoUtxos,
    #[error("Fee too low (min: {min})")]
    FeeTooLow { min: u128 },
    #[error("Stamp mining failed")]
    StampFailed,
    #[error("Signing failed: {0}")]
    SigningFailed(String),
}

/// Einfacher UTXO-Descriptor — kommt von RPC-Abfrage oder Wallet-Scan
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoInfo {
    pub txid:    String,
    pub index:   u32,
    pub value:   u128,
    pub address: String,
}

/// Erstellt eine signierte Transfer-Transaktion
pub fn build_transfer(
    utxos:      &[UtxoInfo],
    recipient:  Address,
    amount:     Amount,
    fee:        Amount,
    change_to:  Address,
    keypair:    &KeyPair,
) -> Result<Transaction, TxBuilderError> {
    if utxos.is_empty() {
        return Err(TxBuilderError::NoUtxos);
    }

    let total_available: u128 = utxos.iter().map(|u| u.value).sum();
    let total_needed = amount.as_atom().saturating_add(fee.as_atom());

    if total_available < total_needed {
        return Err(TxBuilderError::InsufficientFunds {
            available: Amount::from_atom(total_available),
            required:  Amount::from_atom(total_needed),
        });
    }

    // Inputs (unsigned — will be signed below via tx.sign())
    let inputs: Vec<TxInput> = utxos.iter()
        .map(|u| {
            let txid_bytes = hex::decode(&u.txid)
                .map_err(|e| TxBuilderError::SigningFailed(
                    format!("Invalid txid hex '{}': {}", &u.txid, e)
                ))?;
            if txid_bytes.len() != 32 {
                return Err(TxBuilderError::SigningFailed(
                    format!("txid must be 32 bytes, got {}", txid_bytes.len())
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&txid_bytes);
            Ok(TxInput {
                prev_txid:  Hash(arr),
                prev_index: u.index,
                witness:    Witness::zeroed(),
                sequence:   0,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Outputs
    let change = Amount::from_atom(total_available.saturating_sub(total_needed));
    let mut outputs = vec![
        TxOutput { value: amount, address: OutputAddress::Classic(recipient) },
    ];
    if change.as_atom() > 0 {
        outputs.push(TxOutput { value: change, address: OutputAddress::Classic(change_to) });
    }

    let mut tx = Transaction {
        version:   1,
        inputs,
        outputs,
        fee,
        timestamp: now_secs(),
        stamp:     None,
        tx_type:   TxType::Transfer,
    };

    // Stamp minen (Spam-Schutz)
    let txid  = tx.txid();
    let stamp = TxStamp::mine(&txid, 12).map_err(|_| TxBuilderError::StampFailed)?;
    tx.stamp  = Some(stamp);

    // Alle Inputs signieren (setzt Witness::Classic)
    tx.sign(keypair);

    Ok(tx)
}

/// Erstellt eine signierte Post-Quantum Transfer-Transaktion (ML-DSA-65)
pub fn build_transfer_quantum(
    utxos:      &[UtxoInfo],
    recipient:  impl Into<OutputAddress>,
    amount:     Amount,
    fee:        Amount,
    change_to:  impl Into<OutputAddress>,
    keypair:    &PqKeyPair,
) -> Result<Transaction, TxBuilderError> {
    if utxos.is_empty() {
        return Err(TxBuilderError::NoUtxos);
    }

    let recipient  = recipient.into();
    let change_to  = change_to.into();
    let total_available: u128 = utxos.iter().map(|u| u.value).sum();
    let total_needed = amount.as_atom().saturating_add(fee.as_atom());

    if total_available < total_needed {
        return Err(TxBuilderError::InsufficientFunds {
            available: Amount::from_atom(total_available),
            required:  Amount::from_atom(total_needed),
        });
    }

    let inputs: Vec<TxInput> = utxos.iter()
        .map(|u| {
            let txid_bytes = hex::decode(&u.txid)
                .map_err(|e| TxBuilderError::SigningFailed(
                    format!("Invalid txid hex '{}': {}", &u.txid, e)
                ))?;
            if txid_bytes.len() != 32 {
                return Err(TxBuilderError::SigningFailed(
                    format!("txid must be 32 bytes, got {}", txid_bytes.len())
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&txid_bytes);
            Ok(TxInput {
                prev_txid:  Hash(arr),
                prev_index: u.index,
                witness:    Witness::zeroed(),
                sequence:   0,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let change = Amount::from_atom(total_available.saturating_sub(total_needed));
    let mut outputs = vec![TxOutput { value: amount, address: recipient }];
    if change.as_atom() > 0 {
        outputs.push(TxOutput { value: change, address: change_to });
    }

    let mut tx = Transaction {
        version:   1,
        inputs,
        outputs,
        fee,
        timestamp: now_secs(),
        stamp:     None,
        tx_type:   TxType::Transfer,
    };

    let txid  = tx.txid();
    let stamp = TxStamp::mine(&txid, 12).map_err(|_| TxBuilderError::StampFailed)?;
    tx.stamp  = Some(stamp);

    // ML-DSA-65 Signatur
    tx.sign_quantum(keypair);

    Ok(tx)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
