//! ZK-Proof Verifikation für ATLAS Settlement-Batches (Groth16/BN254)
//!
//! VK ist im Binary hardcodiert (keys/vk.bin, mit OsRng generiert).
//! PK liegt auf Aggregator-Nodes (keys/pk.bin).

use atlas_core::hash::Hash;
use atlas_core::amount::Amount;
use atlas_core::crypto::Address;
use atlas_zk::ZkBatchVerifier;
use std::sync::OnceLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

/// Gecachter Verifier (einmalig initialisiert, nutzt hardcodierten VK)
static ZK_VERIFIER: OnceLock<ZkBatchVerifier> = OnceLock::new();

/// Gecachter State-Transition-Verifier (soundness-tragender Circuit, hardcodierter State-VK).
static ZK_STATE_VERIFIER: OnceLock<ZkBatchVerifier> = OnceLock::new();

/// Initialisiert die ZK-Verifier beim Node-Start (beide hardcodierten VKs).
/// Verwendet die ins Binary eingebetteten Verifying-Keys (kein Schlüssel-Aufwand).
pub fn init_zk_verifier() -> anyhow::Result<()> {
    let verifier = ZkBatchVerifier::from_hardcoded_vk()?;
    ZK_VERIFIER.set(verifier)
        .map_err(|_| anyhow::anyhow!("ZK verifier already initialized"))?;

    let state_verifier = ZkBatchVerifier::from_hardcoded_state_vk()?;
    ZK_STATE_VERIFIER.set(state_verifier)
        .map_err(|_| anyhow::anyhow!("ZK state verifier already initialized"))?;

    info!("ZK verifiers initialized (Groth16/BN254: legacy VK + state-transition VK)");
    Ok(())
}

// ── ZkProof / ZkPublicInputs (Protokoll-Typen) ───────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkProof {
    pub batch_id:      Hash,
    pub aggregator:    Address,
    pub tx_count:      u32,
    pub proof_bytes:   Vec<u8>,
    pub public_inputs: ZkPublicInputs,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkPublicInputs {
    pub pre_state_root:  Hash,
    pub post_state_root: Hash,
    pub total_fees:      Amount,
    pub batch_merkle:    Hash,
}

// ── Fehlertypen ───────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum ZkError {
    #[error("ZK proof verification failed: {0}")]
    VerificationFailed(String),
    #[error("ZK verifier not initialized — call init_zk_verifier() at startup")]
    NotInitialized,
    #[error("Empty proof bytes")]
    EmptyProof,
}

// ── ZkVerifier ────────────────────────────────────────────────────────────────

pub struct ZkVerifier {
    test_mode: bool,
}

impl ZkVerifier {
    pub fn new(test_mode: bool) -> Self {
        ZkVerifier { test_mode }
    }

    /// Verifiziert einen einzelnen ZK-Proof.
    pub fn verify(&self, proof: &ZkProof) -> Result<(), ZkError> {
        if self.test_mode {
            return Ok(());
        }
        if proof.proof_bytes.is_empty() {
            return Err(ZkError::EmptyProof);
        }
        let verifier = ZK_VERIFIER.get().ok_or(ZkError::NotInitialized)?;
        verifier.verify(
            &proof.proof_bytes,
            proof.public_inputs.pre_state_root.as_bytes(),
            proof.public_inputs.batch_merkle.as_bytes(),
            proof.public_inputs.total_fees.as_atom(),
        ).map_err(|e| ZkError::VerificationFailed(e.to_string()))
    }

    /// Verifiziert den EINEN aggregierten Block-Proof gegen die on-chain Batch-Menge.
    ///
    /// `batches` = (batch_id, bid_amount_atom) in Block-Reihenfolge, aus den
    /// SettlementBid-TXs des Blocks extrahiert. `pre_root` = block.header.prev_hash.
    /// Der Verifier rechnet den batches_digest unabhängig nach → kein Vertrauen
    /// in den Block-Producer nötig; die Kette ist von Genesis re-verifizierbar.
    pub fn verify_block_agg(
        &self,
        agg_proof: &[u8],
        pre_root:  &Hash,
        batches:   &[([u8; 32], u128)],
    ) -> Result<(), ZkError> {
        if self.test_mode || batches.is_empty() {
            return Ok(());
        }
        if agg_proof.is_empty() {
            return Err(ZkError::EmptyProof);
        }
        let verifier = ZK_VERIFIER.get().ok_or(ZkError::NotInitialized)?;
        verifier.verify_block(agg_proof, pre_root.as_bytes(), batches)
            .map_err(|e| {
                warn!("Aggregated block proof verification failed: {}", e);
                ZkError::VerificationFailed(e.to_string())
            })
    }

    /// Verifiziert den soundness-tragenden State-Transition-Beweis eines einzelnen
    /// SettlementBid. ALLE Public Inputs (`pre_root`, `post_root`, `total_fees`,
    /// `batch_commitment`) stammen aus der On-Chain-TX — nichts Prover-Gewähltes.
    /// Der Beweis bezeugt, dass `pre_root` durch eine gültige L2-TX-Folge (jede mit
    /// Merkle-Inklusion, Balance-/Nonce-Prüfung) deterministisch zu `post_root` wird.
    pub fn verify_state_bid(
        &self,
        proof_bytes:      &[u8],
        pre_root:         &[u8; 32],
        post_root:        &[u8; 32],
        total_fees:       u128,
        batch_commitment: &[u8; 32],
    ) -> Result<(), ZkError> {
        if self.test_mode {
            return Ok(());
        }
        if proof_bytes.is_empty() {
            return Err(ZkError::EmptyProof);
        }
        let verifier = ZK_STATE_VERIFIER.get().ok_or(ZkError::NotInitialized)?;
        verifier.verify_state(proof_bytes, pre_root, post_root, total_fees, batch_commitment)
            .map_err(|e| {
                warn!("State-transition proof verification failed: {}", e);
                ZkError::VerificationFailed(e.to_string())
            })
    }
}
