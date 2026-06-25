//! atlas-zk: Groth16 ZK-Beweis-System für ATLAS Settlement-Batches
//!
//! Implementiert ein Batch-Commitment-Proof-Schema:
//!   - Aggregatoren beweisen Kenntnis eines Nonce der den Batch mit dem
//!     pre/post-State deterministisch verknüpft (MiMC-7 Sponge)
//!   - Verifikation: O(1) via Groth16 auf BN254 (~1ms)
//!   - Circuit: ~110×4 = 440 Multiplikations-Constraints
//!
//! Setup: einmalig mit OsRng generiert (zk_setup binary), VK hardcodiert.
//! PK (keys/pk.bin) liegt auf Aggregator-Nodes.

pub mod account;
pub mod circuit;
pub mod constants;
pub mod eddsa;
pub mod eddsa_gadget;
pub mod l2_state;
pub mod merkle;
pub mod mpc;
pub mod native;
pub mod poseidon;
pub mod proof;
pub mod setup;
pub mod state_circuit;
pub mod transition;

pub use proof::{
    ProofError,
    fr_to_bytes32, hash_to_fr, u128_to_fr,
    prepare_vk, prove, verify,
    compute_batches_digest,
};
pub use setup::{
    generate_keys_devnet, generate_keys_state,
    vk_to_bytes, vk_from_bytes,
    pk_to_bytes, pk_from_bytes,
};

/// Kanonische L2-Batch-Größe (Anzahl TX-Slots pro State-Transition-Beweis).
/// Teil der Circuit-FORM → PK/VK gelten nur für genau diese Größe. Proving-Zeit
/// und PK-Größe skalieren linear (~1,2 s und ~7,8 MB pro Slot, CPU-Groth16).
pub const L2_BATCH_SIZE: usize = 16;

// ── Hardcodierter Verifying-Key (mit OsRng generiert, in Binary eingebettet) ──

/// VK-Bytes, generiert via `cargo run -p atlas-zk --bin zk_setup` (OsRng).
/// Alle Full-Nodes verwenden denselben VK — kein Startup-Overhead.
const HARDCODED_VK_BYTES: &[u8] = include_bytes!("../keys/vk.bin");

/// PK-Bytes, im Binary eingebettet (~348 KB). Proving-Keys sind NICHT geheim
/// (nur der Setup-„toxic waste" ist es) → Miner-Nodes können damit den einen
/// aggregierten Block-Proof erzeugen, ohne externe Schlüsseldatei.
const BUNDLED_PK_BYTES: &[u8] = include_bytes!("../keys/pk.bin");

/// VK-Bytes des soundness-tragenden `StateTransitionCircuit` (batch_size = `L2_BATCH_SIZE`),
/// generiert via `cargo run -p atlas-zk --release --bin zk_setup_state` (OsRng).
/// Klein (~392 B) → in jedes Node-Binary eingebettet. Der zugehörige PK
/// (`keys/state_pk.bin`, ~122 MB) liegt NUR auf Aggregator-Hosts.
const HARDCODED_STATE_VK_BYTES: &[u8] = include_bytes!("../keys/state_vk.bin");

// ── Hochrangige Wrapper für atlas-node (keine ark-Typen nach außen) ───────────

use ark_bn254::Bn254;
use ark_groth16::{PreparedVerifyingKey, ProvingKey};

/// Hochrangiger ZK-Verifier — kapselt ark-Typen.
pub struct ZkBatchVerifier {
    pvk: PreparedVerifyingKey<Bn254>,
}

impl ZkBatchVerifier {
    pub fn new(pvk: PreparedVerifyingKey<Bn254>) -> Self {
        ZkBatchVerifier { pvk }
    }

    /// Erstellt einen Verifier aus dem hardcodierten VK (kein Schlüssel-Aufwand).
    pub fn from_hardcoded_vk() -> anyhow::Result<Self> {
        let vk = vk_from_bytes(HARDCODED_VK_BYTES)?;
        let pvk = prepare_vk(&vk)
            .map_err(|e| anyhow::anyhow!("VK preparation failed: {}", e))?;
        Ok(ZkBatchVerifier { pvk })
    }

    /// Erstellt einen Verifier aus dem hardcodierten State-VK (soundness-tragender Circuit).
    pub fn from_hardcoded_state_vk() -> anyhow::Result<Self> {
        let vk = vk_from_bytes(HARDCODED_STATE_VK_BYTES)?;
        let pvk = prepare_vk(&vk)
            .map_err(|e| anyhow::anyhow!("State-VK preparation failed: {}", e))?;
        Ok(ZkBatchVerifier { pvk })
    }

    /// Verifiziert einen serialisierten Batch-Commitment-Proof.
    pub fn verify(
        &self,
        proof_bytes:  &[u8],
        pre_root:     &[u8; 32],
        batch_merkle: &[u8; 32],
        total_fees:   u128,
    ) -> Result<(), ProofError> {
        proof::verify(&self.pvk, proof_bytes, pre_root, batch_merkle, total_fees)
    }

    /// Verifiziert einen State-Transition-Beweis (soundness-tragend).
    /// ALLE Public Inputs stammen aus On-Chain-Daten — nichts Prover-Gewähltes.
    pub fn verify_state(
        &self,
        proof_bytes:      &[u8],
        pre_root:         &[u8; 32],
        post_root:        &[u8; 32],
        total_fees:       u128,
        batch_commitment: &[u8; 32],
    ) -> Result<(), ProofError> {
        proof::verify_state(&self.pvk, proof_bytes, pre_root, post_root, total_fees, batch_commitment)
    }

    /// Verifiziert den EINEN aggregierten Block-Proof gegen die on-chain Batch-Menge.
    /// `batches` = (batch_id, bid_amount_atom) in Block-Reihenfolge.
    /// Der Digest wird unabhängig nachgerechnet — kein Vertrauen in den Producer nötig.
    pub fn verify_block(
        &self,
        proof_bytes: &[u8],
        pre_root:    &[u8; 32],
        batches:     &[([u8; 32], u128)],
    ) -> Result<(), ProofError> {
        let digest = proof::compute_batches_digest(pre_root, batches);
        let total_fees = batches.iter().map(|(_, f)| *f).fold(0u128, |a, b| a.saturating_add(b));
        proof::verify(&self.pvk, proof_bytes, pre_root, &digest, total_fees)
    }
}

/// Hochrangiger ZK-Prover — kapselt ark-Typen.
pub struct ZkBatchProver {
    pk: ProvingKey<Bn254>,
}

impl ZkBatchProver {
    pub fn new(pk: ProvingKey<Bn254>) -> Self {
        ZkBatchProver { pk }
    }

    /// Lädt den PK aus einer Datei (für Aggregatoren).
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("Failed to read PK file '{}': {}", path, e))?;
        let pk = pk_from_bytes(&bytes)?;
        Ok(ZkBatchProver { pk })
    }

    /// Lädt den ins Binary eingebetteten PK (für Miner-Nodes, kein externer Pfad).
    pub fn from_bundled() -> anyhow::Result<Self> {
        let pk = pk_from_bytes(BUNDLED_PK_BYTES)?;
        Ok(ZkBatchProver { pk })
    }

    /// Lädt den State-PK aus einer Datei (`keys/state_pk.bin`, unkomprimiert, nur
    /// Aggregatoren). Nutzt den schnellen unkomprimierten Pfad (`pk_from_bytes_fast`)
    /// — komprimiertes Laden würde Minuten dauern (Punktdekompression).
    pub fn from_state_file(path: &str) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("Failed to read state-PK file '{}': {}", path, e))?;
        let pk = setup::pk_from_bytes_fast(&bytes)?;
        Ok(ZkBatchProver { pk })
    }

    /// Erzeugt einen State-Transition-Beweis aus einem nativen `BatchWitness`.
    /// Gibt (proof_bytes, post_root_bytes, batch_commitment_bytes) zurück.
    pub fn prove_state(
        &self,
        bw: &transition::BatchWitness,
    ) -> Result<(Vec<u8>, [u8; 32], [u8; 32]), ProofError> {
        proof::prove_state(&self.pk, bw, L2_BATCH_SIZE)
    }

    /// Erzeugt einen Batch-Commitment-Proof.
    /// Gibt (proof_bytes, post_commitment_bytes) zurück.
    pub fn prove(
        &self,
        pre_root:     &[u8; 32],
        batch_merkle: &[u8; 32],
        total_fees:   u128,
    ) -> Result<(Vec<u8>, [u8; 32]), ProofError> {
        proof::prove(&self.pk, pre_root, batch_merkle, total_fees)
    }

    /// Erzeugt EINEN aggregierten Proof für ALLE Batches eines Blocks.
    /// `batches` = (batch_id, bid_amount_atom) in Block-Reihenfolge.
    /// Gibt (proof_bytes, post_commitment) zurück.
    pub fn prove_block(
        &self,
        pre_root: &[u8; 32],
        batches:  &[([u8; 32], u128)],
    ) -> Result<(Vec<u8>, [u8; 32]), ProofError> {
        let digest = proof::compute_batches_digest(pre_root, batches);
        let total_fees = batches.iter().map(|(_, f)| *f).fold(0u128, |a, b| a.saturating_add(b));
        proof::prove(&self.pk, pre_root, &digest, total_fees)
    }
}

/// Die L2-State-Root eines vollständig leeren Account-Baums (Tiefe `merkle::DEPTH`).
/// Dies ist der kanonische Genesis-Startwert der L2-State-Root-Kette: der erste
/// SettlementBid muss mit genau dieser `pre_root` anschließen.
pub fn empty_l2_state_root() -> [u8; 32] {
    let tree = account::AccountTree::new();
    proof::fr_to_bytes32(tree.root())
}

/// Kanonische geförderte Genesis-L2-State-Root (Dev-/Testnet-Allokation).
/// Node (`atlas-core`-Konstante) und Aggregator MÜSSEN exakt diesen Wert als
/// Start der L2-State-Root-Kette verwenden, damit der erste SettlementBid
/// anschließt. Siehe `l2_state::genesis_allocation`.
pub use l2_state::{genesis_allocation, genesis_l2_state_root, GenesisAlloc};

/// Erstellt Verifier aus hardcodiertem VK (kein Key-Generation-Overhead).
/// Für Aggregatoren: PK separat via ZkBatchProver::from_file() laden.
pub fn create_zk_verifier_and_prover() -> anyhow::Result<(ZkBatchVerifier, ZkBatchProver)> {
    // Verifier nutzt hardcodierten VK
    let verifier = ZkBatchVerifier::from_hardcoded_vk()?;
    // Prover benötigt PK — für Devnet aus Datei, sonst Fehler
    let pk_path = concat!(env!("CARGO_MANIFEST_DIR"), "/keys/pk.bin");
    let prover = ZkBatchProver::from_file(pk_path)?;
    Ok((verifier, prover))
}

#[cfg(test)]
mod genesis_root_test {
    #[test]
    fn print_empty_l2_root() {
        let r = super::empty_l2_state_root();
        println!("EMPTY_L2_ROOT_HEX={}", hex::encode(r));
    }
}
