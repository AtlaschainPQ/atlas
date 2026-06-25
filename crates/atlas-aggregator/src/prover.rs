//! ZK-Beweis-Generierung für Settlement-Batches (State-Transition, soundness-tragend).
//!
//! Wrapper um `atlas_zk::ZkBatchProver`. Der Aggregator lädt den State-Proving-Key
//! (`state_pk.bin`, ~122 MB) einmal beim Start und erzeugt dann für jeden Batch
//! einen Groth16-State-Transition-Beweis aus dem nativen `BatchWitness`.
//!
//! Public Inputs des Beweises: `[pre_root, post_root, total_fees, batch_commitment]`
//! — ALLE aus On-Chain- bzw. aus dem öffentlichen L2-Zustand ableitbar, nichts
//! Prover-Gewähltes (im Gegensatz zum alten Batch-Commitment-Circuit).
//!
//! Im Test-Modus (`test_mode=true`) wird ein Dummy-Proof erzeugt (~0 ms) statt
//! eines echten Groth16-Beweises. Passend zu `node.test_mode=true`, das die
//! Verifikation überspringt.

use atlas_core::hash::Hash;
use atlas_zk::transition::BatchWitness;
use atlas_zk::ZkBatchProver;
use tracing::info;

pub struct AggregatorProver {
    prover:    Option<ZkBatchProver>,
    test_mode: bool,
}

impl AggregatorProver {
    /// Lädt den State-Proving-Key aus einer Datei (`keys/state_pk.bin`, ~122 MB).
    pub fn from_state_file(path: &str) -> anyhow::Result<Self> {
        info!("Loading ZK state proving key from {}", path);
        let prover = ZkBatchProver::from_state_file(path)?;
        info!("ZK state proving key loaded");
        Ok(AggregatorProver { prover: Some(prover), test_mode: false })
    }

    /// Test-Modus: überspringt echten Groth16-Proof, gibt Dummy-Proof zurück (~0 ms).
    /// Nur verwenden wenn atlas-node ebenfalls mit `test_mode=true` läuft.
    pub fn test_mode() -> Self {
        info!("ZK Prover: TEST MODE aktiv — Dummy-Proof (Groth16 übersprungen)");
        AggregatorProver { prover: None, test_mode: true }
    }

    /// Erzeugt einen State-Transition-Beweis aus dem nativen `BatchWitness`.
    ///
    /// Gibt `(proof_bytes, post_root, batch_commitment)` zurück. Alle drei werden
    /// (zusammen mit `pre_root` und `total_fees`) an die `submitbatch`-RPC übergeben.
    ///
    /// `expected_post_root` ist die vom Aggregator-`L2State` nach `apply()`
    /// errechnete Wurzel; im Realmodus wird sie gegen die vom Beweis erzeugte
    /// Wurzel geprüft (Konsistenz-Sanity).
    pub fn prove_state(
        &self,
        bw:                 &BatchWitness,
        expected_post_root: [u8; 32],
        batch_merkle:       &Hash,
    ) -> anyhow::Result<(Vec<u8>, [u8; 32], [u8; 32])> {
        if self.test_mode {
            // Dummy-Proof: der Node überspringt die Verifikation im test_mode.
            // post_root kommt aus dem nativ berechneten L2-Zustand; als
            // batch_commitment dient ein deterministischer Platzhalter.
            let dummy_commitment: [u8; 32] = *Hash::sha256(batch_merkle.as_bytes()).as_bytes();
            let proof_bytes = vec![0u8; 128];
            return Ok((proof_bytes, expected_post_root, dummy_commitment));
        }

        let prover = self.prover.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Prover ohne State-Key (kein test_mode)"))?;

        info!("Generating ZK state proof ({} TXs in witness)", bw.txs.len());
        let (proof_bytes, post_root, batch_commitment) = prover.prove_state(bw)
            .map_err(|e| anyhow::anyhow!("ZK state proof generation failed: {}", e))?;

        if post_root != expected_post_root {
            return Err(anyhow::anyhow!(
                "post_root mismatch: Beweis={} L2State={}",
                hex::encode(post_root),
                hex::encode(expected_post_root),
            ));
        }

        info!("ZK state proof generated ({} bytes)", proof_bytes.len());
        Ok((proof_bytes, post_root, batch_commitment))
    }
}
