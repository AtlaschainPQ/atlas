//! Groth16 Schlüsselgenerierung für das BatchProofCircuit.
//!
//! WARNUNG: Der deterministische Setup (from_seed) ist NICHT sicher für Mainnet.
//! Für Mainnet ist eine MPC-Zeremonie erforderlich, bei der der "toxic waste"
//! (die geheimen Zufallszahlen) von mehreren unabhängigen Parteien beigetragen
//! und danach sicher gelöscht wird.
//!
//! Für Devnet/Testnet: deterministischer Setup mit bekanntem Seed — akzeptabel,
//! da kein echtes Geld im Spiel ist.

use ark_bn254::Bn254;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;
use tracing::info;

use crate::circuit::BatchProofCircuit;
use crate::state_circuit::StateTransitionCircuit;

/// Seed für den deterministischen Devnet-Setup.
/// ERSETZEN durch echtes MPC-Ergebnis für Mainnet.
const DEVNET_SETUP_SEED: [u8; 32] = *b"ATLAS-ZK-DEVNET-SETUP-SEED-V1!!!";

/// Generiert PK/VK für den soundness-tragenden `StateTransitionCircuit` einer
/// festen Slotzahl. Die Slotzahl ist Teil der Circuit-FORM → PK/VK gelten nur
/// für genau diese `batch_size`.
pub fn generate_keys_state(batch_size: usize) -> anyhow::Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    info!("Generating state-transition ZK keys (batch_size={}, devnet)...", batch_size);
    let mut rng = ChaCha20Rng::from_seed(DEVNET_SETUP_SEED);
    let (pk, vk) = ark_groth16::Groth16::<Bn254>::circuit_specific_setup(
        StateTransitionCircuit::dummy(batch_size),
        &mut rng,
    ).map_err(|e| anyhow::anyhow!("Groth16 state setup failed: {}", e))?;
    info!("State-transition ZK key generation complete");
    Ok((pk, vk))
}

/// Generiert Proving- und Verifying-Key deterministisch.
/// Dauert ca. 0.5–2 Sekunden beim ersten Aufruf.
pub fn generate_keys_devnet() -> anyhow::Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    info!("Generating ZK proving/verifying keys (devnet setup, ~1s)...");
    let mut rng = ChaCha20Rng::from_seed(DEVNET_SETUP_SEED);
    let (pk, vk) = ark_groth16::Groth16::<Bn254>::circuit_specific_setup(
        BatchProofCircuit::dummy(),
        &mut rng,
    ).map_err(|e| anyhow::anyhow!("Groth16 setup failed: {}", e))?;
    info!("ZK key generation complete");
    Ok((pk, vk))
}

/// Serialisiert den Verifying-Key (klein, ~1 KB, auf allen Nodes gleich).
pub fn vk_to_bytes(vk: &VerifyingKey<Bn254>) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    vk.serialize_compressed(&mut out)
        .map_err(|e| anyhow::anyhow!("VK serialization failed: {}", e))?;
    Ok(out)
}

/// Deserialisiert den Verifying-Key.
pub fn vk_from_bytes(bytes: &[u8]) -> anyhow::Result<VerifyingKey<Bn254>> {
    VerifyingKey::<Bn254>::deserialize_compressed(bytes)
        .map_err(|e| anyhow::anyhow!("VK deserialization failed: {}", e))
}

/// Serialisiert den Proving-Key (groß, nur für Aggregatoren).
pub fn pk_to_bytes(pk: &ProvingKey<Bn254>) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    pk.serialize_compressed(&mut out)
        .map_err(|e| anyhow::anyhow!("PK serialization failed: {}", e))?;
    Ok(out)
}

/// Deserialisiert den Proving-Key.
pub fn pk_from_bytes(bytes: &[u8]) -> anyhow::Result<ProvingKey<Bn254>> {
    ProvingKey::<Bn254>::deserialize_compressed(bytes)
        .map_err(|e| anyhow::anyhow!("PK deserialization failed: {}", e))
}

/// Serialisiert den Proving-Key UNKOMPRIMIERT (für den großen State-PK).
///
/// Komprimierte PK-Deserialisierung muss pro Kurvenpunkt eine Quadratwurzel zur
/// Punktdekompression rechnen — bei Millionen G1/G2-Punkten dauert das Laden
/// Minuten. Unkomprimiert ist die Datei ~2× so groß, lädt aber in Sekunden.
/// Der PK ist ÖFFENTLICH (kein Geheimnis) — Soundness hängt allein am VK —,
/// daher ist das Weglassen der Subgroup-Checks beim Laden (`_unchecked`) sicher.
pub fn pk_to_bytes_fast(pk: &ProvingKey<Bn254>) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    pk.serialize_uncompressed(&mut out)
        .map_err(|e| anyhow::anyhow!("PK uncompressed serialization failed: {}", e))?;
    Ok(out)
}

/// Deserialisiert den unkomprimierten Proving-Key ohne Subgroup-Checks (schnell).
/// Siehe `pk_to_bytes_fast` zur Sicherheitsbegründung.
pub fn pk_from_bytes_fast(bytes: &[u8]) -> anyhow::Result<ProvingKey<Bn254>> {
    ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(bytes)
        .map_err(|e| anyhow::anyhow!("PK uncompressed deserialization failed: {}", e))
}
