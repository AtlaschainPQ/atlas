//! Einmaliger Trusted-Setup für den soundness-tragenden `StateTransitionCircuit`.
//!
//! Erzeugt für `atlas_zk::L2_BATCH_SIZE` Slots:
//!   - keys/state_vk.bin  → klein (~KB), wird in lib.rs via include_bytes! eingebettet
//!   - keys/state_pk.bin  → groß (~124 MB bei batch_size=16), NUR für Aggregatoren
//!
//! Verwendung:
//!   cargo run -p atlas-zk --release --bin zk_setup_state
//!
//! SICHERHEIT: echter OsRng. Der "toxic waste" ist danach unzugänglich. Für ein
//! echtes Mainnet ist trotzdem eine MPC-Zeremonie nötig (ein einzelner Setup-Rechner
//! könnte den toxic waste theoretisch zurückhalten) — siehe zk_ceremony.rs.

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use rand::rngs::OsRng;
use std::fs;
use std::time::Instant;

use atlas_zk::state_circuit::StateTransitionCircuit;
use atlas_zk::L2_BATCH_SIZE;

fn main() -> anyhow::Result<()> {
    println!("=== ATLAS State-Transition ZK Setup (OsRng) ===");
    println!("batch_size = {}", L2_BATCH_SIZE);
    let t0 = Instant::now();

    let mut rng = OsRng;
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        StateTransitionCircuit::dummy(L2_BATCH_SIZE),
        &mut rng,
    ).map_err(|e| anyhow::anyhow!("Groth16 state setup failed: {}", e))?;
    println!("Keys generated in {:.1}s. Serializing...", t0.elapsed().as_secs_f64());

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| anyhow::anyhow!("VK serialization failed: {}", e))?;
    // PK unkomprimiert (schnelles Laden im Aggregator — siehe setup::pk_to_bytes_fast).
    let pk_bytes = atlas_zk::setup::pk_to_bytes_fast(&pk)?;

    let keys_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/keys");
    fs::create_dir_all(keys_dir)?;
    let vk_path = format!("{}/state_vk.bin", keys_dir);
    let pk_path = format!("{}/state_pk.bin", keys_dir);
    fs::write(&vk_path, &vk_bytes)?;
    fs::write(&pk_path, &pk_bytes)?;

    println!();
    println!("✓ VK: {} ({} bytes)", vk_path, vk_bytes.len());
    println!("✓ PK: {} ({:.1} MB)", pk_path, pk_bytes.len() as f64 / 1_048_576.0);
    println!();
    println!("Nächste Schritte:");
    println!("  1. state_vk.bin ins Repo (wird via include_bytes! eingebettet)");
    println!("  2. state_pk.bin auf Aggregator-Hosts (NICHT ins Binary, NICHT committen)");
    Ok(())
}
