//! Einmaliger ZK-Setup mit echtem OsRng.
//!
//! Erzeugt Proving-Key (pk.bin) und Verifying-Key (vk.bin) mit echter
//! Zufälligkeit aus dem Betriebssystem. Nach dem Ausführen:
//!   - keys/vk.bin  → wird in lib.rs via include_bytes! eingebettet
//!   - keys/pk.bin  → für Aggregatoren (groß, nicht ins Binary)
//!
//! Verwendung:
//!   cargo run -p atlas-zk --bin zk_setup
//!
//! SICHERHEITSHINWEIS: Der genannte "toxic waste" (interne Zufallszahlen) ist
//! nach dem Setup nicht mehr zugänglich. Für Mainnet: MPC-Zeremonie.

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use rand::rngs::OsRng;
use std::fs;

use atlas_zk::circuit::BatchProofCircuit;

fn main() -> anyhow::Result<()> {
    println!("=== ATLAS ZK Setup (OsRng) ===");
    println!("Generating Groth16 keys for BN254...");
    println!("(This may take 1–5 seconds)");

    let mut rng = OsRng;

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        BatchProofCircuit::dummy(),
        &mut rng,
    ).map_err(|e| anyhow::anyhow!("Groth16 setup failed: {}", e))?;

    println!("Keys generated. Serializing...");

    // VK serialisieren (klein, ~500 Bytes komprimiert)
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| anyhow::anyhow!("VK serialization failed: {}", e))?;

    // PK serialisieren (groß, ~100–200 KB)
    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|e| anyhow::anyhow!("PK serialization failed: {}", e))?;

    // Ins keys/-Verzeichnis speichern (relativ zum Crate-Root)
    let keys_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/keys");
    fs::create_dir_all(keys_dir)?;

    let vk_path = format!("{}/vk.bin", keys_dir);
    let pk_path = format!("{}/pk.bin", keys_dir);

    fs::write(&vk_path, &vk_bytes)?;
    fs::write(&pk_path, &pk_bytes)?;

    println!();
    println!("✓ VK written: {} ({} bytes)", vk_path, vk_bytes.len());
    println!("✓ PK written: {} ({} bytes)", pk_path, pk_bytes.len());
    println!();
    println!("Next steps:");
    println!("  1. The VK is already embedded via include_bytes! in lib.rs");
    println!("  2. Commit keys/vk.bin to the repository");
    println!("  3. Keep keys/pk.bin for aggregators (do NOT commit unless intentional)");

    Ok(())
}
