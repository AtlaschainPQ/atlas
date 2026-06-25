//! ATLAS ZK Trusted-Setup Zeremonie — Entropie-Sammlung + transparentes Setup.
//!
//! ╔═══════════════════════ EHRLICHE SICHERHEITSAUSSAGE ═══════════════════════╗
//! ║ Dies ist KEINE echte MPC-Phase-2-Zeremonie. Eine echte MPC transformiert  ║
//! ║ den Proving-Key sequenziell bei jedem Teilnehmer (pk → pk^r, r wird       ║
//! ║ verworfen), sodass der toxic waste τ verteilt entsteht und KEIN einzelner ║
//! ║ Rechner ihn je kennt. Dieses Tool sammelt stattdessen Entropie-Beiträge   ║
//! ║ und führt das Setup EINMAL auf der Finalize-Maschine aus:                 ║
//! ║   → Die Finalize-Maschine kennt den Seed im Moment der Erzeugung.         ║
//! ║   → Vertrauensannahme: Finalize-Maschine ist ehrlich UND kompromittfrei.  ║
//! ║ Die Beiträge machen den Prozess öffentlich nachvollziehbar (wer, wann,    ║
//! ║ Commitments), ersetzen aber die MPC NICHT. Für das echte Mainnet MUSS     ║
//! ║ eine auditierte MPC-Phase-2 durchgeführt werden (z. B. Adaption von       ║
//! ║ snarkjs/phase2-bn254 auf diesen Circuit) — siehe MAINNET-READINESS.md.    ║
//! ╚════════════════════════════════════════════════════════════════════════════╝
//!
//! Der Finalize-Seed wird aus `accumulated_hash` UND frischer, NIE persistierter
//! OsRng-Entropie der Finalize-Maschine gemischt. Die ceremony.json allein
//! erlaubt damit KEINE Rekonstruktion des Seeds (frühere Versionen dieses Tools
//! seedeten ausschließlich aus der Datei — das wäre öffentlich fälschbar gewesen).
//!
//! Erzeugt BEIDE Schlüsselsätze:
//!   - keys/state_vk.bin / keys/state_pk.bin  (StateTransitionCircuit — soundness-tragend!)
//!   - keys/vk.bin       / keys/pk.bin        (Legacy-BatchProofCircuit)
//!
//! Befehle:
//!   init       <ceremony.json>                 Erste Contribution (von Projektteam)
//!   contribute <ceremony.json> <dein-name>     Eigene Entropie hinzufügen
//!   finalize   <ceremony.json>                 Alle keys/*.bin erzeugen
//!   verify     <ceremony.json>                 Beitragskette anzeigen

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use rand::rngs::OsRng;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use atlas_zk::circuit::BatchProofCircuit;
use atlas_zk::state_circuit::StateTransitionCircuit;

// ── Datenstrukturen ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct Contribution {
    /// Laufende Nummer
    index:               u32,
    /// Name des Teilnehmers
    contributor:         String,
    /// Unix-Timestamp
    timestamp:           u64,
    /// SHA256(entropy_bytes) — beweist Commitment zur Entropie
    entropy_commitment:  String,
    /// SHA256(prev_accumulated || entropy_bytes) — neuer akkumulierter Hash
    accumulated_hash:    String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CeremonyState {
    /// Version der Zeremonie-Datei
    version:          u32,
    /// Name des verwendeten Circuits
    circuit:          String,
    /// Aktueller akkumulierter Hash (Hex)
    accumulated_hash: String,
    /// Alle Beiträge
    contributions:    Vec<Contribution>,
}

// ── Hilfsfunktionen ───────────────────────────────────────────────────────────

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_state(path: &str) -> anyhow::Result<CeremonyState> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read ceremony file '{}'", path))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Invalid ceremony file '{}'", path))
}

fn save_state(state: &CeremonyState, path: &str) -> anyhow::Result<()> {
    let content = serde_json::to_string_pretty(state)?;
    std::fs::write(path, content)
        .with_context(|| format!("Cannot write ceremony file '{}'", path))
}

/// Erzeugt 64 zufällige Bytes via OsRng und gibt sie zurück.
fn generate_entropy() -> [u8; 64] {
    let mut entropy = [0u8; 64];
    OsRng.fill_bytes(&mut entropy);
    entropy
}

/// Berechnet neuen akkumulierten Hash: SHA256(prev_hash_bytes || entropy_bytes)
fn accumulate(prev_hex: &str, entropy: &[u8]) -> anyhow::Result<String> {
    let prev = hex::decode(prev_hex)
        .with_context(|| format!("Invalid hex in accumulated_hash: {}", prev_hex))?;
    let mut h = Sha256::new();
    h.update(&prev);
    h.update(entropy);
    Ok(hex::encode(h.finalize()))
}

// ── Befehle ───────────────────────────────────────────────────────────────────

fn cmd_init(path: &str) -> anyhow::Result<()> {
    if std::path::Path::new(path).exists() {
        anyhow::bail!(
            "Ceremony file '{}' already exists. Delete it to start fresh.",
            path
        );
    }

    println!("=== ATLAS ZK Ceremony — INIT ===");
    println!("Generating initial entropy via OsRng...");

    let entropy  = generate_entropy();
    let entropy_commitment = hex::encode(Sha256::digest(entropy));
    // Erster akkumulierter Hash = SHA256(entropy) — kein Vorgänger
    let accumulated_hash   = hex::encode(Sha256::digest(entropy));

    let state = CeremonyState {
        version:          1,
        circuit:          "atlas-batch-proof-v1".to_string(),
        accumulated_hash: accumulated_hash.clone(),
        contributions:    vec![Contribution {
            index:              0,
            contributor:        "genesis".to_string(),
            timestamp:          now_unix(),
            entropy_commitment,
            accumulated_hash,
        }],
    };

    save_state(&state, path)?;

    println!("✓ Created '{}'", path);
    println!();
    println!("Next: send the file to participants and have each run:");
    println!("  cargo run -p atlas-zk --bin zk_ceremony -- contribute {} <name>", path);
    Ok(())
}

fn cmd_contribute(path: &str, name: &str) -> anyhow::Result<()> {
    let mut state = load_state(path)?;

    println!("=== ATLAS ZK Ceremony — CONTRIBUTE ===");
    println!("Participant: {}", name);
    println!("Previous contributions: {}", state.contributions.len());
    println!("Current hash: {}…", &state.accumulated_hash[..16]);
    println!();
    println!("Generating entropy via OsRng...");

    let entropy            = generate_entropy();
    let entropy_commitment = hex::encode(Sha256::digest(entropy));
    let new_hash           = accumulate(&state.accumulated_hash, &entropy)?;
    let index              = state.contributions.len() as u32;

    state.contributions.push(Contribution {
        index,
        contributor:        name.to_string(),
        timestamp:          now_unix(),
        entropy_commitment,
        accumulated_hash:   new_hash.clone(),
    });
    state.accumulated_hash = new_hash.clone();

    save_state(&state, path)?;

    println!("✓ Contribution #{} added", index);
    println!("  New hash: {}…", &new_hash[..16]);
    println!();
    println!("Your entropy commitment: {}…", &state.contributions.last().unwrap().entropy_commitment[..16]);
    println!("(Share this hash to prove your contribution was included)");
    Ok(())
}

fn cmd_finalize(path: &str) -> anyhow::Result<()> {
    let state = load_state(path)?;

    if state.contributions.len() < 2 {
        anyhow::bail!(
            "At least 2 contributions required for a secure ceremony (got {}).\n\
             Add more participants with 'contribute'.",
            state.contributions.len()
        );
    }

    println!("=== ATLAS ZK Ceremony — FINALIZE ===");
    println!("Contributions: {}", state.contributions.len());
    println!("Final hash:    {}", state.accumulated_hash);
    println!();
    println!("⚠ Vertrauensannahme: DIESE Maschine sieht den Setup-Seed.");
    println!("  (Keine echte MPC — siehe Tool-Header. Für Mainnet: auditierte Phase-2.)");
    println!();

    // Seed = SHA256(accumulated_hash || frische OsRng-Entropie).
    //
    // Die frische Entropie wird NIE persistiert — aus ceremony.json allein ist
    // der Seed damit NICHT rekonstruierbar. (Würde nur der akkumulierte Hash
    // verwendet, könnte JEDER mit der Datei den toxic waste nachrechnen und
    // beliebige Beweise fälschen.)
    let hash_bytes: Vec<u8> = hex::decode(&state.accumulated_hash)
        .context("Invalid accumulated_hash")?;
    let fresh = generate_entropy();
    let mut h = Sha256::new();
    h.update(&hash_bytes);
    h.update(fresh);
    let seed: [u8; 32] = h.finalize().into();
    let mut rng = ChaCha20Rng::from_seed(seed);

    let keys_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/keys");
    std::fs::create_dir_all(keys_dir)?;

    // ── 1) Soundness-tragender StateTransitionCircuit (state_vk/state_pk) ────
    println!("Generating STATE keys (batch_size = {}, ~30 s)...", atlas_zk::L2_BATCH_SIZE);
    let (state_pk, state_vk) = Groth16::<Bn254>::circuit_specific_setup(
        StateTransitionCircuit::dummy(atlas_zk::L2_BATCH_SIZE),
        &mut rng,
    ).map_err(|e| anyhow::anyhow!("Groth16 state setup failed: {}", e))?;

    let mut state_vk_bytes = Vec::new();
    state_vk.serialize_compressed(&mut state_vk_bytes)
        .map_err(|e| anyhow::anyhow!("State-VK serialization failed: {}", e))?;
    // PK unkomprimiert (schnelles Laden im Aggregator — setup::pk_to_bytes_fast).
    let state_pk_bytes = atlas_zk::setup::pk_to_bytes_fast(&state_pk)
        .map_err(|e| anyhow::anyhow!("State-PK serialization failed: {}", e))?;

    let state_vk_path = format!("{}/state_vk.bin", keys_dir);
    let state_pk_path = format!("{}/state_pk.bin", keys_dir);
    std::fs::write(&state_vk_path, &state_vk_bytes)?;
    std::fs::write(&state_pk_path, &state_pk_bytes)?;
    println!("✓ State-VK: {} ({} bytes)", state_vk_path, state_vk_bytes.len());
    println!("✓ State-PK: {} ({:.1} MB)", state_pk_path,
        state_pk_bytes.len() as f64 / 1_048_576.0);

    // ── 2) Legacy-BatchProofCircuit (vk/pk) ──────────────────────────────────
    println!("Generating legacy batch keys (~10 s)...");
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        BatchProofCircuit::dummy(),
        &mut rng,
    ).map_err(|e| anyhow::anyhow!("Groth16 setup failed: {}", e))?;

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| anyhow::anyhow!("VK serialization failed: {}", e))?;
    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|e| anyhow::anyhow!("PK serialization failed: {}", e))?;

    let vk_path = format!("{}/vk.bin", keys_dir);
    let pk_path = format!("{}/pk.bin", keys_dir);
    std::fs::write(&vk_path, &vk_bytes)?;
    std::fs::write(&pk_path, &pk_bytes)?;
    println!("✓ VK written: {} ({} bytes)", vk_path, vk_bytes.len());
    println!("✓ PK written: {} ({} bytes)", pk_path, pk_bytes.len());

    println!();
    println!("Security summary:");
    println!("  {} Beiträge dokumentiert (öffentlich nachvollziehbar).", state.contributions.len());
    println!("  Seed = H(accumulated_hash ‖ frische OsRng-Entropie) — aus der");
    println!("  ceremony.json allein NICHT rekonstruierbar.");
    println!("  VERBLEIBENDE ANNAHME: diese Finalize-Maschine war ehrlich/sauber.");
    println!("  → Vor Mainnet-Launch durch echte MPC-Phase-2 ersetzen.");
    println!();
    println!("Next steps:");
    println!("  1. keys/state_vk.bin + keys/vk.bin via include_bytes! einbetten (Node neu bauen)");
    println!("  2. ceremony.json + beide VKs ins Repo committen");
    println!("  3. keys/state_pk.bin + keys/pk.bin an Aggregator-Hosts verteilen (NICHT committen)");
    Ok(())
}

fn cmd_verify(path: &str) -> anyhow::Result<()> {
    let state = load_state(path)?;

    println!("=== ATLAS ZK Ceremony — VERIFY ===");
    println!("Circuit:  {}", state.circuit);
    println!("Version:  {}", state.version);
    println!("Contributors: {}", state.contributions.len());
    println!();
    println!("{:<4} {:<20} {:<20} Hash (first 32 chars)", "No.", "Name", "Timestamp");
    println!("{}", "-".repeat(80));

    for c in &state.contributions {
        println!(
            "{:<4} {:<20} {:<20} {}…",
            c.index,
            truncate(&c.contributor, 20),
            c.timestamp,
            &c.accumulated_hash[..32],
        );
    }

    println!();
    println!("Final accumulated hash: {}", state.accumulated_hash);
    println!();

    // Konsistenzprüfung: jeder Beitrag muss zum nächsten passen
    // (Wir kennen die ursprüngliche Entropie nicht, können aber die Kette nicht
    //  rückwärts verifizieren. Was wir können: sicherstellen dass der finale Hash
    //  zum letzten Beitrag passt.)
    if state.contributions.last().map(|c| &c.accumulated_hash) == Some(&state.accumulated_hash) {
        println!("✓ Ceremony state is internally consistent");
    } else {
        println!("⚠ Final hash does not match last contribution — file may be corrupted!");
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { s } else { &s[..max] }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd  = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "init" => {
            let path = args.get(2).map(|s| s.as_str()).unwrap_or("ceremony.json");
            cmd_init(path)
        }
        "contribute" => {
            let path = args.get(2).ok_or_else(|| anyhow::anyhow!("Usage: contribute <ceremony.json> <name>"))?;
            let name = args.get(3).ok_or_else(|| anyhow::anyhow!("Usage: contribute <ceremony.json> <name>"))?;
            cmd_contribute(path, name)
        }
        "finalize" => {
            let path = args.get(2).map(|s| s.as_str()).unwrap_or("ceremony.json");
            cmd_finalize(path)
        }
        "verify" => {
            let path = args.get(2).map(|s| s.as_str()).unwrap_or("ceremony.json");
            cmd_verify(path)
        }
        _ => {
            println!("ATLAS ZK Trusted-Setup Ceremony");
            println!();
            println!("Befehle:");
            println!("  init       [ceremony.json]                Erste Contribution (Projektteam)");
            println!("  contribute <ceremony.json> <name>         Eigene Entropie hinzufügen");
            println!("  finalize   [ceremony.json]                keys/vk.bin + pk.bin erzeugen");
            println!("  verify     [ceremony.json]                Beitragskette anzeigen");
            Ok(())
        }
    }
}
