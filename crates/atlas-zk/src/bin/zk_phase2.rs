//! ATLAS Phase-2-Ceremony-Werkzeug (δ-Beiträge) — OPERATIVES GERÜST.
//!
//! ╔══════════════════ ⚠️ NICHT FÜR ECHTES GELD (ohne Audit) ════════════════════╗
//! ║ Dieses Tool koordiniert δ-Beiträge zum Groth16-Proving-Key und führt ein     ║
//! ║ öffentliches Transcript. Es ist das GERÜST der Ceremony, NICHT die fertige,  ║
//! ║ sichere Ceremony. Es FEHLEN (Cryptographer-+-Audit-Territorium, siehe        ║
//! ║ CEREMONY.md und crates/atlas-zk/src/mpc.rs):                                 ║
//! ║   1. Phase 1 (Powers of Tau) für α/β/τ — `init` nutzt hier                   ║
//! ║      `circuit_specific_setup` (single-machine!). δ-Beiträge sichern α/β/τ    ║
//! ║      NICHT. Vor Mainnet zwingend durch PoT-Wiederverwendung ersetzen.        ║
//! ║   2. Beitrags-Proof-of-Knowledge — Beiträge sind aktuell nicht öffentlich    ║
//! ║      auf Ehrlichkeit verifizierbar.                                          ║
//! ╚═════════════════════════════════════════════════════════════════════════════╝
//!
//! Befehle:
//!   init                    → Start-Parameter erzeugen (phase2.pk) + Transcript
//!   contribute <name>       → einen δ-Beitrag anwenden (auf Airgap-Maschine!)
//!   verify                  → Transcript-Kette anzeigen
//!   finalize                → keys/state_pk.bin + keys/state_vk.bin schreiben

use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use atlas_zk::mpc::{contribute, verify_contribution_structural};
use atlas_zk::state_circuit::StateTransitionCircuit;
use atlas_zk::L2_BATCH_SIZE;

const PK_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/keys/phase2.pk");
const TR_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/keys/phase2_transcript.json");

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }

fn hash_g1(p: &ark_bn254::G1Affine) -> String {
    let mut b = Vec::new();
    p.serialize_compressed(&mut b).unwrap();
    hex::encode(Sha256::digest(&b))
}

fn load_pk() -> anyhow::Result<ProvingKey<Bn254>> {
    let bytes = std::fs::read(PK_PATH)
        .map_err(|e| anyhow::anyhow!("phase2.pk nicht lesbar ('init' zuerst?): {e}"))?;
    atlas_zk::setup::pk_from_bytes_fast(&bytes)
}
fn save_pk(pk: &ProvingKey<Bn254>) -> anyhow::Result<()> {
    std::fs::write(PK_PATH, atlas_zk::setup::pk_to_bytes_fast(pk)?)?;
    Ok(())
}

fn load_tr() -> serde_json::Value {
    std::fs::read_to_string(TR_PATH).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({ "contributions": [] }))
}
fn save_tr(v: &serde_json::Value) -> anyhow::Result<()> {
    std::fs::write(TR_PATH, serde_json::to_string_pretty(v)?)?;
    Ok(())
}

fn banner() {
    eprintln!("⚠️  GERÜST — NICHT fälschungssicher ohne Phase-1-PoT + Beitrags-PoK + Audit.");
    eprintln!("    Siehe CEREMONY.md. Nicht für Mainnet mit echtem Geld verwenden.\n");
}

fn main() -> anyhow::Result<()> {
    banner();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("init") => {
            if std::path::Path::new(PK_PATH).exists() {
                anyhow::bail!("phase2.pk existiert bereits — lösche keys/phase2.pk für Neustart.");
            }
            eprintln!("init: erzeuge Start-Parameter (batch_size={L2_BATCH_SIZE}) …");
            eprintln!("    ⚠️ Phase 1 (α/β/τ) hier SINGLE-MACHINE — vor Mainnet durch PoT ersetzen!");
            let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(
                StateTransitionCircuit::dummy(L2_BATCH_SIZE), &mut OsRng,
            ).map_err(|e| anyhow::anyhow!("Setup: {e}"))?;
            save_pk(&pk)?;
            let tr = serde_json::json!({
                "circuit": "atlas-state-transition",
                "batch_size": L2_BATCH_SIZE,
                "phase1_source": "circuit_specific_setup (SINGLE-MACHINE — MUST be replaced by Powers-of-Tau before mainnet)",
                "contributions": [{
                    "index": 0, "name": "init", "timestamp": now(),
                    "delta_after": hash_g1(&pk.delta_g1),
                }],
            });
            save_tr(&tr)?;
            eprintln!("✓ phase2.pk + Transcript erstellt. Nächster Schritt: contribute <name>.");
        }
        Some("contribute") => {
            let name = args.get(2).map(|s| s.as_str()).unwrap_or("anon");
            let mut pk = load_pk()?;
            eprintln!("contribute '{name}': δ-Beitrag wird angewandt …");
            let c = contribute(&mut pk, &mut OsRng);
            if !verify_contribution_structural(&c) { anyhow::bail!("Beitrag strukturell ungültig"); }
            save_pk(&pk)?;
            let mut tr = load_tr();
            let idx = tr["contributions"].as_array().map(|a| a.len()).unwrap_or(0);
            tr["contributions"].as_array_mut().unwrap().push(serde_json::json!({
                "index": idx, "name": name, "timestamp": now(),
                "delta_before": hash_g1(&c.delta_before_g1),
                "delta_after":  hash_g1(&c.delta_after_g1),
                "s_g1":         hash_g1(&c.s_g1),
            }));
            save_tr(&tr)?;
            eprintln!("✓ Beitrag #{idx} ('{name}') angewandt. δ → {}…", &hash_g1(&c.delta_after_g1)[..16]);
            eprintln!("  → Vernichte jetzt deine Zufälligkeit/Maschine. Veröffentliche das Transcript.");
        }
        Some("verify") => {
            let tr = load_tr();
            println!("Circuit: {}  batch_size: {}", tr["circuit"], tr["batch_size"]);
            println!("Phase-1-Quelle: {}", tr["phase1_source"]);
            println!("{:<4} {:<20} {:<12} delta_after", "#", "contributor", "ts");
            for c in tr["contributions"].as_array().cloned().unwrap_or_default() {
                println!("{:<4} {:<20} {:<12} {}…",
                    c["index"], c["name"].as_str().unwrap_or("?"),
                    c["timestamp"], &c["delta_after"].as_str().unwrap_or("")[..16.min(c["delta_after"].as_str().unwrap_or("").len())]);
            }
            let n = tr["contributions"].as_array().map(|a| a.len().saturating_sub(1)).unwrap_or(0);
            println!("\n{} echte Beiträge. Sicher, WENN ≥1 ehrlich war — UND Phase-1+PoK ergänzt/auditiert.", n);
        }
        Some("finalize") => {
            let pk = load_pk()?;
            let keys = concat!(env!("CARGO_MANIFEST_DIR"), "/keys");
            let mut vk_bytes = Vec::new();
            pk.vk.serialize_compressed(&mut vk_bytes)?;
            std::fs::write(format!("{keys}/state_vk.bin"), &vk_bytes)?;
            std::fs::write(format!("{keys}/state_pk.bin"), atlas_zk::setup::pk_to_bytes_fast(&pk)?)?;
            eprintln!("✓ state_vk.bin ({} B) + state_pk.bin geschrieben.", vk_bytes.len());
            eprintln!("  ⚠️ GÜLTIG NUR, wenn Phase-1-PoT + Beitrags-PoK ergänzt UND auditiert sind.");
            eprintln!("  Danach: state_vk.bin via genesis_root-Workflow ins Repo, Node neu bauen.");
        }
        _ => {
            eprintln!("Befehle: init | contribute <name> | verify | finalize");
        }
    }
    Ok(())
}
