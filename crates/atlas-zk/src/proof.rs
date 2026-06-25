//! Beweis-Generierung und -Verifikation für den BatchProofCircuit.
//!
//! Format von `proof_bytes` in ProofRef:
//!   [0..32]   post_commitment (Fr als LE-Bytes, 32 Byte)
//!   [32..]    Groth16-Beweis (komprimiert, ~192 Byte auf BN254)
//!
//! Öffentliche Eingaben für den Verifier (in Reihenfolge):
//!   1. pre_root        (32-Byte-Hash → Fr mod p)
//!   2. batch_merkle    (32-Byte-Hash → Fr mod p)
//!   3. total_fees      (u128 → Fr)
//!   4. post_commitment (32-Byte → Fr — aus proof_bytes[0..32])

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::rngs::OsRng;
use thiserror::Error;

use crate::circuit::BatchProofCircuit;
use crate::native::mimc_sponge;

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),
    #[error("Proof verification failed")]
    VerificationFailed,
    #[error("Invalid proof bytes: {0}")]
    InvalidBytes(String),
}

// ── Konvertierungen zwischen [u8;32] / u128 und Fr ───────────────────────────

pub fn hash_to_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

pub fn u128_to_fr(n: u128) -> Fr {
    Fr::from(n)
}

pub fn fr_to_bytes32(fr: Fr) -> [u8; 32] {
    let bigint  = fr.into_bigint();
    let le      = bigint.to_bytes_le();
    let mut out = [0u8; 32];
    out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
    out
}

// ── Block-Aggregation: viele Batches → EIN Digest ────────────────────────────

/// Faltet die Batch-Daten eines ganzen Blocks zu EINEM Digest zusammen.
///
/// Reihenfolge der MiMC-Absorption (Prover UND Verifier MÜSSEN identisch sein):
///   [ pre_root, batch_id_1, fees_1, batch_id_2, fees_2, ... ]
///
/// Dieser Digest tritt im aggregierten Block-Proof an die Stelle von `batch_merkle`
/// im bestehenden `BatchProofCircuit`. Der Verifier rechnet ihn unabhängig aus den
/// on-chain SettlementBid-TXs (batch_id + bid_amount) nach und prüft Gleichheit gegen
/// `header.proof_root` — dadurch ist der eine Block-Proof an genau diese Batch-Menge
/// und an die Chain-Position (pre_root) gebunden.
///
/// `batches`: in Block-Reihenfolge — (batch_id, bid_amount_atom).
pub fn compute_batches_digest(pre_root: &[u8; 32], batches: &[([u8; 32], u128)]) -> [u8; 32] {
    let mut inputs = Vec::with_capacity(1 + batches.len() * 2);
    inputs.push(hash_to_fr(pre_root));
    for (batch_id, fees) in batches {
        inputs.push(hash_to_fr(batch_id));
        inputs.push(u128_to_fr(*fees));
    }
    let digest = mimc_sponge(&inputs);
    fr_to_bytes32(digest)
}

// ── Prover ────────────────────────────────────────────────────────────────────

/// Generiert einen Batch-Commitment-Beweis.
///
/// Wählt intern einen zufälligen Nonce und berechnet:
///   post_commitment = MiMC_sponge([pre_root, batch_merkle, total_fees, nonce])
///
/// Gibt zurück: (proof_bytes, post_commitment_bytes)
/// - proof_bytes   = [post_commitment(32B)] + [Groth16-Proof(~192B)]
/// - post_commitment = Fr als LE-Bytes
pub fn prove(
    pk:          &ProvingKey<Bn254>,
    pre_root:    &[u8; 32],
    batch_merkle: &[u8; 32],
    total_fees:  u128,
) -> Result<(Vec<u8>, [u8; 32]), ProofError> {
    // Nonce: zufällig, geheim beim Aggregator
    let mut nonce_raw = [0u8; 32];
    use rand::RngCore;
    OsRng.fill_bytes(&mut nonce_raw);
    let nonce = Fr::from_le_bytes_mod_order(&nonce_raw);

    // Fr-Konvertierungen
    let pre_fr   = hash_to_fr(pre_root);
    let batch_fr = hash_to_fr(batch_merkle);
    let fees_fr  = u128_to_fr(total_fees);

    // post_commitment = MiMC(pre, batch, fees, nonce)
    let post_fr    = mimc_sponge(&[pre_fr, batch_fr, fees_fr, nonce]);
    let post_bytes = fr_to_bytes32(post_fr);

    // Circuit instanzieren
    let circuit = BatchProofCircuit {
        pre_root:        pre_fr,
        batch_merkle:    batch_fr,
        total_fees:      fees_fr,
        post_commitment: post_fr,
        nonce,
    };

    // Groth16-Beweis erzeugen
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut OsRng)
        .map_err(|e| ProofError::GenerationFailed(e.to_string()))?;

    // Beweis serialisieren
    let mut proof_bytes_buf = Vec::new();
    proof.serialize_compressed(&mut proof_bytes_buf)
        .map_err(|e| ProofError::GenerationFailed(e.to_string()))?;

    // Format: [post_commitment(32B)] + [groth16_proof]
    let mut out = Vec::with_capacity(32 + proof_bytes_buf.len());
    out.extend_from_slice(&post_bytes);
    out.extend_from_slice(&proof_bytes_buf);

    Ok((out, post_bytes))
}

// ── State-Transition-Prover/Verifier (Phase 3, soundness-tragend) ────────────

/// Erzeugt einen Groth16-Beweis für den `StateTransitionCircuit`.
///
/// `proof_bytes` = NUR der Groth16-Beweis (kein prover-gewähltes Commitment mehr —
/// `post_root` ist eine eigenständige öffentliche Eingabe, die der Verifier aus
/// On-Chain-Daten bezieht). Rückgabe: (proof_bytes, post_root_bytes, batch_commitment_bytes),
/// damit der Aufrufer post_root + commitment on-chain festschreiben kann.
pub fn prove_state(
    pk:         &ProvingKey<Bn254>,
    bw:         &crate::transition::BatchWitness,
    batch_size: usize,
) -> Result<(Vec<u8>, [u8; 32], [u8; 32]), ProofError> {
    let circuit = crate::state_circuit::StateTransitionCircuit::from_witness(bw, batch_size);
    let post_bytes   = fr_to_bytes32(circuit.post_root);
    let commit_bytes = fr_to_bytes32(circuit.batch_commitment);

    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut OsRng)
        .map_err(|e| ProofError::GenerationFailed(e.to_string()))?;

    let mut out = Vec::new();
    proof.serialize_compressed(&mut out)
        .map_err(|e| ProofError::GenerationFailed(e.to_string()))?;
    Ok((out, post_bytes, commit_bytes))
}

/// Verifiziert einen State-Transition-Beweis gegen die öffentlichen Eingaben.
/// ALLE Public Inputs stammen aus On-Chain-Daten — nichts vom Prover Gewähltes.
pub fn verify_state(
    pvk:              &PreparedVerifyingKey<Bn254>,
    proof_bytes:      &[u8],
    pre_root:         &[u8; 32],
    post_root:        &[u8; 32],
    total_fees:       u128,
    batch_commitment: &[u8; 32],
) -> Result<(), ProofError> {
    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| ProofError::InvalidBytes(e.to_string()))?;

    let public_inputs = vec![
        hash_to_fr(pre_root),
        hash_to_fr(post_root),
        u128_to_fr(total_fees),
        hash_to_fr(batch_commitment),
    ];

    let valid = Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs, &proof)
        .map_err(|e| ProofError::InvalidBytes(e.to_string()))?;
    if valid { Ok(()) } else { Err(ProofError::VerificationFailed) }
}

// ── Verifier ─────────────────────────────────────────────────────────────────

/// Bereitet den Verifying-Key vor (gecacht, einmalig aufrufen).
pub fn prepare_vk(vk: &VerifyingKey<Bn254>) -> Result<PreparedVerifyingKey<Bn254>, ProofError> {
    Groth16::<Bn254>::process_vk(vk)
        .map_err(|e| ProofError::InvalidBytes(e.to_string()))
}

/// Verifiziert einen Batch-Commitment-Beweis.
///
/// - `proof_bytes`: Format = [post_commitment(32B)] + [Groth16-Proof]
/// - `pre_root`, `batch_merkle`, `total_fees`: öffentliche Batch-Daten
pub fn verify(
    pvk:          &PreparedVerifyingKey<Bn254>,
    proof_bytes:  &[u8],
    pre_root:     &[u8; 32],
    batch_merkle: &[u8; 32],
    total_fees:   u128,
) -> Result<(), ProofError> {
    if proof_bytes.len() < 32 {
        return Err(ProofError::InvalidBytes("proof too short".into()));
    }

    // post_commitment aus den ersten 32 Bytes
    let mut post_bytes = [0u8; 32];
    post_bytes.copy_from_slice(&proof_bytes[..32]);
    let post_fr = hash_to_fr(&post_bytes);

    // Groth16-Beweis deserialisieren
    let proof = Proof::<Bn254>::deserialize_compressed(&proof_bytes[32..])
        .map_err(|e| ProofError::InvalidBytes(e.to_string()))?;

    // Öffentliche Eingaben (gleiche Reihenfolge wie im Circuit!)
    let public_inputs = vec![
        hash_to_fr(pre_root),
        hash_to_fr(batch_merkle),
        u128_to_fr(total_fees),
        post_fr,
    ];

    // Verifikation
    let valid = Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs, &proof)
        .map_err(|e| ProofError::InvalidBytes(e.to_string()))?;

    if valid { Ok(()) } else { Err(ProofError::VerificationFailed) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::generate_keys_devnet;

    #[test]
    fn test_prove_verify_roundtrip() {
        let (pk, vk) = generate_keys_devnet().expect("setup must succeed");
        let pvk = prepare_vk(&vk).unwrap();

        let pre_root    = [1u8; 32];
        let batch_merkle = [2u8; 32];
        let total_fees  = 500u128;

        let (proof_bytes, _) = prove(&pk, &pre_root, &batch_merkle, total_fees)
            .expect("proving must succeed");

        verify(&pvk, &proof_bytes, &pre_root, &batch_merkle, total_fees)
            .expect("verification must succeed");
    }

    #[test]
    fn test_batches_digest_deterministic_and_binding() {
        let pre_root = [7u8; 32];
        let batches = [([1u8; 32], 100u128), ([2u8; 32], 200u128)];
        let d1 = compute_batches_digest(&pre_root, &batches);
        let d2 = compute_batches_digest(&pre_root, &batches);
        assert_eq!(d1, d2, "digest must be deterministic");

        // Andere Batch-Menge → anderer Digest
        let batches2 = [([1u8; 32], 100u128), ([2u8; 32], 201u128)];
        assert_ne!(d1, compute_batches_digest(&pre_root, &batches2), "fees change must change digest");

        // Anderer pre_root → anderer Digest (Chain-Position-Bindung)
        assert_ne!(d1, compute_batches_digest(&[8u8; 32], &batches), "pre_root change must change digest");

        // Reihenfolge ist signifikant
        let reordered = [([2u8; 32], 200u128), ([1u8; 32], 100u128)];
        assert_ne!(d1, compute_batches_digest(&pre_root, &reordered), "order must matter");
    }

    #[test]
    fn test_aggregated_block_proof_roundtrip() {
        // Beweist: der bestehende prove/verify funktioniert mit dem Block-Digest
        // an der Stelle von batch_merkle → 1 Proof deckt alle Batches ab.
        let (pk, vk) = generate_keys_devnet().expect("setup");
        let pvk = prepare_vk(&vk).unwrap();

        let pre_root = [3u8; 32];
        let batches = [([10u8; 32], 5u128), ([11u8; 32], 7u128), ([12u8; 32], 9u128)];
        let total_fees: u128 = batches.iter().map(|(_, f)| *f).sum();
        let digest = compute_batches_digest(&pre_root, &batches);

        let (proof_bytes, _) = prove(&pk, &pre_root, &digest, total_fees).expect("prove");
        verify(&pvk, &proof_bytes, &pre_root, &digest, total_fees).expect("verify must succeed");

        // Manipulierte Batch-Menge → Verifier rechnet anderen Digest → Proof scheitert
        let tampered = compute_batches_digest(&pre_root, &[([10u8; 32], 5u128), ([11u8; 32], 7u128)]);
        assert!(verify(&pvk, &proof_bytes, &pre_root, &tampered, total_fees).is_err(),
            "proof must not verify against a different batch set");
    }

    #[test]
    fn test_state_prove_verify_roundtrip() {
        use crate::account::{Account, AccountTree};
        use crate::eddsa::EddsaKeypair;
        use crate::transition::{apply_batch, L2Tx};
        use crate::setup::generate_keys_state;
        use ark_ed_on_bn254::Fr as EdFr;

        let batch_size = 4;
        let (pk, vk) = generate_keys_state(batch_size).expect("state setup");
        let pvk = prepare_vk(&vk).unwrap();

        let alice = EddsaKeypair::from_secret(EdFr::from(1u64));
        let bob = EddsaKeypair::from_secret(EdFr::from(2u64)).public().address_fr();
        let mut tree = AccountTree::new();
        tree.register(Account::new(alice.public().address_fr(), 1_000_000, 0));
        let pre_root = fr_to_bytes32(tree.root());

        let txs = [L2Tx::signed(bob, 1234, 7, 0, &alice)];
        let bw = apply_batch(&mut tree, &txs).unwrap();

        let (proof_bytes, post_root, commit) = prove_state(&pk, &bw, batch_size).expect("prove_state");

        // Gültig.
        verify_state(&pvk, &proof_bytes, &pre_root, &post_root, bw.total_fees, &commit)
            .expect("verify must succeed");

        // Manipulierte post_root → Verifikation scheitert.
        let mut wrong_post = post_root;
        wrong_post[0] ^= 0xFF;
        assert!(verify_state(&pvk, &proof_bytes, &pre_root, &wrong_post, bw.total_fees, &commit).is_err(),
            "Beweis darf gegen falsche post_root nicht verifizieren");

        // Manipulierte Fees → scheitert.
        assert!(verify_state(&pvk, &proof_bytes, &pre_root, &post_root, bw.total_fees + 1, &commit).is_err(),
            "Beweis darf gegen falsche fees nicht verifizieren");
    }

    #[test]
    #[ignore = "Bench: nur explizit ausführen"]
    fn bench_state_batch_sizes() {
        use crate::account::{Account, AccountTree};
        use crate::eddsa::EddsaKeypair;
        use crate::transition::{apply_batch, L2Tx};
        use crate::setup::generate_keys_state;
        use ark_ed_on_bn254::Fr as EdFr;
        use std::time::Instant;

        for &bs in &[8usize, 16, 32, 64] {
            let t_setup = Instant::now();
            let (pk, vk) = generate_keys_state(bs).expect("setup");
            let setup_ms = t_setup.elapsed().as_millis();
            let pvk = prepare_vk(&vk).unwrap();

            // Fülle bs/2 reale TXs (Rest Padding).
            let n = (bs / 2).max(1);
            let senders: Vec<EddsaKeypair> = (0..n)
                .map(|i| EddsaKeypair::from_secret(EdFr::from((i as u64) + 1)))
                .collect();
            let mut tree = AccountTree::new();
            for kp in &senders {
                tree.register(Account::new(kp.public().address_fr(), 1_000_000, 0));
            }
            let txs: Vec<L2Tx> = senders.iter().enumerate().map(|(i, kp)| {
                let to = EddsaKeypair::from_secret(EdFr::from((i as u64) + 1000)).public().address_fr();
                L2Tx::signed(to, 100, 1, 0, kp)
            }).collect();
            let bw = apply_batch(&mut tree, &txs).unwrap();
            let pre_root = fr_to_bytes32(bw.pre_root);

            let t_prove = Instant::now();
            let (proof, post, commit) = prove_state(&pk, &bw, bs).expect("prove");
            let prove_ms = t_prove.elapsed().as_millis();

            let t_verify = Instant::now();
            verify_state(&pvk, &proof, &pre_root, &post, bw.total_fees, &commit).expect("verify");
            let verify_us = t_verify.elapsed().as_micros();

            let pk_bytes = crate::setup::pk_to_bytes(&pk).unwrap().len();
            println!(
                "batch_size={:>3}  setup={:>6}ms  prove={:>6}ms  verify={:>5}us  pk={:>5}KB",
                bs, setup_ms, prove_ms, verify_us, pk_bytes / 1024
            );
        }
    }

    #[test]
    fn test_verify_wrong_pre_root_fails() {
        let (pk, vk) = generate_keys_devnet().expect("setup must succeed");
        let pvk = prepare_vk(&vk).unwrap();

        let pre_root    = [1u8; 32];
        let batch_merkle = [2u8; 32];
        let total_fees  = 500u128;

        let (proof_bytes, _) = prove(&pk, &pre_root, &batch_merkle, total_fees).unwrap();

        // Anderer pre_root → Verifikation muss scheitern
        let wrong_root = [9u8; 32];
        let result = verify(&pvk, &proof_bytes, &wrong_root, &batch_merkle, total_fees);
        assert!(result.is_err(), "Proof with wrong pre_root must not verify");
    }
}
