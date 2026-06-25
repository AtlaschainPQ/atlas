//! Integrationstests für ATLAS — testen das Zusammenspiel mehrerer Crates.
//!
//! Im Gegensatz zu Unit-Tests in chain.rs prüfen diese Tests
//! den kompletten Datenfluss über Crate-Grenzen hinweg.

use std::sync::Arc;

use atlas_consensus::{
    checkpoints::verify_checkpoint,
    params::ConsensusParams,
};
use atlas_core::{
    block::Block,
    crypto::{Address, KeyPair},
    hash::Hash,
};
use atlas_mempool::mempool::Mempool;
use atlas_state::state_db::StateDb;

// Importiere ChainManager + mining-Helper über die lib-Schnittstelle
use atlas_node::chain::{ChainManager, ChainError};

// ── Interne Hilfsmittel (gespiegelt aus chain.rs Tests) ───────────────────────

use atlas_triad::{
    dataset::{Dataset, DatasetConfig},
    epoch::EpochSeed,
    miner::TriadMiner,
    network_entropy::NetworkEntropy,
};
use std::sync::atomic::AtomicBool;

fn make_regtest_chain() -> Arc<ChainManager> {
    let params  = ConsensusParams::regtest();
    let state   = Arc::new(StateDb::new());
    let mempool = Arc::new(Mempool::new(params.clone()));
    Arc::new(ChainManager::new(params, state, mempool, true))
}

fn mine_one(chain: &ChainManager, miner: Address) -> atlas_core::block::Block {
    let mut template = chain.block_template(miner, miner);
    template.header.bits = 0x200f_ffff; // sehr leichte Difficulty für Tests

    let target  = template.header.target();
    let seed    = EpochSeed::for_epoch(template.header.epoch);
    let dataset = Dataset::new_for_verification(&seed, DatasetConfig::test());
    let stop    = Arc::new(AtomicBool::new(false));
    let result  = TriadMiner::new(dataset, NetworkEntropy::new())
        .mine(&template.header, &target, 0, &stop)
        .expect("Easy target must find solution");

    template.header.nonce    = result.nonce;
    template.header.mix_hash = result.mix_hash;
    template
}

// ── Test 1: Checkpoint-Verifikation (atlas-consensus × atlas-core) ────────────

#[test]
fn integration_genesis_checkpoint_matches() {
    // Der Genesis-Block-Hash muss exakt dem Mainnet-Checkpoint entsprechen.
    let genesis = Block::genesis();
    let hash    = genesis.hash();

    // Muss Ok sein
    verify_checkpoint("mainnet", 0, &hash)
        .expect("Genesis hash must match hardcoded mainnet checkpoint");
}

#[test]
fn integration_wrong_hash_rejected_by_checkpoint() {
    let wrong = Hash::sha256(b"wrong-hash");
    let result = verify_checkpoint("mainnet", 0, &wrong);
    assert!(result.is_err(), "Wrong hash must be rejected at checkpoint height 0");
}

#[test]
fn integration_testnet_has_no_checkpoints() {
    // Testnet hat keine Checkpoints — beliebiger Hash muss Ok sein
    let any_hash = Hash::sha256(b"any");
    verify_checkpoint("testnet", 0, &any_hash)
        .expect("Testnet has no checkpoints, should always pass");
}

// ── Test 2: Regtest Mining → Chain-State (atlas-node × atlas-core) ────────────

#[test]
fn integration_two_blocks_height_and_supply() {
    let chain = make_regtest_chain();
    let kp    = KeyPair::generate();

    assert_eq!(chain.height(), 0);

    // Block 1 abbauen + einreichen
    let b1 = mine_one(&chain, kp.address);
    let reward1 = b1.transactions[0].total_output();
    chain.process_block(b1).expect("Block 1 must be accepted");
    assert_eq!(chain.height(), 1);

    // 1s warten damit Block 2 einen höheren Timestamp bekommt
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Block 2
    let b2 = mine_one(&chain, kp.address);
    chain.process_block(b2).expect("Block 2 must be accepted");
    assert_eq!(chain.height(), 2);

    // Total Supply muss ≥ dem Reward von Block 1 sein
    let supply = chain.state().total_supply();
    assert!(supply >= reward1, "Supply after 2 blocks must exceed block-1 reward");
}

#[test]
fn integration_duplicate_block_rejected() {
    let chain = make_regtest_chain();
    let kp    = KeyPair::generate();

    let block = mine_one(&chain, kp.address);
    chain.process_block(block.clone()).expect("First submission must succeed");

    let err = chain.process_block(block).unwrap_err();
    assert!(
        matches!(err, ChainError::AlreadyKnown(_)),
        "Duplicate block must return AlreadyKnown, got {:?}", err
    );
}

#[test]
fn integration_orphan_block_rejected() {
    let chain = make_regtest_chain();
    let kp    = KeyPair::generate();

    let mut orphan = mine_one(&chain, kp.address);
    orphan.header.prev_hash = Hash::sha256(b"nonexistent-parent");

    let err = chain.process_block(orphan).unwrap_err();
    assert!(
        matches!(err,
            ChainError::Orphan(_) | ChainError::Validation(_) | ChainError::AlreadyKnown(_)
        ),
        "Orphan block must be rejected, got {:?}", err
    );
}

// ── Test 3: ZK Proof Round-Trip (atlas-zk) ───────────────────────────────────

#[test]
fn integration_zk_verifier_from_hardcoded_vk() {
    // ZkBatchVerifier muss aus dem hardcodierten VK initialisiert werden können
    let verifier = atlas_zk::ZkBatchVerifier::from_hardcoded_vk()
        .expect("Hardcoded VK must be valid");

    // Dummy-Proof muss abgelehnt werden (leere Bytes)
    let pre_root = [0u8; 32];
    let batch    = [1u8; 32];
    let result   = verifier.verify(&[], &pre_root, &batch, 0);
    assert!(result.is_err(), "Empty proof bytes must be rejected");
}

// ── Test 4: Config Seed-Nodes (atlas-node) ───────────────────────────────────

#[test]
fn integration_mainnet_config_has_seed_nodes() {
    use atlas_node::config::NodeConfig;
    let cfg = NodeConfig::default();
    assert_eq!(cfg.network, "mainnet");
    assert!(!cfg.seed_nodes.is_empty(), "Mainnet config must have seed nodes");
    for seed in &cfg.seed_nodes {
        assert!(seed.contains(':'), "Seed node '{}' must have port", seed);
    }
}

#[test]
fn integration_testnet_config_has_different_port() {
    use atlas_node::config::NodeConfig;
    let mainnet = NodeConfig::default();
    let testnet = NodeConfig::testnet();
    assert_ne!(mainnet.p2p_port, testnet.p2p_port);
    assert_ne!(mainnet.rpc_port, testnet.rpc_port);
    assert!(!testnet.seed_nodes.is_empty(), "Testnet must have seed nodes");
}

#[test]
fn integration_regtest_has_mining_enabled() {
    use atlas_node::config::NodeConfig;
    let regtest = NodeConfig::regtest();
    assert_eq!(regtest.network, "regtest");
    assert!(regtest.mining, "Regtest must have mining enabled by default");
}
