use serde::{Deserialize, Serialize};
use crate::hash::{Hash, merkle_root};
use crate::transaction::Transaction;

pub type BlockHeight = u64;

/// Block-Header — alle Daten die der Miner hasht
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version:      u32,
    pub height:       BlockHeight,
    pub prev_hash:    Hash,
    pub merkle_root:  Hash,
    pub proof_root:   Hash,
    pub timestamp:    u64,
    /// Difficulty-Target als kompakter 4-Byte Wert (wie Bitcoin nBits)
    pub bits:         u32,
    pub nonce:        u64,
    /// TRIAD Mix-Hash: Beweis der memory-hard Berechnung (wie Ethash)
    pub mix_hash:     Hash,
    pub epoch:        u32,
    /// Netzwerk-Entropie Seed (von Peer-Gossip)
    pub network_seed: Hash,
    pub batch_count:  u8,
    /// L2-State-Root nach Anwendung aller SettlementBid-Batches dieses Blocks.
    /// Bildet die fortlaufende L2-State-Root-Kette: gleich der `post_root` des
    /// letzten Batches im Block bzw. dem Vorgängerwert, wenn der Block keine
    /// Batches enthält. Im Genesis = `EMPTY_L2_ROOT` (leerer Account-Baum).
    #[serde(default = "l2_genesis_root")]
    pub l2_state_root: Hash,
}

/// Genesis-Wert der L2-State-Root-Kette: Wurzel eines leeren Account-Baums der
/// Tiefe 32 (Poseidon). Muss mit `atlas_zk::empty_l2_state_root()` übereinstimmen —
/// abgesichert durch den Test `l2_genesis_root_matches_zk` in atlas-zk.
pub const EMPTY_L2_ROOT: [u8; 32] = [
    0x7e, 0x93, 0x32, 0x80, 0xbc, 0x78, 0x81, 0x8c,
    0xff, 0xa1, 0x6c, 0x85, 0xe3, 0xdc, 0xbc, 0x10,
    0xcd, 0x70, 0xa0, 0xda, 0x76, 0xe7, 0xd0, 0xa9,
    0x4f, 0x3a, 0x5f, 0xd2, 0x41, 0x5c, 0xe3, 0x26,
];

/// Kanonische Genesis-L2-State-Root. **Fair Launch (kein Premine):** die
/// Genesis-Allokation (`genesis/alloc.json`) ist LEER → die gesamte Geldmenge
/// entsteht ausschließlich durch die PoW-Emission (Modell A, auf L2-Konten
/// gutgeschrieben). Der Genesis-Block verankert daher den LEEREN Baum
/// (== `EMPTY_L2_ROOT`). Muss mit `atlas_zk::genesis_l2_state_root()`
/// übereinstimmen — abgesichert durch den Cross-Check-Test in atlas-node.
/// Generiert via `cargo run -p atlas-zk --release --bin genesis_root`.
pub const GENESIS_L2_ROOT: [u8; 32] = [
    0x7e, 0x93, 0x32, 0x80, 0xbc, 0x78, 0x81, 0x8c,
    0xff, 0xa1, 0x6c, 0x85, 0xe3, 0xdc, 0xbc, 0x10,
    0xcd, 0x70, 0xa0, 0xda, 0x76, 0xe7, 0xd0, 0xa9,
    0x4f, 0x3a, 0x5f, 0xd2, 0x41, 0x5c, 0xe3, 0x26,
];

fn l2_genesis_root() -> Hash { Hash(GENESIS_L2_ROOT) }

impl BlockHeader {
    pub fn hash(&self) -> Hash {
        let data = bincode::serialize(self).expect("header serialization");
        Hash::double_sha256(&data)
    }

    /// Header ohne nonce und mix_hash für TRIAD-Mining-Prefix.
    /// mix_hash ist das OUTPUT der TRIAD-Berechnung, darf also kein INPUT sein.
    pub fn mining_prefix(&self) -> Vec<u8> {
        let mut h = self.clone();
        h.nonce    = 0;
        h.mix_hash = Hash::zero();
        bincode::serialize(&h).expect("header serialization")
    }

    /// Dekodiert Difficulty-Bits in 256-Bit Target
    pub fn target(&self) -> [u8; 32] {
        bits_to_target(self.bits)
    }

    pub const EPOCH_BLOCKS: u32 = 2016;

    pub fn epoch_from_height(height: BlockHeight) -> u32 {
        (height / Self::EPOCH_BLOCKS as u64) as u32
    }
}

/// Vollständiger Block
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header:       BlockHeader,
    pub transactions: Vec<Transaction>,
    /// EIN aggregierter ZK-Proof, der ALLE SettlementBid-Batches dieses Blocks
    /// abdeckt (Format: [post_commitment(32B)] + [Groth16-Proof]).
    /// Leer, wenn der Block keine Settlement-Batches enthält.
    /// Die Bindung an die Batch-Menge erfolgt über `header.proof_root`
    /// (= MiMC-Digest aus pre_root + allen (batch_id, bid_amount)).
    #[serde(default)]
    pub agg_proof:    Vec<u8>,
}

impl Block {
    pub fn hash(&self) -> Hash { self.header.hash() }
    pub fn height(&self) -> BlockHeight { self.header.height }

    pub fn compute_merkle_root(&self) -> Hash {
        let tx_hashes: Vec<Hash> = self.transactions.iter()
            .map(|tx| tx.txid())
            .collect();
        merkle_root(&tx_hashes)
    }

    pub fn tx_count(&self) -> usize { self.transactions.len() }

    pub fn size_bytes(&self) -> usize {
        bincode::serialize(self).map(|v| v.len()).unwrap_or(0)
    }

    /// Genesis-Block (kein Parent, keine Transaktionen)
    pub fn genesis() -> Self {
        let genesis_time = 1_700_000_000u64;
        let header = BlockHeader {
            version:      1,
            height:       0,
            prev_hash:    Hash::zero(),
            merkle_root:  merkle_root(&[]),
            proof_root:   Hash::zero(),
            timestamp:    genesis_time,
            bits:         GENESIS_BITS,
            nonce:        0,
            mix_hash:     Hash::zero(),
            epoch:        0,
            network_seed: Hash::sha256(b"ATLAS Genesis Block - 2024"),
            batch_count:  0,
            l2_state_root: Hash(GENESIS_L2_ROOT),
        };
        Block { header, transactions: vec![], agg_proof: vec![] }
    }
}

/// Referenz auf einen ZK-Proof im Settlement Layer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofRef {
    pub aggregator:  crate::crypto::Address,
    pub batch_id:    Hash,
    pub bid:         crate::amount::Amount,
    pub proof_bytes: Vec<u8>,
}

/// Genesis Bits: niedrige Schwierigkeit für Bootstrap
pub const GENESIS_BITS: u32 = 0x1e00_ffff;

/// Konvertiert kompakte Bits-Darstellung in 256-Bit Target (Bitcoin-kompatibel)
/// bits = (exponent << 24) | mantissa_3bytes
pub fn bits_to_target(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    let mut target = [0u8; 32];

    // exponent ist Anzahl Bytes im Target (von rechts)
    // Zielposition: 32 - exponent
    // exponent=0 → target bleibt [0; 32] (unmögliche Difficulty)
    // exponent=1..=32 → Mantissa an korrekte Position schreiben
    // exponent>32 → Overflow, target bleibt [0; 32]
    if (1..=32).contains(&exponent) {
        let pos = 32 - exponent;
        let b0 = ((mantissa >> 16) & 0xff) as u8;
        let b1 = ((mantissa >>  8) & 0xff) as u8;
        let b2 = ( mantissa        & 0xff) as u8;
        if pos < 32     { target[pos]     = b0; }
        if pos + 1 < 32 { target[pos + 1] = b1; }
        if pos + 2 < 32 { target[pos + 2] = b2; }
    }
    target
}

/// Konvertiert 256-Bit Target in kompakte Bits-Darstellung
pub fn target_to_bits(target: &[u8; 32]) -> u32 {
    // Finde höchstes nicht-null Byte
    let first_nonzero = match target.iter().position(|&b| b != 0) {
        Some(i) => i,
        None    => return 0x2000_0000, // maximales Target (minimale Difficulty)
    };

    let exponent = 32 - first_nonzero;

    // Mantissa: 3 Bytes ab erstem nicht-null Byte
    let b0 = target[first_nonzero] as u32;
    let b1 = if first_nonzero + 1 < 32 { target[first_nonzero + 1] as u32 } else { 0 };
    let b2 = if first_nonzero + 2 < 32 { target[first_nonzero + 2] as u32 } else { 0 };

    // Sign-bit protection: if the high bit of b0 is set the serialised mantissa
    // would be interpreted as negative.  Bitcoin's GetCompact() shifts the mantissa
    // right by one byte (nCompact >>= 8) and increases the exponent by 1.
    let (mantissa, exp_adj) = if b0 & 0x80 != 0 {
        ((b0 << 8) | b1, 1)   // 0x00_b0_b1 — leading zero inserted
    } else {
        ((b0 << 16) | (b1 << 8) | b2, 0)
    };

    let exp = (exponent + exp_adj).min(0xff);
    ((exp as u32) << 24) | (mantissa & 0x007f_ffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis();
        let hash    = genesis.hash();
        println!("Genesis hash: {:?}", hash);
        assert_eq!(genesis.height(), 0);
        assert!(genesis.transactions.is_empty());
        // Merkle Root der leeren Transaktion-Liste = ZERO_HASH
        assert_eq!(genesis.header.merkle_root, Hash::zero());
    }

    #[test]
    fn test_genesis_hash_deterministic() {
        let g1 = Block::genesis();
        let g2 = Block::genesis();
        assert_eq!(g1.hash(), g2.hash());
    }

    #[test]
    fn test_bits_target_bitcoin_genesis() {
        // Bitcoin Genesis: 0x1d00ffff → Target hat 29 Bytes, erste 2 = 0x00ff
        let bits   = 0x1d00_ffffu32;
        let target = bits_to_target(bits);
        // exponent = 0x1d = 29, pos = 32-29 = 3
        assert_eq!(target[3], 0x00);
        assert_eq!(target[4], 0xff);
        assert_eq!(target[5], 0xff);
        // Alles davor muss 0 sein
        assert_eq!(&target[..3], &[0u8; 3]);
        println!("Bitcoin Genesis Target: {}", hex::encode(target));
    }

    #[test]
    fn test_bits_target_roundtrip() {
        // Roundtrip: bits → target → bits muss konsistent sein
        let test_bits = [0x1d00_ffffu32, 0x1e00_ffffu32, 0x1800_1234u32];
        for &bits in &test_bits {
            let target    = bits_to_target(bits);
            let bits_back = target_to_bits(&target);
            let target2   = bits_to_target(bits_back);
            // Targets müssen gleich sein (bits kann durch leading-zeros-Normalisierung abweichen)
            assert_eq!(target, target2,
                "Roundtrip failed for bits={:#010x}", bits);
        }
    }

    #[test]
    fn test_target_to_bits_zero_target() {
        let zero_target = [0u8; 32];
        let bits = target_to_bits(&zero_target);
        // Soll maximales Target ergeben (minimale Difficulty)
        assert_eq!(bits >> 24, 0x20);
    }

    #[test]
    fn test_bits_target_small_exponents() {
        // Exponent 1: nur 1 Byte signifikant — vorher schrieb der Code das falsche Byte (b2 statt b0)
        let bits1   = 0x0100_007fu32; // exponent=1, mantissa=0x7f (b0=0x00, b1=0x00, b2=0x7f)
        let target1 = bits_to_target(bits1);
        // b0=0x00 geht an Position 31, b1 und b2 liegen außerhalb
        assert_eq!(target1[31], 0x00, "exponent=1: target[31] must be b0=0x00");

        // Exponent 2: 2 Bytes signifikant
        let bits2   = 0x0201_23ffu32; // exponent=2, mantissa=0x0123ff (b0=0x01, b1=0x23, b2=0xff)
        let target2 = bits_to_target(bits2);
        // b0=0x01 an Position 30, b1=0x23 an Position 31, b2 out-of-bounds
        assert_eq!(target2[30], 0x01, "exponent=2: target[30] must be b0=0x01");
        assert_eq!(target2[31], 0x23, "exponent=2: target[31] must be b1=0x23");

        // Roundtrip für exponent=2
        let back = bits_to_target(target_to_bits(&target2));
        assert_eq!(target2, back, "Roundtrip for exponent=2 must be stable");
    }

    #[test]
    fn test_mining_prefix_differs_by_nonce() {
        let mut header = Block::genesis().header;
        let p1 = header.mining_prefix();
        header.nonce = 99999;
        let p2 = header.mining_prefix();
        // Mining-Prefix ignoriert nonce → identisch
        assert_eq!(p1, p2);
    }
}
