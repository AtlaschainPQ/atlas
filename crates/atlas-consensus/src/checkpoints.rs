//! Hardcodierte Checkpoints gegen Long-Range-Angriffe
//!
//! Ein Checkpoint bei Höhe H bedeutet: Jeder Block der H erreicht
//! MUSS den dort gespeicherten Hash haben. Angreifer können keine
//! alternative Chain unter diesem Checkpoint aufbauen.

use atlas_core::hash::Hash;

/// Ein Checkpoint: (Höhe, Block-Hash als Hex-String)
pub struct Checkpoint {
    pub height: u64,
    pub hash:   &'static str,
}

/// Mainnet-Checkpoints
/// Genesis-Hash: deterministisch aus Block::genesis() berechnet.
/// Weitere Checkpoints werden nach dem Launch (alle ~10.000 Blöcke) hinzugefügt.
pub const MAINNET_CHECKPOINTS: &[Checkpoint] = &[
    Checkpoint {
        height: 0,
        hash: "2e10617270dd94a024d8c80ab3cf7a228a9978c939d7b2594627b99700bfe816",
    },
];

pub const TESTNET_CHECKPOINTS: &[Checkpoint] = &[];

pub const REGTEST_CHECKPOINTS: &[Checkpoint] = &[];

/// Prüft ob der gegebene Block-Hash dem Checkpoint bei dieser Höhe entspricht.
/// Gibt `Ok(())` zurück wenn kein Checkpoint existiert oder der Hash stimmt.
/// Gibt `Err(expected_hash)` zurück wenn der Hash abweicht.
pub fn verify_checkpoint(
    network:     &str,
    height:      u64,
    actual_hash: &Hash,
) -> Result<(), String> {
    let checkpoints = match network {
        "testnet" => TESTNET_CHECKPOINTS,
        "regtest" => REGTEST_CHECKPOINTS,
        _         => MAINNET_CHECKPOINTS,
    };

    for cp in checkpoints {
        if cp.height == height {
            let expected = match parse_hex_hash(cp.hash) {
                Some(h) => h,
                None    => continue, // fehlerhafter Checkpoint — ignorieren
            };
            if actual_hash != &expected {
                return Err(format!(
                    "Checkpoint mismatch at height {}: expected={} got={}",
                    height, cp.hash, actual_hash.as_hex()
                ));
            }
            return Ok(());
        }
    }
    Ok(())
}

fn parse_hex_hash(s: &str) -> Option<Hash> {
    Hash::from_hex(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_core::block::Block;

    /// Stellt sicher, dass der Mainnet-Genesis-Checkpoint zum tatsächlichen
    /// Genesis-Block-Hash passt. Schlägt dieser Test fehl, muss
    /// `MAINNET_CHECKPOINTS[0].hash` aktualisiert werden.
    #[test]
    fn test_genesis_checkpoint_matches_actual_block() {
        let actual   = Block::genesis().hash().as_hex();
        let expected = MAINNET_CHECKPOINTS[0].hash;
        assert_eq!(
            actual.as_str(), expected,
            "\nGenesis-Checkpoint stimmt nicht mit dem tatsächlichen Genesis-Hash überein!\
             \n  Tatsächlich: {}\
             \n  Checkpoint:  {}\
             \n  Aktualisiere MAINNET_CHECKPOINTS[0].hash in checkpoints.rs",
            actual, expected,
        );
    }

    #[test]
    fn test_no_checkpoint_at_unknown_height() {
        assert!(verify_checkpoint("mainnet", 999, &atlas_core::hash::Hash::zero()).is_ok());
    }

    #[test]
    fn test_checkpoint_wrong_hash_rejected() {
        let wrong = atlas_core::hash::Hash::sha256(b"wrong");
        let result = verify_checkpoint("mainnet", 0, &wrong);
        assert!(result.is_err(), "Falscher Hash bei Höhe 0 muss abgelehnt werden");
    }

    #[test]
    fn test_checkpoint_correct_hash_accepted() {
        let genesis_hash = Block::genesis().hash();
        assert!(verify_checkpoint("mainnet", 0, &genesis_hash).is_ok());
    }
}
