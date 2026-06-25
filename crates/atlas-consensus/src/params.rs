//! Konsens-Parameter — unveränderliche Protokollregeln

use atlas_core::amount::Amount;

/// Alle unveränderlichen Konsens-Parameter von ATLAS
#[derive(Clone, Debug)]
pub struct ConsensusParams {
    // ── Zeitparameter ─────────────────────────────────────────────────────
    /// Ziel-Blockzeit in Sekunden
    pub target_block_time:    u64,
    /// Maximale Abweichung vom Ziel (Sekunden, Zukunft)
    pub max_future_time_secs: u64,

    // ── Emission ──────────────────────────────────────────────────────────
    /// Start-Subsidy: 200 ATL in ATOM
    pub initial_subsidy:      Amount,
    /// Blöcke pro Halving-Intervall (~4.75 Jahre)
    pub halving_interval:     u64,
    /// Maximale Anzahl Halvings (danach Subsidy = 0)
    pub max_halvings:         u32,

    // ── Reward-Verteilung ─────────────────────────────────────────────────
    /// Miner-Anteil in Basispunkten (7000 = 70 %)
    pub miner_share_bps:      u32,
    /// Prover/Aggregator-Anteil in Basispunkten (3000 = 30 %)
    pub prover_share_bps:     u32,

    // ── Gebühren ──────────────────────────────────────────────────────────
    /// Minimale TX-Gebühr in ATOM
    pub min_fee_atom:         u128,
    /// Maximale TX-Gebühr in ATOM (Fee-Cap)
    pub max_fee_atom:         u128,

    // ── Blockgröße ────────────────────────────────────────────────────────
    /// Maximale Anzahl Settlement-Batches pro Block
    pub max_batches_per_block: u8,
    /// Maximale TX-Anzahl pro Block
    pub max_txs_per_block:    usize,

    // ── Difficulty ────────────────────────────────────────────────────────
    /// Retarget-Intervall in Blöcken
    pub difficulty_adjustment_interval: u64,
    /// Maximale Difficulty-Änderung pro Retarget (Faktor 4)
    pub max_difficulty_change: u32,

    // ── Sicherheit ────────────────────────────────────────────────────────
    /// Anzahl Blöcke für Coinbase-Reife
    pub coinbase_maturity:    u64,
    /// Minimale Chain-Länge für Reorganisationsschutz
    pub min_confirmations:    u64,
    /// Netzwerk-Name: "mainnet" | "testnet" | "regtest"
    pub network:              &'static str,

    // ── L2 Forced Inclusion (Zensurresistenz) ─────────────────────────────
    /// Fälligkeitsfenster in Blöcken: ist eine on-chain Forced-TX älter,
    /// MUSS jedes Settlement die ältesten fälligen Einträge aufnehmen oder
    /// per Rejection-Zeuge nachweislich ablehnen — sonst ist der Block ungültig.
    pub forced_inclusion_window: u64,
}

impl ConsensusParams {
    pub fn mainnet() -> Self {
        ConsensusParams {
            target_block_time:    600,     // 10 Minuten
            max_future_time_secs: 7200,    // 2 Stunden
            initial_subsidy:      Amount::from_atl(200),
            halving_interval:     250_000, // ~4.75 Jahre
            max_halvings:         32,      // danach 0
            miner_share_bps:      7000,    // 70 %
            prover_share_bps:     3000,    // 30 %
            min_fee_atom:         10,
            max_fee_atom:         100,
            max_batches_per_block: 8,
            max_txs_per_block:    10_000,
            difficulty_adjustment_interval: 2016,
            max_difficulty_change: 4,
            coinbase_maturity:    100,
            min_confirmations:    6,
            network:              "mainnet",
            forced_inclusion_window: 30,   // 30 × 10 min = 5 h Schonfrist
        }
    }

    pub fn testnet() -> Self {
        let mut p = Self::mainnet();
        // Halving-Fenster halbiert (wie Mainnet 500k→250k), damit die geerbte
        // 200-ATL-Subsidy die Test-Supply konstant hält: 500 × 200 × 2 = 200.000 ATL.
        p.halving_interval             = 500;
        p.coinbase_maturity            = 10;
        p.min_confirmations            = 1;
        p.network                      = "testnet";
        // ── Skalierungs-Parameter für 40K TPS ─────────────────────────────
        // Ziel: 64 Batches × 2000 TXs / 3s = ~42.000 L2-TPS bestätigt
        p.target_block_time            = 3;          // 3 Sekunden statt 10 Minuten
        p.max_future_time_secs         = 120;        // 2 min statt 2 h — passend zur 3-s-Blockzeit
        p.max_batches_per_block        = 64;         // 8 → 64 Settlement-Batches/Block
        p.max_txs_per_block            = 200_000;    // 10K → 200K L1-TXs/Block
        p.max_fee_atom                 = 10_000;     // 100 → 10K ATOM Fee-Cap (Aggregator-Bids)
        p.difficulty_adjustment_interval = 144;      // Retarget alle ~7min statt alle 2016 Blöcke
        p.forced_inclusion_window      = 200;        // 200 × 3 s = 10 min Schonfrist
        p
    }

    pub fn regtest() -> Self {
        let mut p = Self::testnet();
        // ebenfalls halbiert (150→75): 75 × 200 × 2 = 30.000 ATL, konstante Regtest-Supply.
        p.halving_interval             = 75;
        p.coinbase_maturity            = 1;
        p.network                      = "regtest";
        p.target_block_time            = 1;          // 1 Sekunde für schnelle Tests
        p.difficulty_adjustment_interval = 10;       // Retarget alle 10 Blöcke
        p.forced_inclusion_window      = 5;          // kurz, für Tests
        p
    }

    /// Max Supply in ATOM: Summe aller Subsidy-Zahlungen
    /// = 200 * 250000 + 100 * 250000 + ... = 200 * 250000 * 2
    /// = 100.000.000 ATL
    pub fn max_supply(&self) -> Amount {
        let mut total = Amount::ZERO;
        let mut subsidy = self.initial_subsidy;
        for _ in 0..self.max_halvings {
            total += subsidy * self.halving_interval as u128;
            subsidy = subsidy / 2;
            if subsidy.is_zero() { break; }
        }
        total
    }

    /// Teilt einen Betrag in Miner- und Prover-Anteil auf
    pub fn split_reward(&self, total: Amount) -> (Amount, Amount) {
        let miner  = total * self.miner_share_bps as u128 / 10_000;
        let prover = total.saturating_sub(miner);
        (miner, prover)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_supply() {
        let params = ConsensusParams::mainnet();
        let supply = params.max_supply();
        println!("Max Supply: {} ATL", supply.as_atl_floor());
        // Sollte ~100.000.000 ATL sein
        assert!(supply.as_atl_floor() >= 99_000_000);
        assert!(supply.as_atl_floor() <= 101_000_000);
    }

    #[test]
    fn test_reward_split() {
        let params = ConsensusParams::mainnet();
        let reward = Amount::from_atl(64);
        let (miner, prover) = params.split_reward(reward);
        assert_eq!(miner.as_atl_floor(), 44);  // 70% von 64
        assert_eq!(prover.as_atl_floor(), 19); // 30% von 64 (Rundung)
        println!("Miner: {}, Prover: {}", miner, prover);
    }
}
