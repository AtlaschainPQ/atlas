//! Reward-Berechnung: Subsidy + Fees, 70/30 Split

use atlas_core::amount::Amount;
use atlas_core::block::BlockHeight;
use atlas_core::transaction::Transaction;
use crate::params::ConsensusParams;
use serde::{Deserialize, Serialize};

/// Vollständige Reward-Aufschlüsselung für einen Block
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockReward {
    pub subsidy:       Amount,
    pub total_fees:    Amount,
    pub total:         Amount,
    pub miner_reward:  Amount,
    pub prover_reward: Amount,
    pub era:           u32,
}

pub struct RewardSchedule<'a> {
    params: &'a ConsensusParams,
}

impl<'a> RewardSchedule<'a> {
    pub fn new(params: &'a ConsensusParams) -> Self {
        RewardSchedule { params }
    }

    /// Berechnet die Subsidy für eine Blockhöhe.
    /// Sₑ = 64 / 2^e ATL (era e startet bei 0)
    ///
    /// Bug-Fix: Cast auf u64 vor Vergleich, um u32-Overflow bei extrem hohen Heights zu vermeiden.
    pub fn subsidy_at(&self, height: BlockHeight) -> Amount {
        let era_u64 = height / self.params.halving_interval;
        // Erst vergleichen, dann casten — verhindert Overflow-Bug
        if era_u64 >= self.params.max_halvings as u64 {
            return Amount::ZERO;
        }
        let era = era_u64 as u32;
        // 1u128 << era: sicher, weil max_halvings = 32 → max shift = 31
        self.params.initial_subsidy / (1u128 << era)
    }

    /// Aktuelle Era an einer Blockhöhe (gesichert gegen Overflow)
    pub fn era_at(&self, height: BlockHeight) -> u32 {
        let era_u64 = height / self.params.halving_interval;
        era_u64.min(self.params.max_halvings as u64) as u32
    }

    /// Nächste Halving-Höhe
    pub fn next_halving(&self, height: BlockHeight) -> BlockHeight {
        let current_era = height / self.params.halving_interval;
        (current_era + 1).saturating_mul(self.params.halving_interval)
    }

    /// Blöcke bis zum nächsten Halving
    pub fn blocks_to_halving(&self, height: BlockHeight) -> u64 {
        self.next_halving(height).saturating_sub(height)
    }

    /// Berechnet den vollständigen Block-Reward
    pub fn block_reward(
        &self,
        height:       BlockHeight,
        transactions: &[Transaction],
    ) -> BlockReward {
        let subsidy    = self.subsidy_at(height);
        // Nur FUNDIERTE Fees zählen: bei normalen TXs ist die Fee durch
        // inputs − outputs gedeckt (Coinbase prägt sie konservationsneutral
        // neu). Pseudo-Input-TXs (SettlementBid, L2ForcedTx) zahlen ihre
        // deklarierte Fee von niemandem — sie mitzuzählen wäre ungedeckte
        // Inflation über die Coinbase.
        let total_fees = transactions.iter()
            .filter(|tx| !tx.is_coinbase() && !tx.has_pseudo_inputs())
            .fold(Amount::ZERO, |acc, tx| acc + tx.fee);
        let total  = subsidy + total_fees;
        let (miner_reward, prover_reward) = self.params.split_reward(total);
        let era    = self.era_at(height);

        BlockReward { subsidy, total_fees, total, miner_reward, prover_reward, era }
    }

    /// Projizierte Emissions-Tabelle
    pub fn emission_table(&self) -> Vec<(u32, BlockHeight, Amount)> {
        let mut table   = Vec::new();
        let mut subsidy = self.params.initial_subsidy;
        for era in 0..self.params.max_halvings {
            if subsidy.is_zero() { break; }
            let start = era as u64 * self.params.halving_interval;
            table.push((era, start, subsidy));
            subsidy = subsidy / 2;
        }
        table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inflations-Schutz: deklarierte Fees von Pseudo-Input-TXs (SettlementBid,
    /// L2ForcedTx) sind UNFUNDIERT und dürfen die Coinbase nicht erhöhen.
    #[test]
    fn test_block_reward_ignores_unfunded_pseudo_fees() {
        use atlas_core::hash::Hash;
        use atlas_core::transaction::Transaction;
        use atlas_core::crypto::Address;

        let params   = ConsensusParams::mainnet();
        let schedule = RewardSchedule::new(&params);

        let mut bid = Transaction::new_settlement_bid(
            Hash::zero(), Address([1u8; 20]), Amount::from_atom(50),
            Hash::zero(), Hash::zero(), Hash::zero(), 0,
            Vec::new(), Vec::new(), Vec::new(),
        );
        bid.fee = Amount::from_atom(10);
        let mut forced = Transaction::new_l2_forced_tx(
            [2u8; 20], [3u8; 20], 100, 5, 0, [0u8; 32], vec![0u8; 64], 1,
        );
        forced.fee = Amount::from_atom(10);

        let coinbase = Transaction::new_coinbase(
            1, Amount::from_atom(70), Amount::from_atom(30),
            Address([9u8; 20]), Address([9u8; 20]),
        );
        let reward = schedule.block_reward(1, &[coinbase, bid.clone(), forced]);
        assert_eq!(reward.total_fees, Amount::ZERO,
            "unfundierte Pseudo-Input-Fees dürfen nicht in die Coinbase fließen");

        // Und der Bid-Marker-Output darf keinen Wert tragen (keine Geldschöpfung).
        assert!(bid.total_output().is_zero(),
            "SettlementBid-Outputs müssen wertlos sein (Pseudo-Inputs decken nichts)");
    }

    #[test]
    fn test_subsidy_era0() {
        let params   = ConsensusParams::mainnet();
        let schedule = RewardSchedule::new(&params);
        assert_eq!(schedule.subsidy_at(0).as_atl_floor(), 200);
        assert_eq!(schedule.subsidy_at(1).as_atl_floor(), 200);
        assert_eq!(schedule.subsidy_at(249_999).as_atl_floor(), 200);
    }

    #[test]
    fn test_subsidy_halving_sequence() {
        let params   = ConsensusParams::mainnet();
        let schedule = RewardSchedule::new(&params);

        assert_eq!(schedule.subsidy_at(0).as_atl_floor(),         200);
        assert_eq!(schedule.subsidy_at(250_000).as_atl_floor(),   100);
        assert_eq!(schedule.subsidy_at(500_000).as_atl_floor(),    50);
        assert_eq!(schedule.subsidy_at(750_000).as_atl_floor(),    25);
        assert_eq!(schedule.subsidy_at(1_000_000).as_atl_floor(),  12);
        assert_eq!(schedule.subsidy_at(1_250_000).as_atl_floor(),   6);
        assert_eq!(schedule.subsidy_at(1_500_000).as_atl_floor(),   3);
    }

    #[test]
    fn test_subsidy_after_max_halvings_is_zero() {
        let params   = ConsensusParams::mainnet();
        let schedule = RewardSchedule::new(&params);
        // Nach max_halvings (32) muss Subsidy 0 sein
        let height_after = 32u64 * 250_000 + 1;
        assert_eq!(schedule.subsidy_at(height_after), Amount::ZERO);
    }

    #[test]
    fn test_subsidy_no_overflow_at_max_height() {
        let params   = ConsensusParams::mainnet();
        let schedule = RewardSchedule::new(&params);
        // u64::MAX height darf nicht paniken
        assert_eq!(schedule.subsidy_at(u64::MAX), Amount::ZERO);
    }

    #[test]
    fn test_max_supply_100m_atl() {
        let params = ConsensusParams::mainnet();
        let supply  = params.max_supply();
        let atl     = supply.as_atl_floor();
        // Spec: 100.000.000 ATL
        assert!(atl >= 99_000_000, "Max supply too low: {} ATL", atl);
        assert!(atl <= 101_000_000, "Max supply too high: {} ATL", atl);
        println!("Max supply: {} ATL", atl);
    }

    #[test]
    fn test_reward_split_70_30() {
        let params   = ConsensusParams::mainnet();
        let total    = Amount::from_atl(100);
        let (miner, prover) = params.split_reward(total);
        // 70 ATL miner, 30 ATL prover
        assert_eq!(miner.as_atl_floor(), 70);
        assert_eq!(prover.as_atl_floor(), 30);
        // Summe muss exakt total ergeben
        assert_eq!(miner + prover, total);
    }

    #[test]
    fn test_reward_split_preserves_total() {
        let params = ConsensusParams::mainnet();
        for atl in [1u128, 64, 1000, 999_999_999] {
            let total = Amount::from_atl(atl);
            let (miner, prover) = params.split_reward(total);
            assert_eq!(miner + prover, total,
                "Reward split must sum to total for {} ATL", atl);
        }
    }

    #[test]
    fn test_next_halving() {
        let params   = ConsensusParams::mainnet();
        let schedule = RewardSchedule::new(&params);
        assert_eq!(schedule.next_halving(0),         250_000);
        assert_eq!(schedule.next_halving(100_000),   250_000);
        assert_eq!(schedule.next_halving(249_999),   250_000);
        assert_eq!(schedule.next_halving(250_000),   500_000);
    }

    #[test]
    fn test_block_reward_with_fees() {
        let params   = ConsensusParams::mainnet();
        let schedule = RewardSchedule::new(&params);
        let txs: Vec<Transaction> = vec![];
        let reward = schedule.block_reward(0, &txs);
        assert_eq!(reward.subsidy.as_atl_floor(), 200);
        assert_eq!(reward.total_fees, Amount::ZERO);
        assert_eq!(reward.total.as_atl_floor(), 200);
        assert_eq!(reward.miner_reward + reward.prover_reward, reward.total);
    }

    #[test]
    fn test_emission_table_coverage() {
        let params   = ConsensusParams::mainnet();
        let schedule = RewardSchedule::new(&params);
        let table    = schedule.emission_table();
        assert!(!table.is_empty());
        // Erste Era hat 200 ATL
        assert_eq!(table[0].2.as_atl_floor(), 200);
        // Jede Era hat halbe Subsidy der vorherigen
        for i in 1..table.len() {
            let prev = table[i-1].2;
            let curr = table[i].2;
            assert_eq!(curr, prev / 2, "Era {} subsidy should be half of era {}", i, i-1);
        }
    }
}
