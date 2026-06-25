//! Fee-Schätzung für Wallet-Nutzer
//!
//! Analysiert aktuelle Mempool-Lage und empfiehlt optimale Fees.

use crate::mempool::Mempool;

pub struct FeeEstimator<'a> {
    mempool: &'a Mempool,
}

#[derive(Debug, Clone)]
pub struct FeeRecommendation {
    /// Schnell (nächster Block): höchste aktuelle Mempool-Fee
    pub fast_atom:     u128,
    /// Standard (1-3 Blöcke): Durchschnitt
    pub standard_atom: u128,
    /// Günstig (eventually): Minimum
    pub low_atom:      u128,
    /// Absolutes Protokoll-Minimum
    pub min_atom:      u128,
    /// Protokoll-Maximum (Fee-Cap)
    pub max_atom:      u128,
}

impl<'a> FeeEstimator<'a> {
    pub fn new(mempool: &'a Mempool) -> Self {
        FeeEstimator { mempool }
    }

    pub fn recommend(&self) -> FeeRecommendation {
        let stats = self.mempool.stats();
        let p     = self.mempool.params();

        FeeRecommendation {
            fast_atom:     stats.max_fee_atom.max(p.min_fee_atom),
            standard_atom: stats.avg_fee_atom.max(p.min_fee_atom),
            low_atom:      stats.min_fee_atom.max(p.min_fee_atom),
            min_atom:      p.min_fee_atom,
            max_atom:      p.max_fee_atom,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_consensus::params::ConsensusParams;
    use crate::mempool::Mempool;

    #[test]
    fn test_fee_estimator_uses_protocol_params() {
        let params  = ConsensusParams::mainnet();
        let mempool = Mempool::new(params.clone());
        let est     = FeeEstimator::new(&mempool);
        let rec     = est.recommend();

        // Empty mempool: fast/standard/low all fall back to min
        assert_eq!(rec.min_atom, params.min_fee_atom);
        assert_eq!(rec.max_atom, params.max_fee_atom);
        assert_eq!(rec.fast_atom,     params.min_fee_atom);
        assert_eq!(rec.standard_atom, params.min_fee_atom);
        assert_eq!(rec.low_atom,      params.min_fee_atom);
    }
}
