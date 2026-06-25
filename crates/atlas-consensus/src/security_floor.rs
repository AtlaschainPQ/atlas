//! Adaptiver Security Floor
//!
//! Wenn Fees zu niedrig → Subsidy-Reduktion automatisch verlangsamt.
//! Keine Governance nötig — algorithmisch, deterministisch.
//!
//! Das Protokoll speichert `delay_count` im Chain-State und übergibt
//! es bei jedem Halving-Übergang als Parameter.

use atlas_core::amount::Amount;
use atlas_core::block::BlockHeight;
use crate::params::ConsensusParams;
use serde::{Deserialize, Serialize};

/// Mindest-Sicherheitsbudget pro Block (in ATOM)
/// Wenn Fees + Subsidy darunter fallen, wird das Halving verzögert.
const MIN_SECURITY_BUDGET_ATOM: u128 = 1_000_000_000_000; // 1 ATL

/// Wie viele Halvings maximal verzögert werden können
const MAX_DELAY_HALVINGS: u32 = 3;

/// Zustand des Security Floors
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SecurityFloorState {
    /// Effektive Subsidy (kann höher sein als normale Halving-Kurve)
    pub effective_subsidy:  Amount,
    /// Wie oft das Halving bisher verzögert wurde (0..=MAX_DELAY_HALVINGS)
    pub delay_count:        u32,
    /// Durchschnittliche Fees der letzten N Blöcke
    pub avg_fees_per_block: Amount,
    /// Ist das Sicherheitsbudget gesund?
    pub security_healthy:   bool,
    /// Wurde das Halving in diesem Schritt verzögert?
    pub halving_delayed:    bool,
}

pub struct AdaptiveSecurityFloor<'a> {
    params: &'a ConsensusParams,
}

impl<'a> AdaptiveSecurityFloor<'a> {
    pub fn new(params: &'a ConsensusParams) -> Self {
        AdaptiveSecurityFloor { params }
    }

    /// Berechnet den effektiven Subsidy und ob das Halving verzögert wird.
    ///
    /// # Parameter
    /// - `height`:       Aktuelle Blockhöhe
    /// - `avg_fees`:     Gleitender Durchschnitt der Fees (letzte 2016 Blöcke)
    /// - `delay_count`:  Bisherige Anzahl an Verzögerungen (im Chain-State gespeichert)
    ///
    /// # Rückgabe
    /// `SecurityFloorState` mit dem effektiven Subsidy und ob `delay_count` inkrementiert werden muss.
    pub fn evaluate(
        &self,
        height:      BlockHeight,
        avg_fees:    Amount,
        delay_count: u32,
    ) -> SecurityFloorState {
        let era_u64         = height / self.params.halving_interval;
        let era             = era_u64.min(self.params.max_halvings as u64) as u32;
        let nominal_subsidy = self.params.initial_subsidy / (1u128 << era.min(31));
        let min_budget      = Amount::from_atom(MIN_SECURITY_BUDGET_ATOM);
        // Check fee income alone: once subsidies reach zero, fees must sustain security.
        // Delaying a halving gives fee markets more time to mature.
        let security_healthy = avg_fees >= min_budget;

        // Halving verzögern wenn: Budget zu niedrig UND Verzögerungslimit nicht erreicht
        let should_delay = !security_healthy && delay_count < MAX_DELAY_HALVINGS;

        let effective_subsidy = if should_delay && era > 0 {
            // Subsidy bleibt auf vorheriger Era (halbieren rückgängig)
            self.params.initial_subsidy / (1u128 << (era - 1).min(31))
        } else {
            nominal_subsidy
        };

        SecurityFloorState {
            effective_subsidy,
            delay_count: if should_delay { delay_count + 1 } else { delay_count },
            avg_fees_per_block: avg_fees,
            security_healthy,
            halving_delayed: should_delay,
        }
    }

    /// Berechnet gleitenden Durchschnitt der Fees über ein Fenster
    pub fn compute_avg_fees(fee_history: &[Amount]) -> Amount {
        if fee_history.is_empty() { return Amount::ZERO; }
        let total = fee_history.iter().fold(Amount::ZERO, |acc, &f| acc + f);
        total / fee_history.len() as u128
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_floor_healthy_no_delay() {
        let params = ConsensusParams::mainnet();
        let floor  = AdaptiveSecurityFloor::new(&params);

        // 10 ATL durchschnittliche Fees → Budget gesund
        let high_fees = Amount::from_atl(10);
        let state = floor.evaluate(500_000, high_fees, 0);

        assert!(state.security_healthy);
        assert!(!state.halving_delayed);
        assert_eq!(state.delay_count, 0);
        // height 500_000 → Era 2 (Intervall 250_000): nominal 200/4 = 50 ATL
        assert_eq!(state.effective_subsidy.as_atl_floor(), 50);
    }

    #[test]
    fn test_security_floor_delays_halving_when_fees_low() {
        let params = ConsensusParams::mainnet();
        let floor  = AdaptiveSecurityFloor::new(&params);

        // Nur 100 ATOM avg → Budget weit unter 1 ATL
        let low_fees = Amount::from_atom(100);
        let state    = floor.evaluate(500_000, low_fees, 0);

        assert!(!state.security_healthy);
        assert!(state.halving_delayed, "Halving should be delayed with low fees");
        assert_eq!(state.delay_count, 1, "delay_count should be incremented");
        // Halving verzögert → Subsidy bleibt auf vorheriger Era (Era 1: 200/2 = 100 ATL)
        assert_eq!(state.effective_subsidy.as_atl_floor(), 100,
            "Subsidy should stay at previous era level when halving is delayed");
    }

    #[test]
    fn test_security_floor_max_delay_not_exceeded() {
        let params = ConsensusParams::mainnet();
        let floor  = AdaptiveSecurityFloor::new(&params);
        let low_fees = Amount::from_atom(100);

        // Nach MAX_DELAY_HALVINGS (3) Verzögerungen: keine weitere Verzögerung
        let state = floor.evaluate(500_000, low_fees, MAX_DELAY_HALVINGS);

        assert!(!state.halving_delayed,
            "Delay should stop after MAX_DELAY_HALVINGS");
        assert_eq!(state.delay_count, MAX_DELAY_HALVINGS,
            "delay_count should not exceed maximum");
        // Subsidy muss auf aktuellem Era-Level sein (normal halving, Era 2: 200/4 = 50)
        assert_eq!(state.effective_subsidy.as_atl_floor(), 50);
    }

    #[test]
    fn test_security_floor_era0_cannot_delay_up() {
        let params   = ConsensusParams::mainnet();
        let floor    = AdaptiveSecurityFloor::new(&params);
        let low_fees = Amount::from_atom(100);

        // In Era 0 (height = 0): Halving kann nicht verzögert werden (kein "vorheriges" Level)
        let state = floor.evaluate(0, low_fees, 0);
        // Era 0: era = 0, should_delay = true, aber era > 0 ist false → bleibt bei nominal (200 ATL)
        assert_eq!(state.effective_subsidy.as_atl_floor(), 200);
    }

    #[test]
    fn test_avg_fees_empty_history() {
        assert_eq!(
            AdaptiveSecurityFloor::compute_avg_fees(&[]),
            Amount::ZERO
        );
    }

    #[test]
    fn test_avg_fees_calculation() {
        let fees = vec![
            Amount::from_atl(10),
            Amount::from_atl(20),
            Amount::from_atl(30),
        ];
        let avg = AdaptiveSecurityFloor::compute_avg_fees(&fees);
        assert_eq!(avg.as_atl_floor(), 20);
    }
}
