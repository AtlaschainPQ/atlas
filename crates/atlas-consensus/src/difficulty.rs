//! Difficulty-Anpassung
//!
//! Alle 2016 Blöcke (~2 Wochen), wie Bitcoin.
//! Maximale Änderung: Faktor 4 (×4 oder ÷4).
//! Ziel: 600 Sekunden Blockzeit.

use atlas_core::block::{bits_to_target, target_to_bits, BlockHeight};
use crate::params::ConsensusParams;
use num_bigint::BigUint;
use num_traits::Zero;

pub struct DifficultyAdjuster<'a> {
    params: &'a ConsensusParams,
}

impl<'a> DifficultyAdjuster<'a> {
    pub fn new(params: &'a ConsensusParams) -> Self {
        DifficultyAdjuster { params }
    }

    /// Berechnet neue Difficulty nach einem Retarget-Intervall
    ///
    /// actual_time:   tatsächlich vergangene Zeit (Sekunden) für die letzten N Blöcke
    /// current_bits:  aktuelle kompakte Difficulty des letzten Blocks
    pub fn retarget(&self, current_bits: u32, actual_time: u64) -> u32 {
        let target_time = self.params.target_block_time
            .saturating_mul(self.params.difficulty_adjustment_interval);

        // Clamp: maximal 4× schneller oder langsamer als Ziel
        let actual_clamped = actual_time
            .max(target_time / self.params.max_difficulty_change as u64)
            .min(target_time.saturating_mul(self.params.max_difficulty_change as u64));

        let old_target = bits_to_target(current_bits);
        let new_target = self.scale_target(&old_target, actual_clamped, target_time);
        target_to_bits(&new_target)
    }

    /// Skaliert das Target mit BigUint für exakte 256-Bit-Arithmetik
    fn scale_target(
        &self,
        target:      &[u8; 32],
        actual_time: u64,
        target_time: u64,
    ) -> [u8; 32] {
        if target_time == 0 { return *target; }

        let t     = BigUint::from_bytes_be(target);
        let scaled = t * actual_time / target_time;

        // Maximales Target: 2^224 - 1 (entspricht Difficulty 1)
        let max_target = BigUint::from_bytes_be(&{
            let mut m = [0xffu8; 32];
            m[0] = 0x00;
            m[1] = 0x00;
            m[2] = 0x00;
            m
        });
        let bounded = scaled.min(max_target);

        let bytes = bounded.to_bytes_be();
        let mut result = [0u8; 32];
        if bytes.len() <= 32 {
            result[32 - bytes.len()..].copy_from_slice(&bytes);
        } else {
            // Overflow → minimale Difficulty (Maximum-Target)
            result[3] = 0xff;
            result[4] = 0xff;
            result[5] = 0xff;
        }
        result
    }

    /// Prüft ob an dieser Höhe ein Retarget stattfindet
    pub fn is_retarget_block(&self, height: BlockHeight) -> bool {
        height > 0 && height.is_multiple_of(self.params.difficulty_adjustment_interval)
    }

    /// Berechnet die aktuelle Hashrate-Schätzung (H/s)
    pub fn estimate_hashrate(
        &self,
        bits:        u32,
        actual_time: u64,
        block_count: u64,
    ) -> f64 {
        if actual_time == 0 || block_count == 0 { return 0.0; }
        let difficulty = self.target_to_difficulty(bits);
        // Hashrate = Difficulty * 2^32 / avg_block_time
        // (vereinfacht, echte Formel: difficulty * 2^48 / target_block_time)
        difficulty * (1u64 << 32) as f64 / (actual_time / block_count) as f64
    }

    /// Konvertiert Bits in Difficulty-Zahl relativ zu Difficulty-1-Target
    pub fn target_to_difficulty(&self, bits: u32) -> f64 {
        // Difficulty-1 Target (Bitcoin: 0x1d00ffff)
        let difficulty_one = bits_to_target(0x1d00_ffffu32);
        let max = BigUint::from_bytes_be(&difficulty_one);
        let cur = BigUint::from_bytes_be(&bits_to_target(bits));
        if cur == BigUint::zero() { return f64::INFINITY; }

        // Verhältnis als Float (verlustbehaftet aber ausreichend)
        let max_f: f64 = max.to_string().parse().unwrap_or(1.0);
        let cur_f: f64 = cur.to_string().parse().unwrap_or(1.0);
        max_f / cur_f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_params() -> ConsensusParams {
        ConsensusParams::mainnet()
    }

    #[test]
    fn test_retarget_exact_timing_no_change() {
        let params   = make_params();
        let adjuster = DifficultyAdjuster::new(&params);
        let bits     = 0x1d00_ffffu32;

        let target_time = params.target_block_time * params.difficulty_adjustment_interval;
        let new_bits    = adjuster.retarget(bits, target_time);

        // Bei exakter Zielzeit: Target bleibt identisch
        let old_target = bits_to_target(bits);
        let new_target = bits_to_target(new_bits);
        assert_eq!(old_target, new_target,
            "Perfect timing should not change difficulty");
    }

    #[test]
    fn test_retarget_double_speed_increases_difficulty() {
        let params   = make_params();
        let adjuster = DifficultyAdjuster::new(&params);
        let bits     = 0x1d00_ffffu32;

        let target_time = params.target_block_time * params.difficulty_adjustment_interval;
        // Blöcke kamen doppelt so schnell → Difficulty muss steigen → Target sinkt
        let new_bits   = adjuster.retarget(bits, target_time / 2);
        let old_target = bits_to_target(bits);
        let new_target = bits_to_target(new_bits);

        assert!(new_target < old_target,
            "Faster blocks should increase difficulty (lower target)");
    }

    #[test]
    fn test_retarget_half_speed_decreases_difficulty() {
        let params   = make_params();
        let adjuster = DifficultyAdjuster::new(&params);
        let bits     = 0x1d00_ffffu32;

        let target_time = params.target_block_time * params.difficulty_adjustment_interval;
        // Blöcke kamen halb so schnell → Difficulty muss sinken → Target steigt
        let new_bits   = adjuster.retarget(bits, target_time * 2);
        let old_target = bits_to_target(bits);
        let new_target = bits_to_target(new_bits);

        assert!(new_target > old_target,
            "Slower blocks should decrease difficulty (higher target)");
    }

    #[test]
    fn test_retarget_clamped_at_4x() {
        let params   = make_params();
        let adjuster = DifficultyAdjuster::new(&params);
        let bits     = 0x1d00_ffffu32;

        let target_time = params.target_block_time * params.difficulty_adjustment_interval;
        // 10× langsamer → wird auf 4× geclampt
        let bits_10x_slow = adjuster.retarget(bits, target_time * 10);
        let bits_4x_slow  = adjuster.retarget(bits, target_time * 4);

        let target_10x = bits_to_target(bits_10x_slow);
        let target_4x  = bits_to_target(bits_4x_slow);
        assert_eq!(target_10x, target_4x,
            "Clamping at 4x should prevent extreme difficulty drop");
    }

    #[test]
    fn test_retarget_clamped_at_quarter() {
        let params   = make_params();
        let adjuster = DifficultyAdjuster::new(&params);
        let bits     = 0x1d00_ffffu32;

        let target_time = params.target_block_time * params.difficulty_adjustment_interval;
        // 10× schneller → wird auf 4× geclampt
        let bits_10x_fast = adjuster.retarget(bits, target_time / 10);
        let bits_4x_fast  = adjuster.retarget(bits, target_time / 4);

        let target_10x = bits_to_target(bits_10x_fast);
        let target_4x  = bits_to_target(bits_4x_fast);
        assert_eq!(target_10x, target_4x,
            "Clamping at 1/4 should prevent extreme difficulty spike");
    }

    #[test]
    fn test_is_retarget_block() {
        let params   = make_params();
        let adjuster = DifficultyAdjuster::new(&params);

        assert!(!adjuster.is_retarget_block(0));     // Genesis: kein Retarget
        assert!(!adjuster.is_retarget_block(1));
        assert!(!adjuster.is_retarget_block(2015));
        assert!(adjuster.is_retarget_block(2016));
        assert!(!adjuster.is_retarget_block(2017));
        assert!(adjuster.is_retarget_block(4032));
    }

    #[test]
    fn test_difficulty_1_target() {
        let params   = make_params();
        let adjuster = DifficultyAdjuster::new(&params);
        let d1       = adjuster.target_to_difficulty(0x1d00_ffffu32);
        // Difficulty-1-Target verglichen mit sich selbst = 1.0
        assert!((d1 - 1.0).abs() < 0.001,
            "Difficulty-1 target should have difficulty ~1.0, got {}", d1);
    }

    #[test]
    fn test_difficulty_zero_target_is_infinite() {
        let params   = make_params();
        let adjuster = DifficultyAdjuster::new(&params);
        // Target = 0 (unmöglich zu minen) = unendliche Difficulty
        let bits = target_to_bits(&[0u8; 32]);
        // Der Wert hängt von target_to_bits ab; wir prüfen nur dass kein Panic passiert
        let _ = adjuster.target_to_difficulty(bits);
    }

    #[test]
    fn test_retarget_zero_actual_time_no_panic() {
        let params   = make_params();
        let adjuster = DifficultyAdjuster::new(&params);
        // actual_time = 0 → wird auf target_time/4 geclampt (nicht 0 Division)
        let bits     = 0x1d00_ffffu32;
        let _new_bits = adjuster.retarget(bits, 0);
        // Kein Panic
    }
}
