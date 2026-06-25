//! ATLAS dreistufiges Währungssystem
//!
//! 1 ATL  = 1_000_000_000_000 ATOM  (10^12)
//! 1 UNIT =        10_000     ATOM  (10^4)
//! 1 ATL  =   100_000_000    UNIT  (10^8)
//!
//! Alle internen Berechnungen erfolgen in ATOM (u128).

use std::fmt;
use std::ops::{Add, Sub, Mul, Div, AddAssign, SubAssign};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ATOM_PER_UNIT: u128 = 10_000;
pub const ATOM_PER_ATL:  u128 = 1_000_000_000_000;
pub const UNIT_PER_ATL:  u128 = 100_000_000;

/// Type-Aliases für Klarheit im Code
pub type ATL  = Amount;
pub type UNIT = Amount;
pub type ATOM = Amount;

#[derive(Error, Debug)]
pub enum AmountError {
    #[error("Arithmetic overflow")]
    Overflow,
    #[error("Arithmetic underflow (negative result)")]
    Underflow,
    #[error("Division by zero")]
    DivisionByZero,
}

/// Geldmenge in ATOM (atomare Einheit, 10^-12 ATL)
/// Interner Wert ist stets u128 in ATOM.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord,
    Serialize, Deserialize, Default, Hash,
)]
pub struct Amount(pub u128);

impl Amount {
    pub const ZERO: Self = Amount(0);
    pub const MAX:  Self = Amount(u128::MAX);

    // ── Konstruktoren ──────────────────────────────────────────────────────

    /// Erstellt einen Betrag aus ATL.
    pub fn from_atl(atl: u128) -> Self {
        Amount(atl * ATOM_PER_ATL)
    }

    /// Erstellt einen Betrag aus UNIT.
    pub fn from_unit(unit: u128) -> Self {
        Amount(unit * ATOM_PER_UNIT)
    }

    /// Erstellt einen Betrag direkt aus ATOM.
    pub fn from_atom(atom: u128) -> Self {
        Amount(atom)
    }

    // ── Konversionen ───────────────────────────────────────────────────────

    pub fn as_atom(&self) -> u128 { self.0 }

    pub fn as_unit_floor(&self) -> u128 { self.0 / ATOM_PER_UNIT }

    pub fn as_atl_floor(&self) -> u128 { self.0 / ATOM_PER_ATL }

    /// Gibt den Wert als dezimale ATL-Darstellung zurück: "12.345678901234"
    pub fn as_atl_decimal(&self) -> String {
        let whole  = self.0 / ATOM_PER_ATL;
        let frac   = self.0 % ATOM_PER_ATL;
        format!("{}.{:012}", whole, frac)
    }

    // ── Geprüfte Arithmetik ────────────────────────────────────────────────

    pub fn checked_add(self, rhs: Self) -> Result<Self, AmountError> {
        self.0.checked_add(rhs.0)
            .map(Amount)
            .ok_or(AmountError::Overflow)
    }

    pub fn checked_sub(self, rhs: Self) -> Result<Self, AmountError> {
        self.0.checked_sub(rhs.0)
            .map(Amount)
            .ok_or(AmountError::Underflow)
    }

    pub fn checked_mul(self, rhs: u128) -> Result<Self, AmountError> {
        self.0.checked_mul(rhs)
            .map(Amount)
            .ok_or(AmountError::Overflow)
    }

    pub fn saturating_add(self, rhs: Self) -> Self {
        Amount(self.0.saturating_add(rhs.0))
    }

    pub fn saturating_sub(self, rhs: Self) -> Self {
        Amount(self.0.saturating_sub(rhs.0))
    }

    pub fn is_zero(&self) -> bool { self.0 == 0 }
}

impl Add for Amount {
    type Output = Self;
    fn add(self, rhs: Self) -> Self { Amount(self.0.saturating_add(rhs.0)) }
}

impl Sub for Amount {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self { Amount(self.0.saturating_sub(rhs.0)) }
}

impl Mul<u128> for Amount {
    type Output = Self;
    fn mul(self, rhs: u128) -> Self { Amount(self.0.saturating_mul(rhs)) }
}

impl Div<u128> for Amount {
    type Output = Self;
    fn div(self, rhs: u128) -> Self {
        if rhs == 0 { return Amount::ZERO; }
        Amount(self.0 / rhs)
    }
}

impl AddAssign for Amount {
    fn add_assign(&mut self, rhs: Self) { self.0 = self.0.saturating_add(rhs.0); }
}

impl SubAssign for Amount {
    fn sub_assign(&mut self, rhs: Self) { self.0 = self.0.saturating_sub(rhs.0); }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ATL ({})", self.as_atl_decimal(), self.0)
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Amount({} ATOM = {})", self.0, self.as_atl_decimal())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversions() {
        let one_atl = Amount::from_atl(1);
        assert_eq!(one_atl.as_atom(), 1_000_000_000_000);
        assert_eq!(one_atl.as_unit_floor(), 100_000_000);
        assert_eq!(one_atl.as_atl_decimal(), "1.000000000000");
    }

    #[test]
    fn test_arithmetic() {
        let a = Amount::from_atl(10);
        let b = Amount::from_atl(5);
        assert_eq!((a + b).as_atl_floor(), 15);
        assert_eq!((a - b).as_atl_floor(), 5);
    }

    #[test]
    fn test_small_fee() {
        // 100 ATOM Fee
        let fee = Amount::from_atom(100);
        println!("Fee: {} ATOM", fee.as_atom());

        // Bei 10 Mio € / ATL: 100 ATOM * 10_000_000 € / 1_000_000_000_000 ATOM = 0.001 €
        // In Nano-Euro (10^-9): 100 * 10_000_000 * 1_000 / 10^12 = 1000 nEuro = 1 µ€
        let atl_price_eur = 10_000_000u128;
        // fee_eur_nano = fee_atom * price / ATOM_PER_ATL * 1_000_000_000
        let fee_eur_nano = fee.as_atom() * atl_price_eur * 1_000_000_000 / ATOM_PER_ATL;
        // 100 * 10_000_000 * 1_000_000_000 / 1_000_000_000_000 = 100 * 10_000_000 / 1000 = 1_000_000 nEuro = 0,001 €
        assert_eq!(fee_eur_nano, 1_000_000, "100 ATOM bei 10 Mio €/ATL = 0.001 € = 1M nEuro");
        println!("100 ATOM @ 10M€/ATL = {:.6} €", fee_eur_nano as f64 / 1_000_000_000.0);
    }

    #[test]
    fn test_max_supply() {
        // Max Supply = 26_910_720 ATL
        let max_supply = Amount::from_atl(26_910_720);
        assert_eq!(max_supply.as_atl_floor(), 26_910_720);
        println!("Max Supply: {}", max_supply);
    }
}
