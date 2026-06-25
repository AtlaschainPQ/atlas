/**
 * ATLAS Währungssystem
 *
 * 1 ATL  = 1_000_000_000_000 ATOM  (10^12)
 * 1 UNIT =        10_000     ATOM  (10^4)
 * 1 ATL  =   100_000_000     UNIT  (10^8)
 *
 * Alle internen Berechnungen in ATOM (BigInt).
 */

export const ATOM_PER_UNIT = 10_000n;
export const ATOM_PER_ATL  = 1_000_000_000_000n;
export const UNIT_PER_ATL  = 100_000_000n;

/** Minimale TX-Fee (Protokoll) */
export const MIN_FEE_ATOM  = 10n;
/** Maximale TX-Fee / Fee-Cap */
export const MAX_FEE_ATOM  = 100n;

export class Amount {
  /** Interner Wert in ATOM */
  readonly atom: bigint;

  private constructor(atom: bigint) {
    if (atom < 0n) throw new Error(`Amount cannot be negative: ${atom}`);
    this.atom = atom;
  }

  // ── Konstruktoren ──────────────────────────────────────────────────────────

  static fromAtom(atom: bigint): Amount {
    return new Amount(atom);
  }

  static fromUnit(unit: bigint): Amount {
    return new Amount(unit * ATOM_PER_UNIT);
  }

  static fromAtl(atl: bigint): Amount {
    return new Amount(atl * ATOM_PER_ATL);
  }

  static zero(): Amount {
    return new Amount(0n);
  }

  static fromString(s: string): Amount {
    // Erwartet: "12.345678901234" (ATL mit bis zu 12 Dezimalstellen)
    const parts = s.split('.');
    const whole = BigInt(parts[0] || '0');
    let frac    = (parts[1] || '').padEnd(12, '0').slice(0, 12);
    const fracBig = BigInt(frac);
    return new Amount(whole * ATOM_PER_ATL + fracBig);
  }

  // ── Konversionen ───────────────────────────────────────────────────────────

  toAtlDecimal(): string {
    const whole = this.atom / ATOM_PER_ATL;
    const frac  = this.atom % ATOM_PER_ATL;
    return `${whole}.${frac.toString().padStart(12, '0')}`;
  }

  toUnitFloor(): bigint { return this.atom / ATOM_PER_UNIT; }
  toAtlFloor():  bigint { return this.atom / ATOM_PER_ATL; }

  // ── Arithmetik ─────────────────────────────────────────────────────────────

  add(other: Amount): Amount { return new Amount(this.atom + other.atom); }
  sub(other: Amount): Amount { return new Amount(this.atom - other.atom); }
  mul(factor: bigint): Amount { return new Amount(this.atom * factor); }
  div(divisor: bigint): Amount { return new Amount(this.atom / divisor); }

  eq(other: Amount):  boolean { return this.atom === other.atom; }
  lt(other: Amount):  boolean { return this.atom < other.atom; }
  gt(other: Amount):  boolean { return this.atom > other.atom; }
  lte(other: Amount): boolean { return this.atom <= other.atom; }
  gte(other: Amount): boolean { return this.atom >= other.atom; }

  isZero(): boolean { return this.atom === 0n; }

  toString(): string {
    return `${this.toAtlDecimal()} ATL (${this.atom} ATOM)`;
  }

  // ── Fee-Hilfsmethoden ──────────────────────────────────────────────────────

  isValidFee(): boolean {
    return this.atom >= MIN_FEE_ATOM && this.atom <= MAX_FEE_ATOM;
  }

  /** Berechnet Fee in € bei gegebenem ATL-Preis in € */
  feeInEuros(atlPriceEur: number): string {
    const feeAtl = Number(this.atom) / Number(ATOM_PER_ATL);
    const euros  = feeAtl * atlPriceEur;
    return euros.toFixed(10) + ' €';
  }
}

/** 70/30 Split eines Betrags */
export function splitReward(total: Amount): { miner: Amount; prover: Amount } {
  const miner  = total.mul(70n).div(100n);
  const prover = total.sub(miner);
  return { miner, prover };
}
