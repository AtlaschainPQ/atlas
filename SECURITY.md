# Sicherheitsrichtlinie

## Status: experimentell — NICHT für echtes Geld

ATLAS ist Forschungs-/Entwicklungssoftware. Der Code ist funktional umfangreich
getestet (211 Unit-/Integrationstests, Multi-Node- und Real-Mode-ZK-E2E), wurde
aber **nicht extern auditiert**. Es gab **keine** Mehr-Parteien-Trusted-Setup-
Zeremonie. Betreibe **kein Mainnet mit echten Werten** auf diesem Stand.

Vollständige Bewertung: siehe [`MAINNET-READINESS.md`](MAINNET-READINESS.md) und
[`LAUNCH-CHECKLIST.md`](LAUNCH-CHECKLIST.md).

## Bekannte, bewusste Einschränkungen (vor Mainnet zwingend zu schließen)

1. **Trusted Setup ist Single-Party.** Der Groth16-Proving-Key wurde lokal per
   `OsRng` erzeugt. Wer den Setup-„toxic waste" kennt, kann beliebige Beweise
   fälschen (= Geld schöpfen). Mainnet erfordert eine auditierte MPC-Phase-2 mit
   mehreren unabhängigen Teilnehmern.
2. **Kein externes Audit** von Circuit, Konsens und P2P.
3. **Genesis-Allokation** in `crates/atlas-zk/genesis/alloc.json` ist eine
   Dev-/Testnet-Belegung (deterministische Konten), keine Mainnet-Verteilung.
4. **Härtung/Perf:** kein Fuzzing/adversariale Lasttests; Proving ~27 s/Batch.

## Schwachstelle melden

Bitte Sicherheitslücken **nicht** über öffentliche Issues melden, sondern
vertraulich an die im Repository angegebene Kontaktadresse. Wir bitten um eine
angemessene Frist zur Behebung vor Veröffentlichung (Responsible Disclosure).

Besonders relevant: Soundness-Fehler im ZK-Circuit (under-constrained Gadgets),
Konsens-/Reorg-Fehler, Fälschbarkeit von Settlements, Umgehung der
Data-Availability-Bindung oder der Forced-Inclusion-Pflicht.
