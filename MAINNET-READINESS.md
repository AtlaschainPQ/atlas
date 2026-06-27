# ATLAS — Mainnet-Readiness-Status

Stand: 2026-06-13. Dieses Dokument ist die ehrliche Inventur dessen, was für ein
echtes Mainnet erledigt ist und was noch fehlt. Es wird bei jeder relevanten
Änderung fortgeschrieben.

**Open-Testnet-Reife:** Soundness-Kern, DA, Forced Inclusion, Inflations-Fixes
UND Multi-Node-Konsens (Sync/Propagation/Reorg) sind live verifiziert. Damit
ist der Stack bereit für ein **öffentliches Testnet** (siehe TESTNET.md). Für
echtes **Mainnet** bleiben die externen Blocker offen (MPC-Ceremony, Audits,
Langzeit-Multi-Node, echte Genesis-Allokation) — siehe unten.

## ✅ Erledigt (implementiert + getestet)

### Soundness-Kern
- **Echte Groth16-State-Transition-Beweise** (BN254/Poseidon, batch_size 16,
  746k Constraints): In-Circuit-EdDSA (Baby-Jubjub) + Adressbindung +
  Merkle-Inklusion (Tiefe 32) + Range-Checks + Batch-Commitment.
  Live-E2E verifiziert („Settlement batch accepted", test_mode=false).
- **L2-State-Root-Kette on-chain**: `pre_root → post_root` strikt verkettet,
  von Genesis re-verifizierbar; Header bindet `proof_root` + `l2_state_root`.
- **Proving-OOM behoben**: arkworks-R1CS-tracing-Spans (`target="r1cs"`)
  müssen mit `r1cs=off` gefiltert werden — sonst O(n²)-RAM-Explosion
  (siehe Kommentar in `atlas-aggregator/src/main.rs`).

### Data Availability (Escape-Hatch-Grundlage)
- Calldata jedes Batches liegt **on-chain in der SettlementBid-TX**.
- Node erzwingt **bei Mempool-Eintritt UND Block-Validierung**:
  `Poseidon(calldata-TXs, padding) == batch_commitment` (Public Input des
  Beweises). Calldata kann nicht vom Beweis abweichen; der gesamte L2-Zustand
  ist von Genesis aus rekonstruierbar. Adversarial getestet (Tamper/Leer/Überlang).

### Forced Inclusion / Zensurresistenz (neu)
- **`TxType::L2ForcedTx`**: signierte L2-TX direkt auf L1 (Pseudo-Input +
  TxStamp; keine L1-UTXOs nötig — beliebige Helfer können einreichen,
  Autorisierung steckt in der EdDSA-Signatur; native Prüfung im Konsens).
- **Konsens-Queue** im Chain-State (Reorg-sicher über Snapshots, Kapazität 10k).
- **Enforcement**: ist ein Eintrag älter als `forced_inclusion_window`
  (Mainnet 30 Blöcke ≈ 5 h, Testnet 200 ≈ 10 min), MUSS jedes Settlement
  mindestens den ältesten fälligen Eintrag aufnehmen ODER per nativ
  verifiziertem **Rejection-Zeugen** (Merkle-Pfad gegen `pre_root`:
  leerer Slot / fremde Adresse / Nonce-Mismatch / Unterdeckung) ablehnen —
  sonst ist der Block ungültig. Gültige TXs sind beweisbar NICHT ablehnbar.
  Die „ältester zuerst, einer pro Settlement"-Regel ist deadlock-frei
  (als erste TX eines Batches ist der älteste Eintrag gegen `pre_root`
  immer entweder anwendbar oder nachweislich nicht).
- **Aggregator-Pflichtpfad**: pollt `getforcedqueue`, nimmt Forced-TXs vor
  User-TXs auf, erzeugt Rejections automatisch.
- **CLI**: `atlas-sender --force --url <node-rpc> --seed … --nonce … --index …`.
- Unit-/Adversarial-Tests: Einreihung, Sig-Fälschung, Dedup, Fälligkeits-
  Enforcement, Rejection (gültig/Zensur/manipuliert/leerer Slot), Same-Block.
- **Live-E2E verifiziert (2026-06-12)**: Forced-TX via RPC → L1-Block (Mining,
  TRIAD prod-Dataset) → Konsens-Queue → Aggregator nimmt pflichtgemäß auf →
  echter Groth16-Beweis → „Settlement batch accepted" → Queue leer.
  Dabei gefundener und gefixter Bug: L2ForcedTx ohne Outputs verletzte die
  Basis-TX-Validierung („Transaction has no outputs") und blockierte das
  Mining — jetzt wertloser Marker-Output (wie SettlementBid).

### Ökonomie-Fixes (2026-06-12)
- **Inflationsloch geschlossen**: SettlementBid-`bid_output` trug `bid_amount`
  als Wert OHNE Deckung (Pseudo-Inputs durchlaufen keine Werterhaltung) —
  Aggregatoren konnten pro Batch Coins drucken. Jetzt wertlos; `bid_amount`
  ist reines Metadatum.
- **Unfundierte Fees**: `block_reward` zählte deklarierte Fees von
  Pseudo-Input-TXs (SettlementBid/L2ForcedTx) in die Coinbase, obwohl sie
  niemand zahlt → Coinbase-Inflation. Jetzt ausgeschlossen (Regressionstest).

### Geldpolitik vereinheitlicht — Modell A (2026-06-26)
Früher inkohärent: L1 mintete 100 Mio PoW-Coins, L2 war genesis-only ohne
Bridge → zwei entkoppelte Gelder. **Modell A** vereinheitlicht: EIN Geld, lebt
auf L2; die PoW-Emission wird direkt L2-Konten von Miner/Prover gutgeschrieben.
- **Kein L1-Coin**: `new_coinbase` trägt Wert 0; die Validierung lehnt jeden
  nicht-null L1-Coinbase-Output ab. Emission nativ auf L2.
- **Inflations-sicher**: Der Node rechnet die Gutschrift selbst aus dem
  Schedule nach (Subsidy + Settlement-Fees, 70/30) — aus der Coinbase kommen nur
  die Adressen. Regressionstest `test_coinbase_l2_credit_inflation_safe` sichert:
  Gutschrift == Schedule, und nach 32 Halvings ist die Subsidy 0 (100M-Cap).
- **Gebündelte Gutschrift**: leere Blöcke lassen die L2-Root unverändert, die
  Emission läuft auf und wird beim nächsten Settlement-Block nachgetragen. Damit
  bleibt die Settlement-`pre_root` zwischen Settlements stabil (sonst race-t die
  pro-Block vorrückende Root mit dem ~24-s-Proving → Settlement-Livelock; live
  entdeckt und so behoben). Der Node hält dafür den vollen L2-Baum (reorg-fest
  via Snapshot-Bytes; Reorg × Walk-Back auf Stale-Reads geprüft — ok, da
  `save_block` den Höhen-Index pro Block aktualisiert).
- **Fair Launch**: `genesis/alloc.json` leer (kein Premine) → Geld entsteht NUR
  aus Mining. Aggregator-**Heartbeat** schüttet die aufgelaufene Emission per
  leerem Settlement aus (sonst Bootstrap-Deadlock: Settlement braucht Funds,
  Funds brauchen Settlement — live entdeckt und behoben).
- **Live verifiziert (2026-06-26)**: Settlements landen, Emission 200/Block auf
  L2, Heartbeat-Ausschüttung, Buchhaltung exakt (Sender/Empfänger/Miner-Fees
  konserviert). Whitepaper/README als implementiert dokumentiert.
- **Live-Diagnose (2026-06-27)**: Testnet gesund (Account-Balance über Nacht
  21k→161k ATL, Settlements laufen durch). Der Aggregator-Zähler `batches_failed`
  war durch gutartiges Dedup-Rauschen verfälscht: leere Heartbeat-Batches haben
  eine konstante `batch_id` (Calldata leer → konstante Merkle-Root), die
  Eindeutigkeit pro Settlement liefert im Konsens-Digest die `pre_root`. Reicht
  der Aggregator einen identischen, noch ungeminten Bid erneut ein, weist die
  Node-Mempool-Dedup ihn als Duplikat ab. Fix: der Aggregator zählt eine
  „Duplicate"-Antwort nicht mehr als Fehlschlag (konsens-neutral, nur Metrik).
- **Adversariale Review (2026-06-26)**: Geld-Vektoren geprüft — keine
  Über-Gutschrift (Schedule-gebunden), keine Doppel-Gutschrift (jeder Block genau
  einmal), Cap erzwungen, Fees konserviert, leerer Block kann Root nicht ändern.
- **O(Gap)-Walk-Back beseitigt — Emissions-Akkumulator (2026-06-27)**: Früher
  lief ein Settlement-Block den Storage rückwärts bis zum letzten Settlement ab,
  um die aufgelaufene Emission der leeren Blöcke nachzutragen — O(Lücke) pro
  Settlement und damit ein (milder) DoS-Vektor (viele leere Blöcke → ein teures
  Settlement bei jedem validierenden Node). Jetzt führt der Node einen
  reorg-/neustart-festen **Emissions-Akkumulator** (`pending_emission`): jeder
  leere Block hängt seine Coinbase-Emission O(1) an, jedes Settlement verbraucht
  und resettet ihn. Die gutgeschriebenen Beträge sind **bit-identisch** zum
  früheren Walk-Back (gleiches `coinbase_credits_from`-Primitiv, Credits
  kommutieren) → **keine Konsens-Spaltung**. Nach Reorg/Neustart wird der
  Akkumulator einmalig rekonstruiert (`reconstruct_pending_emission`), der
  Live-Pfad bleibt O(1). Damit ist der Audit-Punkt gelöst — nicht durch eine
  Liveness-gefährdende harte Cap, sondern durch Eliminierung der unbegrenzten
  Berechnung. Regressionstest `test_emission_accumulator_aggregates_by_address`;
  der bestehende Echt-Groth16-E2E-Test deckt den Settlement-Pfad ab (eigene
  Root-Assertion fängt jede Divergenz).

### Genesis-L2-Root-Fix (2026-06-14) — KRITISCH, war Launch-Blocker
Auf einer frischen Chain startete der Node-State mit `EMPTY_L2_ROOT`, während
Genesis-Block UND Aggregator den vorab geförderten `GENESIS_L2_ROOT` verankern.
Folge: das **allererste Settlement** wurde beim Block-Bau verworfen
(„pre_root does not chain") → die L2 wäre auf einer neuen Chain dauerhaft tot
gewesen. Frühere „Settlement accepted"-Meldungen waren irreführend (nur
Mempool-Eintritt, kein Block-Einschluss). Fix: `ChainState::genesis()` verankert
jetzt den geförderten Root + Regressionstest. **Live verifiziert:** echtes
Groth16-Settlement wird in einen Block gemined, L2-Root rückt vor
(„state-transition proof verified for block N").

### Test-Abdeckung (Stand 2026-06-14)
- **211 Unit-/Integrationstests grün, 0 Fehler** (deterministisch).
- Real-Mode (test_mode=false, echtes Groth16): Settlement in Block, L2-Root-Kette,
  Ablehnung manipulierter Proofs — live bestätigt.
- `classify_forced` (3 Tests) + Forced-Queue-Regeln (4 Tests): Zensurresistenz
  deterministisch abgesichert (gültige Forced-TX wird inkludiert, ungültige per
  Zeuge abgelehnt, kein Index-Zensur-Schlupfloch).
- Multi-Node Sync/Reorg/Reconstruction + Persistenz über Neustart — live.

### Multi-Node-Konsens (2026-06-13) — Open-Testnet-Voraussetzung
Live-getestet mit 3 Nodes (Kette C→B→A) auf einem Host:
- **Block-Propagation + IBD**: B und C schließen per Initial Block Download an
  A's Kette an und folgen live; identischer Best-Hash auf allen dreien.
- **Fork-Reorg**: B mint isoliert einen Fork, verbindet sich neu, verwirft die
  eigene Kette und reorganisiert auf A's längere — Konvergenz bestätigt.

Dabei gefundene und gefixte Bugs (jeder hätte ein offenes Netz am Tag 1 in einen
**permanenten Chain-Split** getrieben):
1. Seed-Connect ohne Retry → isolierte Nodes. Fix: Reconnect-Wächter (Backoff).
2. Dataset-Generierung/Mining blockierten die async-Runtime → Node beim Minen
   „taub" (kein RPC/Ping, Peers trennen). Fix: beides in `spawn_blocking`.
3. `IBD_THRESHOLD` Off-by-one (`>` statt `>=`) → Node 1 Block hinten synct nie.
4. Idle-Timeout 60 s zu knapp → gesunde Verbindungen gekappt. Fix: 180 s.
5. Fork-Punkt = `parent.height` (falsch bei Mehr-Block-Forks) → jeder echte
   Reorg lief in eine IBD-Endlosschleife. Fix: gemeinsamen Vorfahren ermitteln.
6. Mining lief während Sync weiter → eigene Kette holt auf Gleichstand, Reorg
   auf die längere Fremdkette löst nie aus. Fix: Mining pausiert bei `is_syncing`.
7. **Snapshots nur im RAM** → ein neu gestarteter Node hat keine Rückroll-Punkte
   und kann NIE unter seinen Tip reorganisieren. Fix: fehlt der Snapshot, wird
   der Fork-Punkt-Zustand durch Neu-Abspielen der aktiven Kette von Genesis über
   dieselbe `apply_block`-Logik rekonstruiert (selten, nur Reorg-nach-Neustart).

### Mainnet-Code-Bausteine (2026-06-14)
- **Genesis-Allokation dateibasiert**: `crates/atlas-zk/genesis/alloc.json`
  (`[{address,balance}]`) ist die EINZIGE Quelle, via `include_str!` in alle
  Binaries eingebettet → Node (treibt `GENESIS_L2_ROOT`) und Aggregator
  byte-identisch. Mainnet-Workflow: Datei ersetzen → `genesis_root` →
  `GENESIS_L2_ROOT` in atlas-core einsetzen → rebuild. Cross-Check-Test erzwingt
  Konsistenz. Tooling: `genesis_root` (Konstante), `genesis_root dump-dev`
  (Dev-JSON), `genesis_root root-of <datei>` (beliebige Allokation prüfen).
  Vorlage: `crates/atlas-zk/genesis/alloc.mainnet.example.json`.
- **`LAUNCH-CHECKLIST.md`**: verbindliche Launch-Reihenfolge inkl. der harten
  externen Gates (MPC-Ceremony, Audit, Langzeit-Testnet).

### Härtung (vorhanden)
- RPC: Header-Cap 8 KB, Body-Cap 1 MB, Token-Bucket-Rate-Limit pro IP,
  constant-time API-Key-Vergleich.
- P2P: 32-MB-Frame-Cap, Idle-Timeouts, Peer-Rate-Limit, Ban-Liste, TLS-Modul,
  Item-Caps (addr/getdata). Checkpoints gegen Long-Range-Angriffe.
- Mempool: Stamp-Pflicht (Mini-PoW), Fee-Bounds, Dedup (Bids pro batch_id,
  TXID), Forced-TX-Format-Sanity.
- ZK-Keys: PK öffentlich (Soundness hängt nur am VK), unkomprimierter
  Fast-Load-Pfad mit dokumentierter Begründung.

## ❌ Offen für echtes Mainnet (Blocker)

1. **MPC-Trusted-Setup (Phase 2) — KRITISCH.**
   Die aktuellen Keys stammen aus Single-Party-`OsRng` (`zk_setup_state`).
   `zk_ceremony` sammelt seit dem Fix Entropie-Beiträge transparent und mischt
   beim Finalize frische, nie persistierte Entropie (der frühere Stand seedete
   AUSSCHLIESSLICH aus der öffentlichen ceremony.json — damit wäre der toxic
   waste öffentlich ableitbar gewesen!). Verbleibende Annahme: die
   Finalize-Maschine ist ehrlich. **Vor Launch: echte, auditierte
   MPC-Phase-2** (jeder Teilnehmer transformiert den PK, verwirft sein r),
   z. B. Adaption von snarkjs/phase2-bn254 auf diesen Circuit.
2. **Externe Audits** — ZK-Circuit (under-constrained-Bugs!), Konsens,
   P2P, Wirtschaftsmodell.
3. **Mehrere unabhängige Nodes/Miner + öffentliches Langzeit-Testnet** —
   bisher 1 Node + 1 Aggregator auf einer Maschine; Reorgs/Partitionen/
   Difficulty über lange Zeiträume unter realen Bedingungen ungetestet.
4. **Aggregator-Dezentralisierung in der Praxis** — permissionless möglich
   (PK öffentlich, State aus DA rekonstruierbar), aber Mehr-Aggregator-Betrieb
   ist nicht real erprobt; L2-Liveness hängt an der Existenz ≥1 Aggregators
   (Konsens kann Existenz nicht erzwingen — inhärent).
5. **Performance** — ~27 s Proof für 16 TXs (CPU). Für nennenswerten Durchsatz:
   GPU-Proving / Rekursion / größere Batches; PK 281 MB.
6. **Betrieb** — Key-Management (HSM), Monitoring/Alerting, reproduzierbare
   Builds, dokumentierter Upgrade-/Governance-Pfad. Genesis-Allokation:
   Mechanik ist jetzt dateibasiert (✅), aber die ECHTE Mainnet-Allokation muss
   noch festgelegt werden (aktuelle `genesis/alloc.json` = 64 Dev-Konten) —
   Verfahren in LAUNCH-CHECKLIST.md (S1).

## Bekannte bewusste Einschränkungen
- `test_mode=true` überspringt ZK-/DA-/Forced-Prüfungen (nur Entwicklung).
- Forced-Inclusion-Fenster startet erst mit Block-Aufnahme der L2ForcedTx;
  Blöcke ohne Settlements unterliegen keinem Enforcement (Aggregator-Existenz
  ist nicht erzwingbar — Standard-Rollup-Tradeoff).
- `sender_index` in Forced-TXs stammt vom User; ein falscher Index macht die
  TX ablehnbar (Neueinreichung mit korrektem Index nötig). Der Index ist aus
  den On-Chain-Calldata rekonstruierbar.
