# ATLAS Mainnet — Launch-Checkliste

Stand: 2026-06-14. Diese Liste ist die verbindliche Reihenfolge für einen
**echten Mainnet-Launch mit Werten**. Sie trennt klar: was per Code erledigt ist
(✅), was DU als Betreiber konfigurieren musst (🔧), und die **harten externen
Gates** ohne die ein Launch fahrlässig wäre (🚫).

Querverweis: `MAINNET-READINESS.md` (Status), `TESTNET.md` (Teilnahme).

---

## 🚫 HARTE GATES — ohne diese KEIN Mainnet mit echtem Geld

### G1. MPC-Trusted-Setup-Ceremony (mehrere unabhängige Teilnehmer)
**Warum:** Der Groth16-Proving-/Verifying-Key entsteht aktuell per Single-Party-
`OsRng` (`zk_setup_state`) bzw. Entropie-Sammlung (`zk_ceremony`). Wer die
Setup-Maschine kontrolliert, kennt den „toxic waste" τ und kann **beliebige
Beweise fälschen → unbegrenzt Geld schöpfen**. Eine echte Phase-2-MPC
transformiert den PK sequenziell bei jedem Teilnehmer (pk → pk^r, r wird
vernichtet); solange EIN Teilnehmer ehrlich ist, ist τ unrekonstruierbar.

**Status (2026-06-14):** Gerüst gebaut & getestet — `crates/atlas-zk/src/mpc.rs`
(funktional korrekte δ-Re-Randomisierung) + `zk_phase2`-Tool (init/contribute/
verify/finalize, öffentliches Transcript). Siehe `CEREMONY.md`. **Noch offen
(Cryptographer + Audit):** (1) Phase-1-PoT für α/β/τ — aktuell single-machine,
δ-Beiträge sichern α/β/τ NICHT; (2) Beitrags-Proof-of-Knowledge. **Ohne diese
zwei ist das Setup weiterhin fälschbar.**
**To-Do vor Launch:** Phase-1 (öffentliche BN254-PoT wiederverwenden + Circuit
spezialisieren) + Beitrags-PoK ergänzen, alles auditieren, dann Ceremony mit
mehreren unabhängigen Teilnehmern fahren. Ergebnis: `state_vk.bin` (ins
Node-Binary), `state_pk.bin` (an Aggregatoren), Transcript veröffentlichen.
**Präzise Spezifikation dieses Schritts für Kryptograf/Auditor:**
`CEREMONY-PHASE1-SPEC.md` (Zielkonstruktion, BN254-PoT-Grad ≥ 2²⁰, PoK-Schema
nach BGM17, Integrationspunkte im Code, Abnahmekriterien).

### G2. Externes Audit (Circuit + Konsens)
**Warum:** Ein under-constrained-Bug im Circuit = stiller Diebstahl. Der am
2026-06-14 gefundene Genesis-L2-Root-Bug (erstes Settlement nie mineable) zeigt:
solche Fehler überleben „läuft"-Tests. **To-Do:** unabhängiges Audit von
`atlas-zk` (Circuit/Gadgets), `atlas-consensus`, `atlas-node` (Reorg/IBD/Fork),
Wirtschaftsmodell. Findings beheben, Re-Audit.

### G3. Öffentliches Langzeit-Testnet
Mehrere unabhängige Nodes/Miner über Wochen unter realer Last, bevor Mainnet.
Difficulty-Adjustment, Reorgs, Partitionen im Feld beobachten.

---

## ✅ Code-seitig erledigt (verifiziert)
- Soundness-Kern: echtes Groth16 In-Circuit-EdDSA + Merkle-State-Transition,
  Settlement wird real in Block gemined, L2-Root-Kette (live verifiziert).
- Data Availability: calldata ↔ batch_commitment gebunden (Node erzwingt beide Ebenen).
- Forced Inclusion / Zensurresistenz (Konsens-Queue + native Rejection-Zeugen).
- Multi-Node Sync/Propagation/Reorg + Reorg-Reconstruction nach Neustart.
- Inflations-Schutz (keine ungedeckten Pseudo-Input-Fees/Bid-Outputs).
- 211 Unit-/Integrationstests grün.
- **Genesis-Allokation dateibasiert** (`genesis/alloc.json`) — siehe S1.

---

## 🔧 Betreiber-Konfiguration (vor Launch zu setzen)

### S1. Genesis-Allokation festlegen (= Anfangsverteilung der L2-Geldmenge)
Die Genesis-Allokation ist die ANFANGSVERTEILUNG der L2-Geldmenge; dazu kommt die
gedeckelte PoW-Emission (≤ 100 Mio ATL), die ebenfalls L2-Konten gutgeschrieben
wird (Modell A). Es gibt keine L1↔L2-Bridge.
1. Echte Allokation als JSON schreiben (Vorlage: `crates/atlas-zk/genesis/alloc.mainnet.example.json`):
   `[{"address":"<40 Hex>","balance":<ATOM u128>}, ...]`
2. Datei nach `crates/atlas-zk/genesis/alloc.json` legen (wird per `include_str!`
   in alle Binaries eingebettet → alle Nodes byte-identisch).
3. Konstante regenerieren:
   `cargo run -p atlas-zk --release --bin genesis_root`
   → gibt `GENESIS_L2_ROOT`-Array aus. In `crates/atlas-core/src/block.rs` einsetzen.
4. Workspace neu bauen. Der Cross-Check-Test (`test_genesis_l2_root_matches_zk`)
   MUSS grün sein — er erzwingt Konstante == Datei == Node-Genesis-Root.
   Validierung vorab ohne Einbetten: `genesis_root root-of <datei.json>`.

### S2. Seed-Nodes eintragen
`crates/atlas-node/src/config.rs` → `mainnet()` → `seed_nodes`: Platzhalter
`seed1.atlas-network.io:8333` durch echte, erreichbare Seed-Hosts ersetzen
(öffentliche IP/DNS, Port 8333 freigegeben).

### S3. Konsens-Parameter prüfen (`atlas-consensus/src/params.rs::mainnet`)
Blockzeit 600 s, Halving 250 000, Subsidy 200 ATL, Fee-Cap, Forced-Window 30 —
gegen das Tokenomics-Modell bestätigen. Diese Werte sind nach Launch UNVERÄNDERLICH.

### S4. Checkpoints
`atlas-consensus/src/checkpoints.rs` → Genesis-Checkpoint stimmt automatisch;
nach Launch alle ~10 000 Blöcke einen Checkpoint nachtragen (Long-Range-Schutz).

### S5. Key-Management & Ops
- Aggregator-/Miner-Keys in HSM/Cold-Storage; RPC nie ohne `rpc_api_key` öffentlich.
- Monitoring (`metrics_port`), Alerting, Backups des `data-dir`.
- Reproduzierbare Builds (gepinnte Toolchain), Release-Signaturen.

---

## Launch-Sequenz (nachdem G1–G3 + S1–S5 erfüllt sind)
1. Finale Keys aus der Ceremony (G1) einbetten/verteilen, Genesis (S1) fixieren.
2. `cargo build --release`; volle Testsuite + `genesis_root`-Cross-Check grün.
3. Seed-Nodes starten (`atlas-node --network mainnet`), Ports offen.
4. Miner-Nodes starten (`--mining`), Aggregator(en) mit `state_pk.bin`.
5. Ersten Settlement-Durchlauf beobachten: Node-Log
   „state-transition proof(s) verified for block N" + L2-Root rückt vor.
6. Erste Checkpoints nachtragen, Release veröffentlichen, Teilnehmer onboarden.

## NICHT vor diesen Punkten launchen
Solange G1 (echte MPC) und G2 (Audit) offen sind, ist jeder Mainnet-Start mit
realem Wert ein offenes Scheunentor. Bis dahin: Open Testnet (siehe TESTNET.md).
