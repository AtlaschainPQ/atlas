# ATLAS — Ein quantensicheres Layer-1 mit Zero-Knowledge Layer-2

**Technisches Whitepaper**
Version 1.1 — Juni 2026

---

## Abstract

ATLAS ist eine zweischichtige Blockchain-Architektur, die die Sicherheit eines
Proof-of-Work-Layer-1 (L1) im Stil von Bitcoin mit dem Durchsatz eines
Zero-Knowledge-Rollup-Layer-2 (L2) verbindet. Die L1 sichert das Netzwerk über
einen speicherharten (memory-hard) PoW-Algorithmus namens **TRIAD** und verwaltet
einen UTXO-Zustand. Der gesamte Zahlungsverkehr der Nutzer findet auf der L2 statt:
Ein **Aggregator** bündelt kontosbasierte L2-Transaktionen, beweist ihre Korrektheit
mit einem **Groth16-zk-SNARK** über der Kurve BN254 und reicht den Beweis zusammen
mit den Transaktionsdaten (Data Availability) on-chain ein. Die L1 **verifiziert**
diese Beweise, ohne sie selbst zu erzeugen.

Drei Eigenschaften unterscheiden ATLAS von vergleichbaren Entwürfen:

1. **Quantensicherheit auf Signaturebene (L1):** Neben klassischem ECDSA (secp256k1)
   unterstützt ATLAS für L1-Transaktionen nativ **ML-DSA-65 (CRYSTALS-Dilithium3,
   NIST FIPS 204)** als post-quantum-sicheres Signaturverfahren.
2. **Soundness durch In-Circuit-Beweise statt Vertrauen:** Jeder Settlement-Batch
   trägt einen eigenständigen Zustandsübergangs-Beweis. Die L2-Signaturen werden
   **innerhalb der Schaltung** verifiziert (Baby-Jubjub-EdDSA), sodass ein
   Aggregator keine fremden oder unsignierten Transfers einschleusen kann. Alle
   öffentlichen Eingaben stammen aus On-Chain-Daten — nichts kann ohne gültigen
   Beweis gefälscht werden.
3. **Zensurresistenz ohne Bridge:** Über **Forced Inclusion** kann jeder Nutzer
   eine signierte L2-Transaktion direkt auf L1 erzwingen; der Konsens verpflichtet
   Aggregatoren, fällige Einträge aufzunehmen oder nachweislich abzulehnen.

---

## 1. Motivation

Klassische Blockchains stehen vor drei strukturellen Problemen:

- **Skalierbarkeit:** On-chain verarbeitete Transaktionen sind durch Blockgröße und
  Blockzeit begrenzt.
- **Quantenrisiko:** ECDSA und andere auf dem diskreten Logarithmus basierende
  Verfahren sind durch Shors Algorithmus angreifbar, sobald hinreichend große
  Quantencomputer existieren.
- **Vertrauen in Betreiber:** Viele Rollups verlassen sich auf die Ehrlichkeit eines
  Sequencers oder auf Betrugsbeweise mit langen Anfechtungsfristen.

ATLAS adressiert alle drei: Skalierung durch Validity-Rollup, Quantenrisiko durch
ML-DSA-65, und Vertrauensminimierung durch zk-SNARK-Validitätsbeweise mit
vollständiger On-Chain-Datenverfügbarkeit.

---

## 2. Architekturüberblick

```
            ┌─────────────────────────────────────────────┐
            │                  Layer 1 (PoW)              │
            │                                             │
            │   TRIAD memory-hard Mining  ·  UTXO-Set     │
            │   verifiziert Groth16-Zustandsbeweise       │
            │   speichert L2-Calldata (Data Availability) │
            └───────────────▲─────────────────────────────┘
                            │ SettlementBid-TX
                            │ (Beweis + Roots + Calldata)
            ┌───────────────┴─────────────────────────────┐
            │                Aggregator (L2)               │
            │                                             │
            │   AccountTree (Merkle, Tiefe 32)            │
            │   bündelt L2-TX · erzeugt Groth16-Beweis    │
            └───────────────▲─────────────────────────────┘
                            │ signierte L2-Transaktionen
            ┌───────────────┴─────────────────────────────┐
            │                   Nutzer / Sender            │
            └─────────────────────────────────────────────┘
```

Die Rollenverteilung ist strikt: **Der Aggregator beweist, die L1 verifiziert.**
Die L1 hält niemals einen Proving-Key und führt nie eine Beweis-Erzeugung durch.

### 2.1 Implementierungsstruktur

ATLAS ist in Rust implementiert und in zehn Crates gegliedert:

| Crate | Aufgabe |
|---|---|
| `atlas-core` | Grundtypen: Block, Transaktion, Hash, klassische & PQ-Kryptographie, Beträge |
| `atlas-consensus` | Konsensparameter, Difficulty, Reward-Schedule, Checkpoints, Validierung |
| `atlas-triad` | TRIAD memory-hard PoW (Dataset, Miner, Verifier, Epoch-Rotation) |
| `atlas-state` | UTXO-Set, Block-Executor (Signaturprüfung Classic + PQ, Werterhaltung) |
| `atlas-mempool` | Transaktions-Mempool, Fee-Schätzung |
| `atlas-zk` | Groth16/BN254, Poseidon, AccountTree, Zustandsübergangs-Schaltung, L2-State |
| `atlas-node` | Full-Node: Chain-Management, P2P, JSON-RPC, Block-Produktion, ZK-Verifikation |
| `atlas-aggregator` | L2-Aggregator: Batch-Bildung, Beweis-Erzeugung, Bid-Einreichung |
| `atlas-sender` | Hochdurchsatz-Lastgenerator für L2-Transaktionen |
| `atlas-wallet` | Schlüsselverwaltung (Classic + PQ), Transaktionsaufbau |

---

## 3. Layer 1: Proof-of-Work und Zustand

### 3.1 TRIAD — speicherharter Proof-of-Work

TRIAD ist ein speicherharter PoW-Algorithmus, dessen primäres Mining-Limit die
**RAM-Bandbreite** ist (vergleichbar mit Ethash/RandomX in der Zielsetzung).

- **Dataset:** ~4 GB, deterministisch aus einem Epoch-Seed erzeugt
  (4·1024³ / 64 = **67.108.864 Items** à 64 Byte).
- **Cache:** 1/32 des Datasets, aus dem das volle Dataset rekonstruierbar ist.
- **Speicherzugriffe:** 64 pseudozufällige Dataset-Zugriffe pro Hash-Versuch.
- **Hash-Primitive:** SHA-256 und SHA3-256.
- **Epoch-Rotation:** Das Dataset wechselt regelmäßig (alle ~2 Wochen). Dadurch wird
  die Amortisierung spezialisierter ASIC-Hardware unattraktiv.

Die Verifikation eines Blocks benötigt nur den Cache, nicht das volle Dataset —
Light-Verifier sind also möglich.

### 3.2 UTXO-Modell und Signaturen

Die L1 verwaltet einen UTXO-Zustand (Unspent Transaction Outputs) wie Bitcoin.
Jeder Output ist an eine Adresse gebunden, die in zwei Varianten existiert:

- **Klassisch (`ATL:`):** ECDSA über secp256k1, 64-Byte-Signaturen.
- **Post-Quantum (`ATLQ:`):** ML-DSA-65, 3309-Byte-Signaturen.

Der Block-Executor (`atlas-state`) prüft bei jedem Input zwei Bedingungen:
1. Die aus dem Witness abgeleitete Adresse stimmt mit dem UTXO-Eigentümer überein.
2. Die kryptographische Signatur über den Transaktions-Hash ist gültig.

Verstößt eine Transaktion gegen die Werterhaltung (`Summe Inputs = Summe Outputs +
Gebühr`) oder gegen eine Signaturprüfung, wird sie atomar zurückgerollt — verbrauchte
UTXOs werden vollständig wiederhergestellt.

### 3.3 Geldsystem

ATLAS nutzt ein dreistufiges, ganzzahliges Geldsystem (interne Berechnung stets in
ATOM, `u128`):

| Einheit | Wert |
|---|---|
| 1 ATOM | atomare Einheit (10⁻¹² ATL) |
| 1 UNIT | 10.000 ATOM |
| 1 ATL  | 100.000.000 UNIT = 1.000.000.000.000 ATOM (10¹²) |

### 3.4 Emission und Rewards

ATLAS hat **eine** Geldmenge, die auf der L2 lebt (§4.5). Die hier beschriebene
PoW-Emission wird **direkt L2-Konten** gutgeschrieben — es gibt **keinen separaten
L1-Coin**.

- **Initiale Subsidy:** 200 ATL pro Block.
- **Halving:** alle 250.000 Blöcke (~4,75 Jahre), maximal 32 Halvings, danach 0.
- **Emissions-Obergrenze:** **100.000.000 ATL** (200 × 250.000 × 2) — die
  Gesamtmenge ist **Genesis-Allokation + ≤ 100 Mio ATL** Emission.
- **Reward-Split:** **70 % Miner / 30 % Prover (Aggregator)**, beide als
  Gutschrift auf ihren L2-Konten. Der Prover-Anteil entlohnt die rechenintensive
  Beweis-Erzeugung.
- **Blockzeit (Mainnet):** 600 s (10 Minuten).
- **Difficulty-Retarget:** alle 2016 Blöcke, maximale Änderung Faktor 4.
- **Coinbase-Reife:** 100 Blöcke. **Bestätigungstiefe:** 6 Blöcke.

---

## 4. Layer 2: Zero-Knowledge-Rollup

### 4.1 Kontomodell und AccountTree

Im Gegensatz zur UTXO-basierten L1 ist die L2 **kontobasiert**. Der Zustand ist ein
Merkle-Baum (`AccountTree`) der **Tiefe 32**, dessen Blätter Konten mit `(Balance,
Nonce)` sind. Die Wurzel dieses Baums ist die **L2-State-Root**.

Die L2-State-Root wird on-chain fortgeschrieben: `BlockHeader.l2_state_root` und der
`ChainState` führen die laufende Wurzel mit. Da die Geldmenge auf L2 lebt und mit
der Genesis-Allokation startet, verankert der Genesis-Block **nicht** den leeren
Baum, sondern den **vorab geförderten** Zustand: die Konstante `GENESIS_L2_ROOT`. Sowohl der frische
`ChainState` als auch der Genesis-Block tragen exakt diese Wurzel — andernfalls
würde das allererste Settlement nicht anschließen. Die Übereinstimmung zwischen
der Genesis-Allokationsdatei, `atlas-zk` und `atlas-core` wird durch einen
Cross-Check-Test erzwungen. Die Allokation selbst ist **dateibasiert**
(`genesis/alloc.json`, in alle Binaries einkompiliert) — siehe Abschnitt 4.5.

### 4.2 Der Zustandsübergangs-Beweis

Jeder Settlement-Batch trägt einen eigenständigen **Groth16-zk-SNARK** über der
Kurve **BN254** mit **Poseidon** als arithmetisierungsfreundlicher Hashfunktion. Der
Aggregator beweist, dass `pre_root` durch eine gültige Folge von L2-Transaktionen
deterministisch in `post_root` übergeht. Für jede einzelne L2-Transaktion erzwingt
die Schaltung:

- **In-Circuit-Signaturprüfung (Baby-Jubjub-EdDSA):** Die Gültigkeit der Signatur
  `S·B == R + c·A` wird *innerhalb* der Schaltung verifiziert. Damit ist
  kryptographisch ausgeschlossen, dass ein Aggregator fremde oder unsignierte
  Transfers einschleust.
- **Adressbindung:** `from == lower160(Poseidon(A.x, A.y))` — die Absenderadresse
  ist an den öffentlichen Schlüssel gebunden.
- **Merkle-Inklusion** von Sender- und Empfängerkonto im `pre_root`,
- **ausreichendes Guthaben** des Senders (Range-Checks, Underflow-Schutz),
- **korrekte Nonce** (Replay-Schutz),
- **konsistente Aktualisierung** beider Konten zum `post_root`,
- **Werterhaltung** (keine Erzeugung oder Vernichtung von Guthaben).

Die L2-Signatur ist **Baby-Jubjub-EdDSA** (32-Byte-Pubkey, 64-Byte-Signatur), eine
„embedded curve" über dem BN254-Skalarfeld — dadurch ist die In-Circuit-Punkt­
arithmetik effizient (keine teure Non-Native-Field-Emulation).

**Öffentliche Eingaben** des Beweises sind ausschließlich:

```
[ pre_root , post_root , total_fees , batch_commitment ]
```

Alle vier Werte stammen aus On-Chain-Daten. Da `pre_root` strikt an die aktuelle
Chain-L2-Root anschließen muss und `post_root` zur neuen Wurzel wird, kann ein
Aggregator keinen Zustand „erfinden". Ein gültiger Beweis ist **~128 Byte** groß.

| Parameter | Wert |
|---|---|
| Beweissystem | Groth16 |
| Kurve | BN254 (alt-bn128) |
| Hash in der Schaltung | Poseidon |
| L2-Signatur (in-circuit) | Baby-Jubjub-EdDSA |
| Merkle-Tiefe | 32 |
| Batch-Größe (aktueller Circuit) | 16 Transaktionen (~746k Constraints) |
| Verifying Key (`state_vk.bin`) | 392 Byte, in den Node einkompiliert |
| Proving Key (`state_pk.bin`) | ~281 MB, nur beim Aggregator |
| Beweisgröße | ~128 Byte (konstant) |

### 4.3 Data Availability (Datenverfügbarkeit)

Damit der L2-Zustand jederzeit von Genesis aus rekonstruierbar bleibt, postet jeder
`SettlementBid` die **L2-Calldata** des Batches on-chain — pro Transaktion 80 Byte:

```
from(20) | to(20) | amount(16) | fee(16) | nonce(8)   = 80 Byte
```

Der Node dekodiert die Calldata, berechnet daraus das Poseidon-`batch_commitment`
neu und prüft, dass es **exakt** dem im Beweis gebundenen Commitment entspricht.
Dadurch ist garantiert, dass die veröffentlichten Daten der bewiesenen Transition
entsprechen. Selbst wenn der Aggregator verschwindet, kann jeder den vollständigen
L2-Zustand aus den öffentlichen On-Chain-Daten wiederherstellen — der **Escape-Hatch**.

### 4.4 Einreichung: der SettlementBid

Der Aggregator reicht ein Settlement als spezielle L1-Transaktion vom Typ
`SettlementBid` ein. Sie enthält:

- `batch_id` (Merkle-Root der TX-Hashes),
- `pre_root`, `post_root`,
- `batch_commitment` (Data-Availability-Bindung),
- `total_fees`,
- `proof` (Groth16, ~128 B),
- `calldata` (L2-Transaktionsdaten).

Der Node validiert die L2-Root-Kette (jeder `pre_root` muss an die aktuelle Wurzel
anschließen), verifiziert den Groth16-Beweis und prüft die Data-Availability-Bindung,
bevor er die neue L2-State-Root übernimmt.

### 4.5 Finanzierung: ein Geld auf L2, keine Bridge (Modell A)

ATLAS hat **eine** Geldmenge, und sie lebt auf der **L2** (kontobasiert).
Nutzer-Transaktionen laufen **ausschließlich über die L2**. Die Geldmenge hat
**zwei Quellen, beide direkt auf L2-Konten**:

1. die **Genesis-Allokation** (Anfangsverteilung), und
2. die **PoW-Block-Emission** (§3.4), die Miner und Prover (70/30) **direkt auf
   ihren L2-Konten** gutgeschrieben wird.

Die L1 trägt **keinen eigenen Coin** — sie ist reine PoW-Sicherheits-, Settlement-
und Datenverfügbarkeits-Schicht. Weil aller Wert auf **einem** Ledger (L2) liegt,
braucht es bewusst **keine L1↔L2-Bridge**. Wertänderungen auf L2 sind Transfers
**plus** die deterministische, gedeckelte Emission (≤ 100 Mio ATL); die Gesamtmenge
ist Genesis-Allokation (ggf. leer) + Emittiertes.

> **Umsetzung (implementiert & live verifiziert):** Der Node führt den vollen
> L2-Baum mit. Die Coinbase trägt **keinen L1-Wert**; ihre Emission wird beim
> nächsten Settlement-Block **nativ** den L2-Konten von Miner/Prover gutgeschrieben
> (Beträge aus dem Schedule → inflations-sicher). Die Gutschrift ist **gebündelt**
> (leere Blöcke lassen die L2-Root unverändert, die Emission läuft auf), damit die
> Settlement-`pre_root` zwischen Settlements stabil bleibt. Ein Aggregator-
> **Heartbeat** reicht bei Leerlauf ein leeres Settlement ein, das die aufgelaufene
> Emission ausschüttet — so funktioniert auch ein **Fair Launch ohne Premine**.

Die Genesis-Allokation (`genesis/alloc.json`) ist **konfigurierbar**: **leer = Fair
Launch** (kein Premine — die gesamte Geldmenge entsteht nur aus der Mining-Emission)
oder eine Liste `{address, balance}` als Anfangsverteilung. Sie wird per `include_str!`
in alle Binaries einkompiliert, sodass Node und Aggregator byte-identisch dieselbe
Geldmenge verankern. Aus der Datei wird die Konstante `GENESIS_L2_ROOT` deterministisch
abgeleitet; ein Cross-Check-Test erzwingt, dass Datei, Konstante und Genesis-Block
übereinstimmen.

### 4.6 Forced Inclusion (Zensurresistenz)

Da Nutzergelder ausschließlich auf der L2 liegen, ist die Liveness der Aggregatoren
sicherheitskritisch. ATLAS bietet daher einen **Escape-Hatch auf Protokollebene**:
Jeder kann eine signierte L2-Transaktion als spezielle L1-Transaktion (`L2ForcedTx`)
direkt veröffentlichen — ohne L1-Guthaben (Spam-Schutz über einen Mini-PoW-Stamp),
die Autorisierung liegt allein in der eingebetteten EdDSA-Signatur.

Solche Einträge landen in einer **konsens-geführten Forced-Inclusion-Queue** (Teil
des Chain-States, Reorg-sicher). Ist ein Eintrag älter als das
`forced_inclusion_window`, MUSS jedes nachfolgende Settlement den ältesten fälligen
Eintrag entweder **aufnehmen** (seine Calldata enthält die TX) oder per **nativem
Rejection-Zeugen** nachweislich ablehnen (Merkle-Pfad gegen `pre_root`: leerer Slot,
fremde Adresse, falsche Nonce oder Unterdeckung) — andernfalls ist der Block
**ungültig**. Eine gegen den Zustand gültige Forced-TX ist beweisbar **nicht**
ablehnbar; ein Aggregator kann sie also nicht zensieren, ohne ungültige Blöcke zu
produzieren.

---

## 5. Post-Quantum-Sicherheit

ATLAS integriert **ML-DSA-65 (CRYSTALS-Dilithium3)** gemäß **NIST FIPS 204** als
gitterbasiertes, quantenresistentes Signaturverfahren.

| Eigenschaft | Wert |
|---|---|
| Sicherheitsniveau | NIST Level 3 (192-Bit klassisch / 128-Bit post-quantum) |
| Public Key | 1952 Byte |
| Secret Key | 4032 Byte (mit `zeroize` beim Verlassen des Scopes gelöscht) |
| Signatur | 3309 Byte |
| Adressformat | `ATLQ:` + 20 Byte (SHA-256(pk)[..20]) |

Klassische und post-quantum-Adressen sind durch ihren Präfix (`ATL:` vs. `ATLQ:`)
eindeutig unterscheidbar. ML-DSA-65 wird auf der **L1** durchgängig unterstützt:

- **L1-Mempool:** akzeptiert und verifiziert klassische *und* PQ-Witnesses
  (Adress-Abgleich gegen den UTXO-Eigentümer plus Signaturprüfung).
- **L1-Block-Executor:** verifiziert beide Witness-Typen beim Zustandsübergang.

**Signaturen auf der L2.** Die L2 verwendet **Baby-Jubjub-EdDSA** (32-Byte-Pubkey,
64-Byte-Signatur) — nicht weil EdDSA quantensicher wäre, sondern weil es als
„embedded curve" über dem BN254-Skalarfeld effizient *innerhalb* der Groth16-
Schaltung verifizierbar ist (Abschnitt 4.2). Die L2 erbt die L1-PoW-Sicherheit;
die Vertraulichkeit/Integrität der Transfers garantiert der Validitätsbeweis.
Eine post-quantum-sichere In-Circuit-Signatur (z. B. gitterbasiert) ist ein
offenes Forschungsthema und auf der Roadmap (Abschnitt 9). Wer maximale
Quantensicherheit für Werte will, hält sie heute auf einer `ATLQ:`-L1-Adresse.

---

## 6. Skalierung und Durchsatz

Die Konsensparameter sind netzwerkabhängig. Die Testnet-Konfiguration ist auf hohen
Durchsatz ausgelegt:

- Blockzeit 3 s, bis zu 64 Settlement-Batches pro Block,
- Architektonisches Ziel: **~40.000 bestätigte L2-TPS**
  (64 Batches × ~2.000 TX / 3 s).

Der aktuelle, vollständig verifizierte Produktions-Circuit arbeitet mit Batch-Größe
16 (~746k Constraints, inkl. In-Circuit-EdDSA). Die Beweis-Erzeugung für einen
Batch-16/Tiefe-32-Übergang dauert im Release-Modus **~27 s** (BN254-CPU-Groth16 mit
aktivierter Parallelisierung); dies ist der rechnerische Flaschenhals und wird über
mehrere parallele Aggregatoren bzw. größere Batches skaliert. Die **Verifikation**
auf der L1 ist dagegen konstant günstig (~128-Byte-Beweis, O(1)-Pairing-Check).

> Hinweis: Frühere Whitepaper-Fassungen nannten ~475 s — dieser Wert stammte aus
> einer pathologischen Konfiguration (versehentlich aktiviertes Tracing der
> Constraint-Synthese, O(n²)-Overhead) und wurde behoben.

---

## 7. Sicherheitseigenschaften

- **Validity statt Fraud Proofs:** Ein ungültiger Zustandsübergang ist
  kryptographisch unmöglich einzureichen — es gibt keine Anfechtungsfrist.
- **Vollständige Datenverfügbarkeit:** Der L2-Zustand ist aus On-Chain-Calldata
  rekonstruierbar; keine Abhängigkeit von der Verfügbarkeit des Aggregators.
- **Strikte Root-Verkettung:** `pre_root` jedes Batches muss an die aktuelle
  Chain-L2-Root anschließen; abweichende Bids werden verworfen.
- **Zensurresistenz:** Forced Inclusion (Abschnitt 4.6) erzwingt die Aufnahme
  fälliger Nutzer-TX auf Protokollebene — unabhängig von der Kooperation einzelner
  Aggregatoren.
- **Quantenresistente Signaturen (L1):** ML-DSA-65 für Nutzer, die Werte gegen
  zukünftige Quantenangriffe absichern wollen.
- **Reorg-Schutz:** Zustands-Snapshots vor jedem Block ermöglichen sauberes
  Rollback. Fehlt nach einem Neustart ein Snapshot, wird der Fork-Punkt-Zustand
  durch Neu-Abspielen der Kette von Genesis rekonstruiert — ein neu gestarteter
  Node kann also stets korrekt reorganisieren. Checkpoints verankern die Historie.
- **ASIC-Resistenz:** speicherharter PoW mit Epoch-Rotation.

---

## 8. Validierungsstatus

Der Implementierungsstand ist durch eine umfangreiche Testsuite abgesichert:
**211 Unit- und Integrationstests, alle grün.** Verifiziert wurde u. a.:

- **Soundness-Ende-zu-Ende (real, kein Test-Modus):** nativer Batch-Executor →
  echter Groth16-Beweis (281-MB-Proving-Key, In-Circuit-EdDSA) → On-Chain-
  Verifikation → Einschluss in einen geminten Block, fortschreitende L2-Root.
  Gültige Übergänge werden akzeptiert, manipulierte Beweise / `post_root` /
  Gebühren abgelehnt.
- **Mehr-Node-Konsens (live):** Block-Propagation, Initial Block Download und
  Fork-**Reorg**-Konvergenz über mehrere unabhängige Nodes; Zustandsrekonstruktion
  nach Neustart.
- **Zensurresistenz:** Forced-Inclusion-Queue und native Rejection-Zeugen
  (deterministische Tests: gültige TX wird inkludiert, ungültige nachweislich
  abgelehnt, kein Index-Zensur-Schlupfloch).
- **Data-Availability-Bindung:** manipulierte/leere/überlange Calldata wird
  abgelehnt.
- **Post-Quantum-Signaturen (L1):** Primitiv-, Mempool- und Executor-Ebene
  (gültige ML-DSA-Signatur akzeptiert, Manipulation und falscher Schlüssel
  abgelehnt).

Im Zuge der Launch-Härtung wurde eine Reihe konsenskritischer Fehler gefunden und
behoben — u. a. ein Genesis-L2-Root-Mismatch, durch den auf einer frischen Chain
das erste Settlement nie hätte gemined werden können, sowie mehrere Mehr-Node-
Sync/Reorg-Fehler. Details: `MAINNET-READINESS.md`.

---

## 9. Status, offene Punkte und Ausblick

### 9.1 Trusted Setup — der entscheidende Mainnet-Vorbehalt

Groth16 benötigt einen circuit-spezifischen Trusted Setup. Der aktuelle Proving-/
Verifying-Key wurde per Single-Party-`OsRng` erzeugt. **Solange kein echtes
Mehr-Parteien-Setup (MPC, „Phase 2") durchgeführt wurde, könnte eine Partei mit
Zugriff auf den Setup-„toxic waste" beliebige Beweise fälschen.** Für ein Mainnet
mit echten Werten ist eine auditierte MPC-Zeremonie mit mehreren unabhängigen
Teilnehmern daher **zwingend** und bis dahin ein expliziter Blocker (siehe
`LAUNCH-CHECKLIST.md`, Gate G1). Dieses Whitepaper macht diesen Vorbehalt bewusst
transparent.

### 9.2 Reife-Status
- **Open Testnet:** code-seitig bereit (Konsens, ZK, DA, Forced Inclusion,
  Multi-Node verifiziert).
- **Mainnet:** code-seitig vollständig; ausstehend sind die externen Gates —
  MPC-Ceremony (9.1), externes Circuit-/Konsens-**Audit** und ein öffentliches
  Langzeit-Testnet. Erst danach ein Launch mit Werten.

### 9.3 Ausblick
- **Post-Quantum-L2-Signaturen:** gitterbasierte In-Circuit-Signatur, um auch die
  L2 quantensicher zu machen.
- **Beweissystem-Migration:** Evaluierung transparenter, setup-freier Systeme
  (z. B. Plonky2/3, STARKs) zur Beseitigung des Trusted-Setup.
- **Aggregator-Dezentralisierung:** mehrere konkurrierende Aggregatoren mit
  bid-basierter Auswahl (Forced Inclusion sichert bereits heute die Liveness ab).
- **Proving-Performance:** GPU-Beweis, rekursive Aggregation, größere Batches.

---

## 10. Glossar

| Begriff | Bedeutung |
|---|---|
| **L1** | Layer 1 — die PoW-gesicherte Basisschicht (UTXO) |
| **L2** | Layer 2 — der kontobasierte ZK-Rollup |
| **TRIAD** | Der speicherharte Proof-of-Work-Algorithmus von ATLAS |
| **Aggregator** | Dienst, der L2-TX bündelt und Zustandsbeweise erzeugt |
| **SettlementBid** | L1-Transaktion, die einen bewiesenen L2-Batch einreicht |
| **AccountTree** | Merkle-Baum (Tiefe 32) des L2-Kontozustands |
| **State-Root** | Merkle-Wurzel des L2-Zustands |
| **Data Availability** | On-Chain-Veröffentlichung der L2-Calldata |
| **Forced Inclusion** | Protokoll-Escape-Hatch: erzwungene Aufnahme einer L2-TX via L1 |
| **Groth16** | Verwendetes zk-SNARK-Beweissystem |
| **Baby-Jubjub-EdDSA** | In-Circuit-verifizierbare L2-Signatur (embedded curve über BN254) |
| **Trusted Setup / MPC** | Schlüssel-Erzeugung für Groth16; sicher nur als Mehr-Parteien-Zeremonie |
| **ML-DSA-65** | Post-quantum-Signaturverfahren der L1 (CRYSTALS-Dilithium3, FIPS 204) |
| **ATOM / UNIT / ATL** | Geldeinheiten (1 ATL = 10¹² ATOM) |

---

*Dieses Whitepaper beschreibt den aktuellen Implementierungsstand von ATLAS (v1.1,
Juni 2026) und dient als technische Referenz. Parameter (Blockzeit, Batch-Größe,
Durchsatzziele, Genesis-Allokation) sind netzwerkabhängig konfigurierbar und können
sich vor dem Mainnet-Start ändern. Ein Mainnet-Launch mit echten Werten setzt die
in Abschnitt 9.1 und in `LAUNCH-CHECKLIST.md` genannten externen Gates voraus —
insbesondere eine echte MPC-Trusted-Setup-Zeremonie und ein externes Audit.*
