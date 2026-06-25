# ATLAS — Phase-1-/Setup-Soundness-Spezifikation (für Kryptograf + Audit)

**Status:** offen — dies ist der **Mainnet-Blocker G1** aus `LAUNCH-CHECKLIST.md`.
**Zweck dieses Dokuments:** Den sicherheitstragenden Kern der Trusted-Setup-Ceremony
so präzise spezifizieren, dass ein Kryptograf/Auditor ihn vervollständigen und
prüfen kann — ohne bei Null anzufangen. Der ATLAS-Autor implementiert diesen Kern
**bewusst nicht** freihändig (subtile Fehler brechen die Garantie lautlos; siehe
`CEREMONY.md`).

Querverweise: `CEREMONY.md` (Plan + Ist-Stand), `crates/atlas-zk/src/mpc.rs`
(δ-Re-Randomisierung), `crates/atlas-zk/src/bin/zk_phase2.rs` (Transcript-Tool).

---

## 1. Kontext & Bedrohungsmodell

ATLAS-L2 ist ein Groth16-ZK-Rollup über **BN254** (alt_bn128). Der
`StateTransitionCircuit` (in-Circuit Baby-Jubjub-EdDSA + Poseidon-Merkle,
`batch_size = L2_BATCH_SIZE = 16`) beweist gültige L2-Zustandsübergänge. Der Node
verifiziert diese Beweise nativ gegen einen eingebetteten Verifying Key (`state_vk.bin`).

**Ökonomische Besonderheit:** ATLAS hat **keine Bridge, kein Mint/Burn**. Die
gesamte Geldmenge entsteht in der Genesis-Allokation; alle weiteren Bewegungen
sind L2-Transfers, deren Korrektheit **ausschließlich** der Groth16-Beweis
garantiert. **Folge:** Wer gültige Beweise für FALSCHE Zustandsübergänge erzeugen
kann, kann Guthaben aus dem Nichts schöpfen oder stehlen — ohne dass irgendeine
andere Schicht das auffängt. Die Soundness des Setups ist damit gleichbedeutend
mit der Integrität der gesamten Geldmenge.

**Der „toxic waste":** Groth16 braucht einen circuit-spezifischen Trusted Setup mit
geheimen Zufallswerten α, β, γ, δ, τ. Wer eine ausreichende Teilmenge davon kennt
(insb. τ bzw. α/β), kann beliebige Beweise fälschen. Ziel der Ceremony: Es darf
**keine Partei und keine Koalition unter ⟨alle Teilnehmer⟩** diese Werte
rekonstruieren können — solange **mindestens ein** Teilnehmer ehrlich seine
Zufälligkeit vernichtet hat.

---

## 2. Ist-Zustand (was vorhanden ist — und warum es NICHT genügt)

| Baustein | Datei | Status |
|---|---|---|
| Schlüsselerzeugung | `crates/atlas-zk/src/setup.rs:32`, `src/bin/zk_setup_state.rs:31` | `Groth16::<Bn254>::circuit_specific_setup(dummy(16), OsRng)` — **alles auf einer Maschine** |
| δ-Re-Randomisierung | `crates/atlas-zk/src/mpc.rs` (`contribute`) | funktional korrekt, getestet; transformiert **nur δ** |
| Ceremony-Ablauf/Transcript | `crates/atlas-zk/src/bin/zk_phase2.rs` | init/contribute/verify/finalize + öffentliches Transcript |
| Beitrags-Echtheitsprüfung | `mpc.rs::verify_contribution_structural` | prüft nur **Struktur**, NICHT Soundness (kein PoK) |

**Kernproblem (der eigentliche Befund):** `circuit_specific_setup` erzeugt α, β, γ,
δ, τ **in einem Zug auf einer Maschine**. Eine reine δ-Phase-2 (das, was `mpc.rs`
heute kann) re-randomisiert **nur δ**. **α, β und τ bleiben der Initial-Maschine
bekannt — und deren Kenntnis allein erlaubt bereits das Fälschen von Beweisen.**
Eine δ-only-Phase-2 auf `circuit_specific_setup` macht das Setup also **nicht**
fälschungssicher; sie würde nur falsche Sicherheit vorgaukeln.

**Es fehlen zwei Dinge** (beide sicherheitstragend, beide hier spezifiziert):
1. **Phase 1 (Powers of Tau) für α/β/τ** — statt Single-Machine.
2. **Beitrags-Proof-of-Knowledge (PoK)** für jeden Phase-2-δ-Beitrag.

---

## 3. Zielkonstruktion

Standard-Groth16-MPC nach **[BGM17]** („Scalable Multiparty Computation for
zk-SNARK Parameters in the Random Beacon Model"), wie von `snarkjs`/Hermez gelebt:

### Phase 1 — universell, circuit-UNABHÄNGIG (Powers of Tau)
Behandelt τ, α, β. Ergebnis: `{ [τ^i]₁ }`, `{ [τ^i]₂ }`, `{ [α·τ^i]₁ }`,
`{ [β·τ^i]₁ }`, `[β]₂` bis zum benötigten Grad.

**ATLAS muss Phase 1 NICHT selbst durchführen.** BN254 ist identisch zur Kurve der
**Perpetual Powers of Tau** (Hermez/snarkjs, `bn128`). Diese Ceremony hat
zahlreiche unabhängige Teilnehmer und einen öffentlichen Beacon — wir **lesen ein
existierendes, verifiziertes PoT-Ergebnis ein** und sparen uns ein eigenes Phase-1.

**Benötigter Grad:** Der QAP-Grad ist die nächste Zweierpotenz ≥
`num_constraints + num_instance_variables` des `StateTransitionCircuit` bei
`batch_size = 16`. Gemessen ≈ **746.000 Constraints** → Domain **2²⁰ = 1.048.576**.
→ Eine PPoT-Datei mit **Grad ≥ 2²⁰** (Hermez liefert bis 2²⁸) genügt.
*Implementierungspflicht:* Den exakten Wert via
`ConstraintSystem::num_constraints()` + `num_instance_variables()` bestätigen und
die `ptau`-Stufe entsprechend wählen (eine zu kleine Datei MUSS hart abgelehnt
werden).

### Phase 2 — circuit-SPEZIFISCH (δ)
Aus dem Phase-1-Ergebnis + dem konkreten QAP des `StateTransitionCircuit` werden
die initialen Groth16-Parameter abgeleitet (das ersetzt das heutige
`circuit_specific_setup`). Anschließend tragen N Teilnehmer **sequenziell** je einen
geheimen δ-Faktor bei und vernichten ihn; ein **öffentlicher Beacon** (z. B. ein
künftiger Bitcoin-Blockhash) bildet den letzten Beitrag. Jeder Beitrag ist
öffentlich verifizierbar (PoK, §5).

---

## 4. Zwei verantwortbare Umsetzungswege

### Weg A — circom + snarkjs (EMPFOHLEN für echtes Geld)
Den `StateTransitionCircuit` nach **circom** portieren; `snarkjs groth16` nutzt PPoT
(`.ptau`) + Phase-2 mit Beitrags-PoK + Beacon **out of the box**, kampferprobt &
weit auditiert.
- **Pro:** geringstes Eigen-Krypto-Risiko; die sicherheitstragende Maschinerie ist
  vetted; `.zkey`-Verifikation ist standardisiert.
- **Contra:** Circuit-Rewrite (In-Circuit-EdDSA, Poseidon, Merkle) in circom; der
  **Node-Verifier** muss das snarkjs-VK-Format lesen (oder VK → arkworks-Format
  konvertieren); Proving-Pfad wechselt. Großer, aber klar abgegrenzter Umbau.
- **Bit-Genauigkeit:** circom-Poseidon/EdDSA-Parameter MÜSSEN bit-identisch zum
  bisherigen `atlas-zk` sein (sonst ändert sich `GENESIS_L2_ROOT` und die
  bestehende DA-/Calldata-Logik bricht). Diese Äquivalenz ist Audit-Gegenstand.

### Weg B — arkworks-nativ
PoT-Ingest + Phase-2-Ableitung selbst in Rust/arkworks bauen (arkworks 0.4 bietet
**nichts** davon out of the box → effektiv „snarkjs in arkworks nachbauen").
- **Pro:** kein circom-Rewrite, gesamter bestehender Stack bleibt.
- **Contra:** **selbstgeschriebene, sicherheitskritische Krypto** — nur akzeptabel,
  wenn vollständig Teil des externen Audits (G2). Höheres Risiko als Weg A.

**Empfehlung:** Für ein Netz mit echtem Wert **Weg A**. Weg B nur, wenn ein
Kryptograf den Kern schreibt UND auditiert.

---

## 5. Spezifikation des Beitrags-Proof-of-Knowledge (gilt für beide Wege)

Jeder δ-Beitrag transformiert δ → δ·s mit geheimem s. Heute (`mpc.rs::contribute`)
passiert genau das, aber **ohne Nachweis, dass der Beitragende s kennt und konsistent
in G1 und G2 angewandt hat**. Ohne diesen Nachweis kann ein bösartiger Beitrag die
Kette brechen, ohne dass `verify` es bemerkt.

**Zu implementieren (Standard-BGM17-Beitragsnachweis):**
- Beitragender wählt s ∈ 𝔽ᵣ\{0}, setzt δ′₁ = s·δ₁ (G1), δ′₂ = s·δ₂ (G2).
- **PoK von s, bindend G1↔G2:** Fiat-Shamir-Challenge
  `r = H(transcript ∥ δ₁ ∥ δ′₁ ∥ δ₂ ∥ δ′₂)` (Hash-to-G1 oder Hash-to-Scalar je nach
  Schema), dann Antwort, die per **Pairing-Gleichung** prüft, dass derselbe Skalar s
  in G1 und G2 verwendet wurde (`e(δ′₁, [r]₂) = e([r]₁, δ′₂)`-artige
  Konsistenz; exakte Form gemäß BGM17/snarkjs).
- **Transcript:** je Beitrag {δ-vorher-Hash, δ-nachher-Hash, PoK} öffentlich anhängen
  (Format bereits in `zk_phase2.rs` vorhanden — um das PoK-Feld erweitern).
- `verify` MUSS: (a) die δ-Kette lückenlos prüfen (δ_after[i] == δ_before[i+1]),
  (b) jeden PoK verifizieren, (c) prüfen, dass die finalen PK/VK-Elemente
  konsistent zum letzten δ und zum Phase-1-Input stehen.

---

## 6. Integrationspunkte in diesem Repo

| Was | Wo | Änderung |
|---|---|---|
| Setup-Quelle | `crates/atlas-zk/src/setup.rs`, `bin/zk_setup_state.rs` | `circuit_specific_setup` ersetzen durch „aus Phase-1 + QAP abgeleitete Initialparameter" (Weg B) **oder** snarkjs-`.zkey`-Import (Weg A) |
| δ-Beitrag | `crates/atlas-zk/src/mpc.rs::contribute` | um PoK-Erzeugung erweitern (§5) |
| Echtheitsprüfung | `mpc.rs::verify_contribution_structural` | durch echte PoK-Verifikation ersetzen |
| Ablauf/Transcript | `bin/zk_phase2.rs` | Phase-1-Ingest + PoK-Felder + Beacon-Schritt; init darf NICHT mehr `circuit_specific_setup` nutzen |
| VK-Einbettung | `crates/atlas-zk/src/lib.rs` (`state_vk.bin` via `include_bytes!`) | finalen, aus der echten Ceremony stammenden VK einsetzen; VK-Hash im Release publizieren |
| Genesis-Konsistenz | `crates/atlas-core/src/block.rs` (`GENESIS_L2_ROOT`) | bei Weg A sicherstellen, dass Poseidon-Parameter bit-identisch bleiben (sonst Root-Bruch) |

---

## 7. Operativer Ablauf der Ceremony (sobald §3–§5 stehen)

1. **Phase-1 wählen & verifizieren:** öffentliche PPoT-Datei (bn128, Grad ≥ 2²⁰),
   deren Transcript/Beacon nachvollziehen; Hash veröffentlichen.
2. **Phase-2-Init (Koordinator):** initiale Parameter aus Phase-1 + Circuit-QAP
   ableiten; Transcript-Start veröffentlichen.
3. **Beiträge (je Teilnehmer, idealerweise Airgap):** laden → `contribute` (mit PoK)
   → Zufälligkeit/Maschine vernichten → Beitrags-Attestation veröffentlichen.
4. **Beacon:** öffentliche, unvorhersehbare Zufälligkeit (z. B. künftiger
   Bitcoin-Blockhash) als finaler Beitrag.
5. **Finalize:** `state_vk.bin` (ins Node-Binary), `state_pk.bin` (an Aggregatoren);
   vollständiges Transcript publizieren.
6. **Verifikation:** Jeder kann Transcript + alle PoKs prüfen; der im Release
   bekanntgegebene VK-Hash wird gegen den eingebetteten VK abgeglichen.

---

## 8. Abnahmekriterien (Audit-Checkliste G1)

- [ ] Phase-1-Quelle ist eine **öffentliche, mehrparteiige** PPoT (bn128), korrekt
      verifiziert; Grad ≥ Circuit-Domain; zu kleine Datei wird hart abgelehnt.
- [ ] **Kein** `circuit_specific_setup`/Single-Machine-RNG mehr im Setup-Pfad.
- [ ] Jeder Phase-2-Beitrag trägt einen **PoK**, der G1↔G2-Konsistenz von s
      beweist; `verify` lehnt jeden ungültigen/strukturell-nur-geprüften Beitrag ab.
- [ ] δ-Kette im Transcript lückenlos; finaler VK/PK konsistent zu Phase-1 + letztem δ.
- [ ] **Beacon** als letzter Beitrag dokumentiert.
- [ ] Reproduzierbarkeit: unabhängige Dritte können das gesamte Transcript
      nachrechnen und den eingebetteten VK-Hash bestätigen.
- [ ] (Weg A) Bit-Äquivalenz circom-Circuit ↔ `atlas-zk` für Poseidon/EdDSA/Merkle
      nachgewiesen; `GENESIS_L2_ROOT` unverändert.
- [ ] Toxic-waste-Vernichtung je Teilnehmer attestiert.

**Solange auch nur EIN Kriterium offen ist, bleibt der Setup fälschbar und das
Mainnet ein offenes Scheunentor (siehe `LAUNCH-CHECKLIST.md` G1).**

---

## 9. Referenzen

- **[BGM17]** Bowe, Gabizon, Miers — *Scalable Multiparty Computation for zk-SNARK
  Parameters in the Random Beacon Model*, ePrint 2017/1050.
- **[Groth16]** Groth — *On the Size of Pairing-based Non-interactive Arguments*.
- **Perpetual Powers of Tau** (bn128): github.com/privacy-scaling-explorations/perpetualpowersoftau
- **snarkjs** (Phase-2 + Beacon + PoK-Referenzimplementierung): github.com/iden3/snarkjs
- ATLAS-intern: `CEREMONY.md`, `crates/atlas-zk/src/mpc.rs`, `crates/atlas-zk/src/bin/zk_phase2.rs`.
