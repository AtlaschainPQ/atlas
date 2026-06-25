# ATLAS — Trusted-Setup-Ceremony (Plan)

Ziel: den **Single-Point-of-Trust** im Groth16-Setup beseitigen, sodass NIEMAND
beliebige Beweise fälschen (= Geld schöpfen/stehlen) kann. Dies ist der harte
Mainnet-Blocker G1 aus `LAUNCH-CHECKLIST.md`.

## Hintergrund (warum überhaupt)
Groth16 braucht einen circuit-spezifischen Trusted Setup. Die Schlüsselerzeugung
involviert geheime Zufallswerte (α, β, γ, δ, τ — der „toxic waste"). Wer diese
kennt, kann gültige Beweise für FALSCHE Aussagen erzeugen. Der Setup zerfällt in:

- **Phase 1 (universell, „Powers of Tau"):** behandelt τ/α/β, ist circuit-unabhängig.
  → Kann ein **öffentliches, bestehendes BN254-Ergebnis wiederverwenden**
  (z. B. Perpetual Powers of Tau / Hermez). Müssen wir NICHT selbst durchführen.
- **Phase 2 (circuit-spezifisch, δ):** MUSS für den `StateTransitionCircuit`
  durchgeführt werden. N Teilnehmer tragen nacheinander einen geheimen Zufalls-
  faktor bei und vernichten ihn; **solange EIN Teilnehmer ehrlich ist, ist der
  toxic waste unrekonstruierbar.** Jeder Beitrag ist öffentlich verifizierbar.

## Ist-Zustand (ungenügend für Mainnet)
- `zk_setup_state` / `zk_ceremony` nutzen `Groth16::circuit_specific_setup` —
  **ein einziger RNG auf einer Maschine**. Keine MPC.
- `zk_ceremony` sammelt zusätzlich Entropie-Beiträge und mischt frische
  Zufälligkeit beim Finalize. Das erschwert die nachträgliche Rekonstruktion aus
  der öffentlichen `ceremony.json`, ändert aber NICHTS daran, dass die
  **Finalize-Maschine den Seed im Erzeugungsmoment kennt**. → Kein Ersatz für Phase 2.

## Operativer Ablauf (sobald ein Phase-2-Mechanismus steht)
1. **Koordinator** erzeugt aus öffentlichem Phase-1 + Circuit die initialen Parameter.
2. **Jeder Teilnehmer** (idealerweise auf einer Airgap-Maschine):
   - lädt den aktuellen Stand, trägt geheime Zufälligkeit bei (`contribute`),
   - vernichtet seine Zufälligkeit (Maschine wipen),
   - veröffentlicht seinen Beitrags-Hash/Attestation.
3. **Abschluss-Beacon:** öffentliche, unvorhersehbare Zufälligkeit (z. B. ein
   künftiger Bitcoin-Blockhash) als letzter Beitrag.
4. **Finalize:** `state_vk.bin` (ins Node-Binary einbetten), `state_pk.bin`
   (an Aggregatoren). Vollständiges **Transcript** veröffentlichen.
5. **Verifikation:** Jeder kann das Transcript prüfen; der VK-Hash wird im Release
   bekannt gegeben und mit dem eingebetteten VK abgeglichen.

## Offene Entscheidung: WIE Phase 2 für DIESEN Circuit?
Der Circuit ist in **arkworks** geschrieben. Zwei verantwortbare Wege:

### Weg A — circom + snarkjs (vetted Tooling)
Circuit nach circom portieren, dann snarkjs-`groth16`-Phase-2 + öffentliches PoT
nutzen. **Pro:** kampferprobte, weit auditierte Tools; geringes Eigen-Krypto-Risiko.
**Contra:** `StateTransitionCircuit` (In-Circuit-EdDSA, Merkle, Poseidon) muss neu
in circom geschrieben werden; Proving/Verifikation wechseln auf das snarkjs-Format
(VK-Format + Node-Verifier anpassen). Großer Umbau.

### Weg B — arkworks-natives Phase-2
δ-Beitrags-Phase-2 in Rust/arkworks implementieren (PK-Elemente pro Beitrag mit
geheimem Skalar transformieren + Konsistenzbeweis). **Pro:** behält den gesamten
bestehenden Stack; kein circom-Rewrite. **Contra:** **selbstgeschriebene Krypto** —
ein subtiler Fehler bricht die MPC-Garantie lautlos (funktionale Tests bemerken es
NICHT). Daher **nur akzeptabel, wenn es Teil des externen Audits (G2) ist** —
was ohnehin Pflicht ist.

### Nicht-Option
Das aktuelle Entropie-`zk_ceremony` als „die Ceremony" auszugeben. Es ist KEIN
Phase-2 und macht das Mainnet nicht fälschungssicher.

## ⚠️ Kritischer Soundness-Befund (beim Aufsetzen von Weg B entdeckt)
arkworks' `Groth16::circuit_specific_setup` erzeugt **α, β, γ, δ, τ in einem
Zug auf einer Maschine**. Eine reine **δ-Phase-2** (das, was man „obendrauf"
implementieren würde) re-randomisiert NUR δ. **α, β und τ bleiben der
Initial-Maschine bekannt — und deren Kenntnis erlaubt bereits das Fälschen von
Beweisen.** Eine δ-only-Phase-2 auf `circuit_specific_setup` macht das Setup
also NICHT fälschungssicher; sie würde nur falsche Sicherheit vorgaukeln.

**Konsequenz:** Ein *sounder* Weg B braucht ZUSÄTZLICH eine Phase 1 (Powers of
Tau) für α/β/τ — entweder eine öffentliche BN254-PoT **einlesen und den Circuit
darauf spezialisieren** (das, was `snarkjs groth16 setup` tut) oder eine eigene
PoT-Ceremony. arkworks bietet davon **nichts** out-of-the-box. Damit ist ein
vollständig sounder Weg B ≈ „snarkjs in arkworks nachbauen" — **großer Umfang
UND selbstgeschriebene, sicherheitskritische Krypto ohne erprobte Tools.**

## Ehrliche Empfehlung (revidiert)
1. Die **sicherheitskritische** MPC-/Phase-1-Krypto sollte ich für ein Netz mit
   echtem Geld **nicht als alleiniger Autor frei aus dem Kopf** schreiben — genau
   hier brechen subtile Fehler die Garantie lautlos (funktionale Tests merken es
   NICHT). Das ist Cryptographer-+-Audit-Territorium.
2. Wenn maximale Soundness mit erprobten Tools das Ziel ist, ist **Weg A**
   (circom + snarkjs, inkl. korrekter PoT-Wiederverwendung) der sichere Weg —
   trotz Circuit-Rewrite.
3. Was ich verantwortbar SOFORT bauen kann: die **nicht-sicherheitskritische
   Infrastruktur** der Ceremony (Koordination, Transcript-Format, Beitrags-Flow,
   δ-Re-Randomisierung mit funktionalen Tests), sodass ein Kryptograf/Auditor nur
   noch den sicherheitstragenden Kern (Beitrags-Proof-of-Knowledge + Phase-1)
   prüfen/vervollständigen muss — statt bei Null anzufangen.

**Unverändert gilt:** erst nach Audit UND vollständig + korrekt durchgeführter
Ceremony (Phase 1 + Phase 2) darf echtes Geld aufs Netz.

---

## Stand der Umsetzung (2026-06-14)

### ✅ Gebaut & getestet (das verantwortbare Gerüst)
- **`crates/atlas-zk/src/mpc.rs`** — funktional korrekte **δ-Re-Randomisierung**
  des Groth16-Proving-Keys (`contribute`). Tests beweisen: nach mehreren Beiträgen
  verifizieren echte Beweise weiter, falscher Public-Input wird abgelehnt, δ ändert
  sich bei jedem Beitrag.
- **`crates/atlas-zk/src/bin/zk_phase2.rs`** — operatives Ceremony-Tool:
  ```
  cargo run -p atlas-zk --release --bin zk_phase2 -- init
  cargo run -p atlas-zk --release --bin zk_phase2 -- contribute <name>   # je Teilnehmer, Airgap
  cargo run -p atlas-zk --release --bin zk_phase2 -- verify               # Transcript-Kette
  cargo run -p atlas-zk --release --bin zk_phase2 -- finalize             # state_vk/pk schreiben
  ```
  Führt ein öffentliches Transcript (`keys/phase2_transcript.json`) mit δ-Hashes
  pro Beitrag. End-to-End auf dem echten State-Circuit-Key (281 MB) getestet.

### ❌ Bewusst NICHT gebaut (Cryptographer + Audit)
1. **Phase-1-PoT-Ingest** für α/β/τ. `init` nutzt noch `circuit_specific_setup`
   (single-machine). Ohne PoT-Wiederverwendung/-Ceremony bleibt das Setup
   fälschbar — **die δ-Beiträge allein genügen NICHT.**
2. **Beitrags-Proof-of-Knowledge** (Bindung von s in G1↔G2 via Fiat-Shamir).
   Ohne ihn sind Beiträge nicht auf Ehrlichkeit prüfbar
   (`verify_contribution_structural` prüft nur Struktur, nicht Soundness).

Diese zwei Punkte sind der sicherheitstragende Kern und MÜSSEN von einem
Kryptografen ergänzt und im externen Audit (G2) geprüft werden, bevor die
erzeugten Keys ein Netz mit echtem Geld absichern dürfen.

➡️ **Präzise, umsetzungsreife Spezifikation dieser zwei Punkte:**
`CEREMONY-PHASE1-SPEC.md` — Bedrohungsmodell, Zielkonstruktion (BGM17), benötigter
BN254-PoT-Grad (≥ 2²⁰), PoK-Schema, exakte Integrationspunkte im Code (`setup.rs`,
`mpc.rs`, `zk_phase2.rs`) und Audit-Abnahmekriterien.
