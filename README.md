# ATLAS Blockchain

Hochskalierbare Proof-of-Work-L1 mit Zero-Knowledge-Rollup-L2 für globale
Zahlungen und Settlement. Optimiert für Heimhardware-Validatoren. Dauerhaft
niedrige Nutzergebühren. Post-Quantum-sicher auf L1 durch ML-DSA-65
(CRYSTALS-Dilithium3, NIST FIPS 204).

> ⚠️ **Status: experimentell — Testnet-tauglich, NICHT mainnet-tauglich.**
> Der Code ist umfangreich getestet (211 Tests, Multi-Node- und echte
> Groth16-ZK-E2E), aber **nicht extern auditiert**, und es gab **keine echte
> MPC-Trusted-Setup-Zeremonie**. Betreibe **kein Mainnet mit echtem Wert** auf
> diesem Stand — auf dem aktuellen Single-Party-Setup sind Beweise fälschbar.
> Lizenz: MIT (siehe [`LICENSE`](LICENSE)).

**Dokumentation:** [Whitepaper](WHITEPAPER.md) ·
[Status / Mainnet-Readiness](MAINNET-READINESS.md) ·
[Launch-Checkliste](LAUNCH-CHECKLIST.md) ·
[Testnet-Teilnahme](TESTNET.md) · [Web-Wallet](web-wallet/README.md) ·
[Sicherheit](SECURITY.md)

---

## Inhaltsverzeichnis

1. [Architektur](#architektur)
2. [Währungssystem](#währungssystem)
3. [Geldpolitik](#geldpolitik)
4. [Kryptographie](#kryptographie)
5. [TRIAD Proof-of-Work](#triad-proof-of-work)
6. [Netzwerk & RPC](#netzwerk--rpc)
7. [Wallet](#wallet)
8. [Schnellstart](#schnellstart)
9. [Sicherheitsmodell](#sicherheitsmodell)

---

## Architektur

```
atlas/
  crates/
    atlas-core/        Basistypen: Block, Transaction, Hash, Amount, Kryptographie
    atlas-triad/       TRIAD PoW-Algorithmus (Memory-Hard, ASIC-resistent)
    atlas-consensus/   Validierung, Difficulty, Halving, Reward, Security Floor
    atlas-state/       UTXO-Set (RAM), Block-Executor, RocksDB-Persistenz
    atlas-mempool/     Mempool, TX-Stamp-Verifikation, Fee-Sortierung
    atlas-node/        Full Node, Chain Manager, P2P-Netzwerk, JSON-RPC, Mining
    atlas-wallet/      CLI-Wallet (ECDSA + ML-DSA-65)
    atlas-zk/          ZK-Proof Stub (MiMC/Groth16)
  miner/               C++ TRIAD Mining Engine (SIMD-optimiert)
```

### Schichtenmodell

```
┌─────────────────────────────────────────────────────────┐
│  Layer 2 — Execution                                    │
│  RAM-basierte Verarbeitung · 40 000+ TPS · ZK-Proofs   │
├─────────────────────────────────────────────────────────┤
│  Layer 1 — Settlement                                   │
│  TRIAD PoW · UTXO-Konsens · Finalität                  │
└─────────────────────────────────────────────────────────┘
```

**Determinism Firewall:** Rust entscheidet über Gültigkeit. C++ Mining liefert nur Nonce-Kandidaten.

---

## Währungssystem

| Einheit | Wert               | Verwendung           |
|---------|--------------------|----------------------|
| ATL     | 1 ATL              | Anzeige, Preise      |
| UNIT    | 0,00000001 ATL     | Kompatibilitätsebene |
| ATOM    | 0,000000000001 ATL | Gebühren, Protokoll  |

```
1 ATL  = 1 000 000 000 000 ATOM  (10^12)
1 ATL  = 100 000 000 UNIT        (10^8)
1 UNIT = 10 000 ATOM
```

ATOM ermöglicht extrem niedrige Gebühren selbst bei hohem ATL-Preis (< 0,001 € bei 100 Mio € / ATL).

---

## Geldpolitik

ATLAS hat **eine** Geldmenge, und sie lebt auf der **L2** (kontobasiert). Sie speist
sich aus zwei Quellen, **beide direkt auf L2-Konten** gutgeschrieben:
die **Genesis-Allokation** (Anfangsverteilung) und die **PoW-Block-Emission**.

| Parameter          | Wert                                  |
|--------------------|---------------------------------------|
| Anfangsverteilung  | Genesis-Allokation (L2-Konten)        |
| Start-Reward       | 200 ATL / Block                       |
| Halving-Intervall  | 250 000 Blöcke (~4,75 Jahre), max. 32 |
| Blockzeit (Ziel)   | ~10 Minuten (Mainnet)                 |
| Emissions-Cap      | +100 000 000 ATL (gesamtes Mining)    |
| Gesamtmenge        | Genesis-Allokation + ≤ 100 Mio ATL    |

> **Modell A:** Die PoW-Emission wird **direkt den L2-Konten** von Miner/Prover
> gutgeschrieben — es gibt **keinen separaten L1-Coin** und **keine Bridge**; die
> L1 ist reine PoW-Sicherheits-/Settlement-Schicht. *(Status: als einheitliche
> Geldpolitik beschlossen; Code-Umsetzung der L2-Gutschrift in Arbeit — aktuell
> mintet der Code die Emission noch L1-seitig.)*

### Emissionsplan

| Era | Startblock | ATL/Block | Era-Gesamt (ATL) |
|-----|-----------|-----------|------------------|
| 0   | 0         | 200       | 50 000 000       |
| 1   | 250 000   | 100       | 25 000 000       |
| 2   | 500 000   | 50        | 12 500 000       |
| 3   | 750 000   | 25        | 6 250 000        |
| …   | …         | …         | Σ → 100 000 000  |

### Reward-Verteilung

```
BlockReward = Subsidy + TxFees

Miner:  70 %  (Subsidy + Fees)
Prover: 30 %  (Subsidy + Fees)
```

### Gebührenmodell

```
Min-Fee:  10 ATOM   (Protokoll-Minimum)
Max-Fee: 100 ATOM   (Fee-Cap, User-Schutz)
```

### Adaptiver Security Floor

Wenn die durchschnittliche Fee unter einen Schwellwert fällt, wird das nächste Halving verzögert.
Keine Governance nötig — der Algorithmus schützt die Mining-Wirtschaftlichkeit automatisch.

---

## Kryptographie

### ECDSA (klassisch)

- Schlüssel: secp256k1 (32 Bytes Privat, 33 Bytes Komprimiert Public)
- Adress-Präfix: `ATL:`
- Adresse: `ATL:<40 Hex>` = RIPEMD160(SHA256(pk))

### ML-DSA-65 (Post-Quantum)

ATLAS unterstützt Post-Quantum-Signaturen nach **NIST FIPS 204** (CRYSTALS-Dilithium Level 3):

| Parameter     | Wert            |
|---------------|-----------------|
| Public Key    | 1 952 Bytes     |
| Secret Key    | 4 032 Bytes     |
| Signatur      | 3 309 Bytes     |
| Sicherheit    | 128-Bit PQ / 192-Bit klassisch |
| Adress-Präfix | `ATLQ:`         |

PQ-Adressen und klassische Adressen sind vollständig interoperabel:
- ECDSA-Wallets können ATL an ATLQ:-Adressen senden und umgekehrt
- Jede TX-Ausgabe trägt explizit den Adresstyp (`Classic` / `Quantum`)

### TX-Stamp (Spam-Schutz)

Jede Transaktion trägt einen Mini-PoW (12 Leading-Zero-Bits):
- Erstellung: ~20–50 ms auf Consumer-Hardware
- Verifikation: O(1), nahezu kostenlos
- Schutz: wirtschaftlich teurer Spam ohne hohe Gebühren

---

## TRIAD Proof-of-Work

**Memory Bandwidth × Cache Dependency × Network Entropy**

| Eigenschaft         | Wert                       |
|--------------------|----------------------------|
| Dataset-Größe      | ~4 GB / Epoch              |
| Epoch-Länge        | 2 016 Blöcke (~2 Wochen)   |
| Accesses/Hash      | 64 datenabhängige Lookups  |
| GPU-Vorteil        | Begrenzt (RAM-Limit)       |
| ASIC-Attraktivität | Niedrig (Epoch-Rotation)   |

### Ziel-Hardware

```
CPU:  8–16 Kerne (AMD Ryzen / Intel Core)
RAM:  32 GB DDR4/DDR5
SSD:  1 TB NVMe (Chain-Daten + TRIAD-Dataset)
Net:  Breitband (> 10 Mbit/s)
```

---

## Netzwerk & RPC

### P2P

- **Protokoll:** Bincode-framed TCP mit TLS (self-signed, TOFU-Verifikation)
- **Peer-Discovery:** Addr/GetAddr-Gossip
- **Sync:** Header-First IBD, paralleler Block-Download von mehreren Peers
- **Schutz:** Rate-Limiter (200 Nachrichten/s), Peer-Scoring, automatische Bans, Keepalive-Ping

### JSON-RPC (HTTP)

Der Node bietet einen vollständigen JSON-RPC 2.0 Server (Standard-Port `8334`).

#### Chain

| Methode              | Parameter               | Rückgabe                    |
|----------------------|-------------------------|-----------------------------|
| `getblockcount`      | –                       | Aktuelle Kettenhöhe         |
| `getbestblockhash`   | –                       | Tip-Hash (hex)              |
| `getchaininfo`       | –                       | Höhe, Supply, Bits, …       |
| `getblock`           | `<hash \| height>`      | Vollständiger Block (JSON)  |
| `getblockheader`     | `<hash>`                | Block-Header (JSON)         |
| `gettransaction`     | `<txid>`                | TX aus Block oder Mempool   |

#### Wallet

| Methode        | Parameter       | Rückgabe                          |
|----------------|-----------------|-----------------------------------|
| `getbalance`   | `<ATL:…\|ATLQ:…>` | Saldo in ATL und ATOM          |
| `getutxos`     | `<ATL:…\|ATLQ:…>` | Alle UTXOs der Adresse         |

Beide Methoden unterstützen klassische (`ATL:`) und Post-Quantum-Adressen (`ATLQ:`).

#### Mempool

| Methode              | Parameter   | Rückgabe               |
|----------------------|-------------|------------------------|
| `getmempoolinfo`     | –           | Anzahl, Fees, Stats    |
| `getrawmempool`      | –           | Liste aller TXIDs      |
| `sendrawtransaction` | `<hex>`     | TXID                   |

#### Netzwerk

| Methode          | Parameter | Rückgabe                     |
|------------------|-----------|------------------------------|
| `getpeers`       | –         | Verbundene Peers + Höhen     |
| `getnetworkinfo` | –         | Peer-Anzahl, Version         |

#### Beispiel

```bash
# Block-Count
curl -s http://127.0.0.1:8334 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}'

# Saldo einer PQ-Adresse
curl -s http://127.0.0.1:8334 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":["ATLQ:abc123..."],"id":1}'

# Mit API-Key
curl -s http://127.0.0.1:8334 \
  -H "Authorization: Bearer <KEY>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getchaininfo","params":[],"id":1}'
```

### Persistenz (RocksDB)

Der Node speichert alle Daten in `<data-dir>/chain/` mit 7 Column Families:

| Column Family | Schlüssel             | Wert                          |
|---------------|-----------------------|-------------------------------|
| `blocks`      | Block-Hash (32 B)     | Serialisierter Block          |
| `height`      | Höhe (8 B BE)         | Block-Hash (32 B)             |
| `txindex`     | TxId (32 B)           | Höhe (8 B) ‖ Tx-Pos (4 B)    |
| `chain`       | `"state"`             | Serialisierter ChainState     |
| `utxos`       | OutPoint (bincode)    | Serialisiertes Utxo           |
| `peers`       | `"peers"`             | Vec\<SocketAddr>              |
| `mempool`     | `"txs"`               | Vec\<Transaction>             |

Block + Height-Index + TX-Index werden atomar in einem `WriteBatch` geschrieben.
UTXO-Updates sind inkrementell (Delta pro Block, kein Full-Rewrite).

### Prometheus Metrics

Optional unter Port `metrics_port` (Standard deaktiviert):

```
atlas_height          Gauge  Aktuelle Kettenhöhe
atlas_total_supply    Gauge  Umlaufmenge in ATOM
atlas_mempool_size    Gauge  Anzahl ausstehender TXs
atlas_utxo_count      Gauge  Größe des UTXO-Sets
atlas_avg_fee_atom    Gauge  Durchschnittliche Fee in ATOM
```

---

## Wallet

Das `atlas-wallet` CLI verwaltet ECDSA- und ML-DSA-65-Schlüssel in einer verschlüsselten JSON-Datei.

```
atlas-wallet [BEFEHL] [OPTIONEN]

Befehle:
  new-key      [--label NAME] [--wallet FILE]    Neuen ECDSA-Schlüssel generieren (ATL:)
  new-key-pq   [--label NAME] [--wallet FILE]    Neuen PQ-Schlüssel generieren (ATLQ:)
  import-key   --privkey HEX [--label NAME]      ECDSA-Schlüssel importieren
  list-keys    [--wallet FILE]                   Alle Schlüssel anzeigen
  balance      <ADDRESS> [--rpc URL]             Kontostand abfragen
  send         --from <ADDR> --to <ADDR>         ECDSA-Transfer senden
               --amount <ATOM> [--fee <ATOM>]
  send-pq      --from <ATLQ:ADDR> --to <ADDR>   Post-Quantum-Transfer senden
               --amount <ATOM> [--fee <ATOM>]
  height       [--rpc URL]                       Aktuelle Chain-Höhe

Optionen:
  --wallet   FILE   Wallet-Datei (Standard: wallet.json)
  --rpc      URL    Node RPC (Standard: http://127.0.0.1:8334)
  --api-key  KEY    RPC API-Key
```

Passwörter werden interaktiv abgefragt (kein Echo, kein Shell-History-Eintrag).

### Keystore-Format

```json
{
  "version": 3,
  "keys": [
    {
      "label": "main",
      "key_type": "classic",
      "address": "ATL:abcdef...",
      "encrypted_privkey": "<base64-AES-GCM>",
      "salt": "<base64>",
      "nonce": "<base64>"
    },
    {
      "label": "pq-main",
      "key_type": "quantum",
      "address": "ATLQ:abcdef...",
      "encrypted_privkey": "<base64-AES-GCM>",
      "salt": "<base64>",
      "nonce": "<base64>"
    }
  ]
}
```

Verschlüsselung: AES-256-GCM, Schlüsselableitung per Argon2id (OWASP-Empfehlung).

---

## Schnellstart

### Voraussetzungen

```
Rust  >= 1.75     (rustup: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh)
C++20 Compiler    (clang++ oder g++)
```

### Bauen

```bash
# Rust Workspace (alle Crates)
cargo build --release

# C++ Mining Engine (optional — nur für Mainnet-Mining)
cd miner
clang++ -std=c++20 -O3 -march=native \
  -I include \
  src/sha256.cpp src/cache.cpp src/dataset.cpp src/triad_miner.cpp \
  -shared -fPIC -o libatlas_triad.so
```

### Tests

```bash
# Alle 127 Rust-Unit- und Integrationstests
cargo test --workspace
```

### Node starten

```bash
# Regtest (lokales Testnet, kein PoW)
cargo run --bin atlas-node -- --network regtest --mining

# Mainnet
cargo run --release --bin atlas-node

# Mit Konfiguration
cargo run --release --bin atlas-node -- \
  --network mainnet \
  --data-dir /var/lib/atlas \
  --rpc-port 8334 \
  --p2p-port 8333 \
  --api-key mysecretkey
```

### Wallet benutzen

```bash
# Neues ECDSA-Wallet
cargo run --bin atlas-wallet -- new-key --label main

# Post-Quantum-Schlüssel hinzufügen
cargo run --bin atlas-wallet -- new-key-pq --label pq-main

# Schlüssel anzeigen
cargo run --bin atlas-wallet -- list-keys

# Saldo prüfen
cargo run --bin atlas-wallet -- balance ATL:abcdef...

# ECDSA-Transfer
cargo run --bin atlas-wallet -- send \
  --from ATL:abc... --to ATL:def... \
  --amount 1000000000000 --fee 100

# Post-Quantum-Transfer
cargo run --bin atlas-wallet -- send-pq \
  --from ATLQ:abc... --to ATLQ:def... \
  --amount 1000000000000 --fee 100
```

---

## Sicherheitsmodell

### Konsens

- **51%-Angriffe:** TRIAD-PoW mit 4-GB-Dataset (hohe Hardware-Anforderungen)
- **Long-Range-Angriffe:** Checkpoints + Security Delay
- **Timewarp:** Timestamp-Validierung (Future-Block-Limit, Monotonie)
- **Selfish Mining:** Standard-PoW-Anreizstruktur

### Netzwerk

- **Eclipse-Angriffe:** TOFU-TLS + Peer-Diversität
- **DoS:** Rate-Limiter (200 msg/s pro Peer), Peer-Scoring, automatische Bans
- **Sybil:** TLS-Identität + IP-basiertes Scoring
- **Replay-Angriffe:** TxId = Hash über alle TX-Felder inkl. Timestamp

### Kryptographie

- **Klassisch:** secp256k1 ECDSA (128-Bit Sicherheit)
- **Post-Quantum:** ML-DSA-65 (128-Bit PQ-Sicherheit, NIST FIPS 204)
- **Signatur-Schutz:** Secret Keys werden per Zeroize gelöscht nach Nutzung

### Gebühren

- **Spam:** TX-Stamp (Mini-PoW, 12 Bit) macht Massen-TX wirtschaftlich teuer
- **Fee-Manipulation:** Fee-Cap (100 ATOM Max) schützt User vor Erpressung
- **Mining-Wirtschaftlichkeit:** Adaptiver Security Floor verhindert Unterversorgung

---

## Lizenz

MIT
