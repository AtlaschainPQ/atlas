# ATLAS Open Testnet — Teilnahme-Anleitung

So nimmst du am ATLAS-Testnet teil — als Node, Miner oder Aggregator.
Das Testnet fährt die volle Mainnet-Mechanik (echte Groth16-Verifikation,
PoW, Data Availability, Forced Inclusion) — nur mit Test-Parametern
(3-s-Blockzeit). Wie das Mainnet startet es als **Fair Launch**: keine
Vorab-Allokation, Geld entsteht ausschließlich durch Mining.

> ⚠️ Testnet-Coins haben keinen Wert. Chain-Resets sind jederzeit möglich.

## 1. Bauen

Voraussetzungen: Rust (stable), ~8 GB RAM, ~10 GB Disk.

```bash
git clone <repo-url> atlas && cd atlas
cargo build --release
```

## 2. Node starten (Follower)

```bash
./target/release/atlas-node \
  --network testnet \
  --data-dir ~/.atlas-testnet \
  --p2p-port 18333 --rpc-port 18334
```

Bootstrap: trage den Seed-Node in eine Config-Datei ein (`--config node.json`):

```json
{
  "network": "testnet", "data_dir": "~/.atlas-testnet",
  "p2p_port": 18333, "rpc_port": 18334,
  "mining": false, "miner_address": null, "prover_address": null,
  "max_peers": 64, "mempool_max_size": 50000,
  "test_mode": false, "log_level": "info", "rpc_api_key": null,
  "seed_nodes": ["<SEED-NODE-IP>:18333"],
  "mining_threads": 0, "metrics_port": 0,
  "persist_mempool": true, "storage_mode": "full"
}
```

`<SEED-NODE-IP>` wird vom Testnet-Betreiber veröffentlicht. Der Node lädt
per IBD die Kette und verifiziert ALLE Beweise selbst (kein Vertrauen nötig).

## 3. Minen

```bash
./target/release/atlas-node --config node.json --mining --threads 4
```

Beim ersten Start wird das TRIAD-PoW-Dataset (4 GB) generiert (~10–15 min,
wird gecacht). Die Miner-Adresse wird automatisch erzeugt, falls nicht
konfiguriert (`miner_address`). **Wichtig (Fair Launch):** Mining ist der
EINZIGE native Förderpfad — die PoW-Emission wird direkt deinem
`miner_address`/`prover_address`-L2-Konto gutgeschrieben (Modell A). Wer
selbst mint, hat damit auch L2-Guthaben zum Senden.

## 4. An Guthaben kommen (Faucet) + L2-Transaktionen senden

Unter Fair Launch hat ein frisches Konto **kein** Guthaben. Zwei Wege:

1. **Selbst minen** (Abschnitt 3) — dein Miner-/Prover-Konto sammelt Emission.
2. **Faucet** — der Betreiber betreibt einen Faucet (aus geschürftem Guthaben).
   Fordere Test-ATOM für deine L2-Adresse an: `<FAUCET-URL>` (vom Betreiber
   veröffentlicht). Es gibt **keine** vorab geförderten Dev-Konten mehr (das
   war der Stand vor dem Fair Launch).

Senden geht am einfachsten über die **Web-Wallet** (`web-wallet/`, Browser,
Baby-Jubjub-EdDSA + Poseidon, byte-identisch zum Circuit) oder per CLI:

```bash
# Hochlast/Benchmark: viele TXs zwischen Seed-Konten (NUR sinnvoll, wenn diese
# Seeds gefördert sind — z.B. nachdem der Faucet sie gefüllt hat):
./target/release/atlas-sender --url <AGGREGATOR-IP>:8080 \
  --count 100 --senders 10 --amount 100 --fee 5
```

Eine einzelne signierte TX baust du mit der Web-Wallet (`build_submit_tx`) und
schickst sie per `POST <AGGREGATOR-IP>:8080/submit`.

## 5. Forced Inclusion (Zensurresistenz testen!)

Wenn ein Aggregator deine TX nicht aufnimmt, erzwinge sie direkt über L1 —
ganz ohne L1-Guthaben (Spam-Schutz: Mini-PoW-Stamp). Die TX braucht aber
**L2-Guthaben** für `amount`+`fee` (sonst wird sie nachweislich abgelehnt):

```bash
./target/release/atlas-sender --force --url <NODE-IP>:18334 \
  --seed <DEIN-SEED> --nonce 0 --index <DEIN-KONTO-INDEX> --amount 50 --fee 5
```

Konsens-Regel: Nach 200 Blöcken (~10 min) MUSS jedes Settlement deine TX
aufnehmen oder nachweislich (Merkle-Zeuge) ablehnen — sonst sind dessen
Blöcke ungültig. Status: RPC `getforcedqueue`.

## 6. Eigenen Aggregator betreiben (permissionless)

1. Proving-Key besorgen/erzeugen: `keys/state_pk.bin` (~280 MB) — vom
   Betreiber laden ODER selbst aus dem (öffentlichen) Setup ableiten.
2. L2-State ist aus der On-Chain-Calldata von Genesis rekonstruierbar
   (Data Availability) — kein Vertrauen in andere Aggregatoren nötig.
3. Konfig (`aggregator.json`):

```json
{ "listen_port": 8080, "node_rpc_addr": "127.0.0.1:18334",
  "node_api_key": null, "aggregator_address": "<deine-20-byte-hex-adresse>",
  "max_batch_size": 16, "batch_timeout_secs": 5,
  "state_pk_path": "crates/atlas-zk/keys/state_pk.bin",
  "genesis_alloc": [], "bid_amount_atom": 50, "test_mode": false }
```

```bash
./target/release/atlas-aggregator --config aggregator.json
```

Der Aggregator nimmt fällige Forced-TXs automatisch auf (Konsens-Pflicht).
`genesis_alloc` MUSS byte-identisch zur `genesis/alloc.json` des Netzwerks sein
(beim Fair-Launch-Testnet: leer `[]`), sonst chained der erste Settlement nicht.

## 7. Nützliche RPCs (Port 18334)

| Methode | Zweck |
|---|---|
| `getblockcount` / `getbestblockhash` | Sync-Stand |
| `getchaininfo` | Netzwerk/Höhe/Supply |
| `getforcedqueue` | Offene Forced-Inclusion-Einträge |
| `getbatchinfo` | Settlement-/Mempool-Stand |
| `getpeers` | Verbundene Peers |

Aggregator (Port 8080): `GET /account/<hex20>` (Guthaben+Nonce),
`POST /submit` (L2-TX), `GET /status`.

## Port-Übersicht

| Dienst | Port |
|---|---|
| P2P (Testnet) | 18333 |
| RPC | 18334 (nicht öffentlich exponieren oder `rpc_api_key` setzen!) |
| Aggregator HTTP | 8080 |

---

## Für Testnet-Betreiber — Checkliste zum Öffnen

Was nötig ist, damit Fremde tatsächlich teilnehmen können:

- [ ] **Erreichbarer Seed-Node**: P2P-Port 18333 öffentlich erreichbar
  (Port-Forward/Cloud-Host oder Tailscale-IP an Tester verteilen). Die
  Seed-IP veröffentlichen.
- [ ] **Genesis veröffentlichen**: `genesis/alloc.json` (Fair Launch: `[]`) +
  die resultierende `GENESIS_L2_ROOT` / den Genesis-Block-Hash, damit Teilnehmer
  verifizieren, dass sie derselben Kette beitreten. (`cargo run -p atlas-zk
  --release --bin genesis_root`.)
- [ ] **Faucet betreiben**: aus geschürftem Guthaben Test-ATOM an angefragte
  L2-Adressen senden — vorhanden als `atlas-sender --fund` (Nonce wird
  automatisch vom Aggregator geholt):
  ```bash
  ./target/release/atlas-sender --fund --url <AGGREGATOR-IP>:8080 \
    --secret <geförderter-32B-hex> --to <tester-20B-hex> --amount 1000000 --fee 5
  ```
  Für Selbstbedienung optional einen kleinen HTTP-Wrapper davor setzen
  (Rate-Limit/Captcha gegen Missbrauch). Ohne Faucet kann nur teilnehmen, wer
  selbst mint.
- [ ] **RPC absichern**: `rpc_api_key` setzen ODER Port 18334 nicht exponieren.
- [ ] **Monitoring**: Höhe/Settlement-Fortschritt/Peers beobachten
  (`getchaininfo`, `getbatchinfo`, Aggregator `/status`).
- [ ] **Proving-Key bereitstellen**: `keys/state_pk.bin` (~280 MB) zum Download
  für Tester, die einen eigenen Aggregator fahren wollen.

## Bekannte Grenzen des Testnets

Siehe `MAINNET-READINESS.md` — insbesondere: Single-Party-Trusted-Setup (kein
auditierter MPC), bislang 1 Node + 1 Aggregator auf einer Maschine, sowie der
revertierte Akkumulator-Versuch (aktueller Stand verarbeitet echte Transfers
sauber).
