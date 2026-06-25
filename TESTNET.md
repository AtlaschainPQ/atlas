# ATLAS Open Testnet — Teilnahme-Anleitung

So nimmst du am ATLAS-Testnet teil — als Node, Miner oder Aggregator.
Das Testnet fährt die volle Mainnet-Mechanik (echte Groth16-Verifikation,
PoW, Data Availability, Forced Inclusion) — nur mit Test-Parametern
(3-s-Blockzeit) und Dev-Genesis-Konten.

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
konfiguriert (`miner_address`).

## 4. L2-Transaktionen senden

Das Testnet hat 64 vorab geförderte Dev-Konten (deterministische Seeds
`0xA71A5000 … 0xA71A503F`, je 1 000 000 000 000 ATOM) — der eingebaute Faucet.

```bash
# 100 TXs über den Aggregator schicken (Seeds 0..49):
./target/release/atlas-sender --url <AGGREGATOR-IP>:8390 \
  --count 100 --senders 10 --amount 100 --fee 5
```

## 5. Forced Inclusion (Zensurresistenz testen!)

Wenn ein Aggregator deine TX nicht aufnimmt, erzwinge sie direkt über L1 —
ganz ohne L1-Guthaben (Spam-Schutz: Mini-PoW-Stamp):

```bash
./target/release/atlas-sender --force --url <NODE-IP>:18334 \
  --seed 0xA71A5007 --nonce 0 --index 8 --amount 50 --fee 5
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
{ "listen_port": 8390, "node_rpc_addr": "127.0.0.1:18334",
  "node_api_key": null, "aggregator_address": "<deine-20-byte-hex-adresse>",
  "max_batch_size": 16, "batch_timeout_secs": 5,
  "state_pk_path": "crates/atlas-zk/keys/state_pk.bin",
  "genesis_alloc": [], "bid_amount_atom": 50, "test_mode": false }
```

```bash
./target/release/atlas-aggregator --config aggregator.json
```

Der Aggregator nimmt fällige Forced-TXs automatisch auf (Konsens-Pflicht).

## 7. Nützliche RPCs (Port 18334)

| Methode | Zweck |
|---|---|
| `getblockcount` / `getbestblockhash` | Sync-Stand |
| `getchaininfo` | Netzwerk/Höhe/Supply |
| `getforcedqueue` | Offene Forced-Inclusion-Einträge |
| `getbatchinfo` | Settlement-/Mempool-Stand |
| `getpeers` | Verbundene Peers |

## Port-Übersicht

| Dienst | Port |
|---|---|
| P2P (Testnet) | 18333 |
| RPC | 18334 (nicht öffentlich exponieren oder `rpc_api_key` setzen!) |
| Aggregator HTTP | 8390 |

## Bekannte Grenzen des Testnets
Siehe `MAINNET-READINESS.md` — insbesondere: Single-Party-Trusted-Setup
(echte MPC vor Mainnet), ~27 s Proof-Zeit pro 16er-Batch, Dev-Genesis.
