# ATLAS Web-Wallet

Eine schlanke Browser-Wallet für die ATLAS-**L2**. Sie signiert Transaktionen mit
**Baby-Jubjub-EdDSA** (über WASM aus dem echten `atlas-zk`-Code → byte-identisch
zu dem, was der Groth16-Circuit erwartet) und spricht direkt mit Aggregator und Node.

> ⚠️ **Testnet / experimentell.** Der private Schlüssel liegt unverschlüsselt im
> `localStorage` des Browsers. Nicht für echte Werte verwenden.

## Warum keine MetaMask?
MetaMask spricht ausschließlich Ethereum/EVM (secp256k1, Keccak-Adressen, RLP,
`eth_*`-RPC). ATLAS nutzt ein anderes Adressformat und auf der L2 **Baby-Jubjub-
EdDSA, im ZK-Circuit verifiziert** — Signaturen, die MetaMask gar nicht erzeugen
kann. Eine native Wallet ist deshalb der richtige Weg.

## Funktionen
- Konto erzeugen mit **24-Wort-BIP39-Mnemonic** als Backup; Import per Mnemonic
  oder Secret-Hex (alles lokal im Browser)
- **Passwort-Verschlüsselung**: der Schlüssel wird mit PBKDF2 (SHA-256, 210k
  Iterationen) + AES-GCM verschlüsselt im `localStorage` abgelegt — nie im
  Klartext. Entsperren per Passwort.
- L2-Guthaben + Nonce anzeigen (`GET <aggregator>/account/<addr>`)
- L2-Transaktion senden (`POST <aggregator>/submit`)
- Forced Inclusion / Escape-Hatch (`forcel2tx` an die Node-RPC)

> Die Mnemonic ist das **einzige** Backup — wird sie verloren UND das Passwort
> vergessen, ist das Konto unwiederbringlich. Mnemonic offline notieren.

## Voraussetzungen im Backend
- **Aggregator** läuft und ist erreichbar (Standard `http://127.0.0.1:8390`).
  Liefert `/account/<addr>` und nimmt `/submit` an (CORS ist aktiviert).
- **Node-RPC** erreichbar (Standard `http://127.0.0.1:18634`) für Forced Inclusion
  (CORS + OPTIONS-Preflight sind aktiviert).

## Starten
Die Wallet ist statisch — sie braucht nur einen HTTP-Server (wegen ES-Module/WASM
nicht per `file://` öffnen):

```bash
cd web-wallet
python3 -m http.server 8088
# Browser: http://127.0.0.1:8088/
```

Das vorgebaute WASM liegt in `pkg/` und ist eingecheckt — kein Build nötig.

## WASM neu bauen (optional)
```bash
cargo install wasm-pack           # einmalig
cd web-wallet
wasm-pack build --target web --release   # erzeugt pkg/
```

## Aufbau
- `src/lib.rs` — WASM-Krypto-Kern (Keygen, EdDSA-Signing, JSON-Bau). Hängt nur an
  `atlas-zk` (ohne `native-perf`-Feature → ohne x86-asm/rayon, wasm32-tauglich).
- `index.html` — komplette UI in einer Datei.
- `pkg/` — wasm-pack-Output (eingecheckt).
