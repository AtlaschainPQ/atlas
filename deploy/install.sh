#!/usr/bin/env bash
# ATLAS Node — Server-Installation
# Getestet auf Ubuntu 22.04 / 24.04
#
# Verwendung:
#   sudo bash install.sh [--network mainnet|testnet|regtest] [--mining] [--api-key KEY]
#
set -euo pipefail

# ── Konfiguration ──────────────────────────────────────────────────────────────
ATLAS_USER="atlas"
ATLAS_HOME="/var/lib/atlas"
ATLAS_CONFIG="/etc/atlas"
ATLAS_BIN="/usr/local/bin"
NETWORK="mainnet"
MINING=false
API_KEY=""
MINER_ADDRESS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --network)        NETWORK="$2"; shift 2 ;;
        --mining)         MINING=true; shift ;;
        --api-key)        API_KEY="$2"; shift 2 ;;
        --miner-address)  MINER_ADDRESS="$2"; shift 2 ;;
        *) echo "Unbekannte Option: $1"; exit 1 ;;
    esac
done

# ── Root-Check ─────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "Fehler: Dieses Script muss als root ausgeführt werden (sudo bash install.sh)"
    exit 1
fi

echo "=== ATLAS Node Installation ==="
echo "  Netzwerk:  $NETWORK"
echo "  Mining:    $MINING"
echo ""

# ── Abhängigkeiten ─────────────────────────────────────────────────────────────
echo "[1/6] Abhängigkeiten installieren..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    curl ca-certificates build-essential pkg-config \
    libssl-dev clang librocksdb-dev \
    logrotate ufw

# ── Rust installieren (falls nicht vorhanden) ──────────────────────────────────
if ! command -v rustc &>/dev/null; then
    echo "[2/6] Rust installieren..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
else
    echo "[2/6] Rust bereits vorhanden ($(rustc --version))"
fi

# ── Binary bauen ──────────────────────────────────────────────────────────────
echo "[3/6] ATLAS Node bauen (--release)..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
~/.cargo/bin/cargo build --release -p atlas-node
cp target/release/atlas-node "$ATLAS_BIN/atlas-node"
cp target/release/atlas-wallet "$ATLAS_BIN/atlas-wallet" 2>/dev/null || true
echo "      Binary: $ATLAS_BIN/atlas-node ($(du -sh target/release/atlas-node | cut -f1))"

# ── Benutzer und Verzeichnisse ────────────────────────────────────────────────
echo "[4/6] Benutzer und Verzeichnisse einrichten..."
if ! id "$ATLAS_USER" &>/dev/null; then
    useradd --system --no-create-home \
        --home-dir "$ATLAS_HOME" \
        --shell /usr/sbin/nologin \
        "$ATLAS_USER"
fi
mkdir -p "$ATLAS_HOME" "$ATLAS_CONFIG"
chown -R "$ATLAS_USER:$ATLAS_USER" "$ATLAS_HOME"
chmod 750 "$ATLAS_HOME"
chown root:atlas "$ATLAS_CONFIG"
chmod 750 "$ATLAS_CONFIG"

# ── Konfiguration schreiben ────────────────────────────────────────────────────
echo "[5/6] Konfiguration erstellen..."
CONFIG_FILE="$ATLAS_CONFIG/atlas.json"

if [[ ! -f "$CONFIG_FILE" ]]; then
    # Ports abhängig vom Netzwerk
    case $NETWORK in
        testnet) P2P_PORT=18333; RPC_PORT=18334 ;;
        regtest) P2P_PORT=18444; RPC_PORT=18445 ;;
        *)       P2P_PORT=8333;  RPC_PORT=8334  ;;
    esac

    # JSON-Konfiguration generieren
    cat > "$CONFIG_FILE" << JSONEOF
{
  "network": "$NETWORK",
  "data_dir": "$ATLAS_HOME",
  "p2p_port": $P2P_PORT,
  "rpc_port": $RPC_PORT,
  "rpc_api_key": $([ -n "$API_KEY" ] && echo "\"$API_KEY\"" || echo "null"),
  "max_peers": 125,
  "mempool_max_size": 50000,
  "mining": $MINING,
  "miner_address": $([ -n "$MINER_ADDRESS" ] && echo "\"$MINER_ADDRESS\"" || echo "null"),
  "prover_address": null,
  "mining_threads": 0,
  "metrics_port": 9090,
  "persist_mempool": true,
  "test_mode": false,
  "log_level": "info",
  "seed_nodes": [
    "seed1.atlas-network.io:8333",
    "seed2.atlas-network.io:8333",
    "seed3.atlas-network.io:8333"
  ]
}
JSONEOF
    chown root:atlas "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
    echo "      Konfiguration: $CONFIG_FILE"
else
    echo "      Konfiguration bereits vorhanden: $CONFIG_FILE (unverändert)"
fi

# ── systemd Unit installieren ──────────────────────────────────────────────────
echo "[6/6] systemd Service einrichten..."
cp "$SCRIPT_DIR/deploy/atlas-node.service" /etc/systemd/system/atlas-node.service
systemctl daemon-reload
systemctl enable atlas-node

# ── Firewall (ufw) ─────────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
    ufw allow "$P2P_PORT/tcp" comment "ATLAS P2P" 2>/dev/null || true
    echo "      Firewall: Port $P2P_PORT (P2P) geöffnet"
    echo "      Hinweis:  RPC-Port $RPC_PORT bleibt lokal (kein externer Zugriff)"
fi

# ── Logrotate ─────────────────────────────────────────────────────────────────
cat > /etc/logrotate.d/atlas-node << 'LOGEOF'
/var/log/journal/atlas-node/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
}
LOGEOF

# ── Zusammenfassung ───────────────────────────────────────────────────────────
echo ""
echo "=== Installation abgeschlossen ==="
echo ""
echo "Node starten:"
echo "  sudo systemctl start atlas-node"
echo ""
echo "Status prüfen:"
echo "  sudo systemctl status atlas-node"
echo "  sudo journalctl -u atlas-node -f"
echo ""
echo "RPC testen (lokal):"
echo "  curl -s http://127.0.0.1:$RPC_PORT \\"
echo "    -H 'Content-Type: application/json' \\"
if [[ -n "$API_KEY" ]]; then
echo "    -H 'Authorization: Bearer $API_KEY' \\"
fi
echo "    -d '{\"jsonrpc\":\"2.0\",\"method\":\"getchaininfo\",\"params\":[],\"id\":1}'"
echo ""
echo "Konfiguration: $CONFIG_FILE"
echo "Daten:         $ATLAS_HOME"
echo ""
if $MINING && [[ -z "$MINER_ADDRESS" ]]; then
    echo "HINWEIS: Mining ist aktiviert, aber keine Miner-Adresse gesetzt."
    echo "  Eine neue Adresse erstellen:"
    echo "  atlas-wallet new-key --label miner"
    echo "  Dann in $CONFIG_FILE eintragen: miner_address"
    echo ""
fi
