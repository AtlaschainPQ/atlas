#!/usr/bin/env bash
# Live-E2E: Node (testnet, echte ZK-Verifikation) + Aggregator (echter Groth16)
# + atlas-sender. Treibt genau einen vollen Batch durch den ganzen Pfad:
#   sender → aggregator (apply + prove_state) → node submitbatch (verify_state_bid)
# Erfolg = Node-Log enthält "Settlement batch accepted".
set -u
source ~/.cargo/env 2>/dev/null || true
cd ~/atlas

NODE_LOG=/tmp/atlas-node.log
AGG_LOG=/tmp/atlas-agg.log
DATA_DIR=/tmp/atlas-e2e-data
AGG_CFG=/tmp/atlas-agg.json

echo "== Cleanup =="
pkill -f 'target/release/atlas-node' 2>/dev/null
pkill -f 'target/release/atlas-aggregator' 2>/dev/null
sleep 1
rm -rf "$DATA_DIR" "$NODE_LOG" "$AGG_LOG"

echo "== Build (release) =="
cargo build --release -p atlas-node -p atlas-aggregator -p atlas-sender 2>&1 | tail -3 || exit 1

# Isolierte, nachweislich freie Ports — System-Dienste + Docker-Container
# (8080/8085/8086/8090/8096/8097/8766/8767/18333/18334) bleiben unberührt.
NODE_RPC=18634
NODE_P2P=18633
NODE_METRICS=19191
AGG_PORT=8390

cat > "$AGG_CFG" <<JSON
{
  "listen_port": $AGG_PORT,
  "node_rpc_addr": "127.0.0.1:$NODE_RPC",
  "node_api_key": null,
  "aggregator_address": "00112233445566778899aabbccddeeff00112233",
  "max_batch_size": 16,
  "batch_timeout_secs": 5,
  "state_pk_path": "crates/atlas-zk/keys/state_pk.bin",
  "genesis_alloc": [],
  "bid_amount_atom": 50,
  "test_mode": false
}
JSON

echo "== Start node (testnet, test_mode=false, isolierte Ports) =="
RUST_LOG=info ./target/release/atlas-node --network testnet --data-dir "$DATA_DIR" \
    --rpc-port $NODE_RPC --p2p-port $NODE_P2P --metrics-port $NODE_METRICS > "$NODE_LOG" 2>&1 &
NODE_PID=$!

echo "   warte auf RPC $NODE_RPC..."
for i in $(seq 1 60); do
  if curl -s -m 1 -X POST \
      -d '{"jsonrpc":"2.0","id":1,"method":"getbatchinfo","params":[]}' \
      http://127.0.0.1:$NODE_RPC >/dev/null 2>&1; then echo "   RPC up"; break; fi
  sleep 1
done

echo "== Start aggregator (echter Groth16) =="
RUST_LOG=info ./target/release/atlas-aggregator --config "$AGG_CFG" > "$AGG_LOG" 2>&1 &
AGG_PID=$!

echo "   warte auf 'Aggregator ready' (PK-Laden, max 120s)..."
for i in $(seq 1 120); do
  if grep -q "Aggregator ready" "$AGG_LOG"; then echo "   Aggregator up nach ${i}s"; break; fi
  if ! kill -0 "$AGG_PID" 2>/dev/null; then echo "   AGGREGATOR ABGESTÜRZT"; tail -5 "$AGG_LOG"; break; fi
  sleep 1
done
grep -m1 "Genesis-Root" "$AGG_LOG" || true

echo "== Sender: 16 TXs (1 voller Batch), 8 geförderte Seeds =="
./target/release/atlas-sender --url 127.0.0.1:$AGG_PORT \
    --count 16 --senders 8 --batch 16 --amount 100 2>&1 | tail -6

echo "   warte auf Proving + Settlement (max 600s)..."
for i in $(seq 1 600); do
  if grep -q "Settlement batch accepted" "$NODE_LOG"; then break; fi
  if grep -qiE "rejected|state proof.*fail|fehler" "$NODE_LOG"; then break; fi
  sleep 1
done

echo
echo "===== AGGREGATOR LOG (proving/submit) ====="
grep -iE "genesis-root|batch|prov|settlement|submit|root|fehler|error" "$AGG_LOG" | tail -25
echo
echo "===== NODE LOG (settlement) ====="
grep -iE "settlement batch accepted|zk state proof|rejected|bid|error" "$NODE_LOG" | tail -25
echo
echo "===== getbatchinfo ====="
curl -s -X POST \
  -d '{"jsonrpc":"2.0","id":1,"method":"getbatchinfo","params":[]}' \
  http://127.0.0.1:$NODE_RPC

echo
echo "== Ergebnis =="
if grep -q "Settlement batch accepted" "$NODE_LOG"; then
  echo "E2E OK: Node hat den echten Groth16-Settlement-Batch akzeptiert."
else
  echo "E2E FAIL: kein 'Settlement batch accepted' im Node-Log."
fi

echo "== Cleanup =="
kill "$AGG_PID" "$NODE_PID" 2>/dev/null
