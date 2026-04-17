#!/bin/bash

echo "========== PACKET LOSS MEASUREMENT =========="

PID=$(pgrep -f "mininet:h1" | head -n 1)

run_ping() {
    mnexec -a $PID ping -c 5 10.0.0.2
}

extract_loss() {
    echo "$1" | grep -oP '\d+(?=% packet loss)'
}

echo ""
echo "[1] BASELINE TEST"
OUT1=$(run_ping)
echo "$OUT1"
BASE=$(extract_loss "$OUT1")

echo ""
echo "[2] APPLYING DROP RULE..."
curl -s -X POST http://localhost:8080/drop_rules \
-d '{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}'
sleep 2

echo ""
echo "[3] TEST AFTER DROP"
OUT2=$(run_ping)
echo "$OUT2"
DROP=$(extract_loss "$OUT2")

echo ""
echo "[4] CLEARING DROP RULES..."
curl -s -X DELETE http://localhost:8080/drop_rules
sleep 2

mnexec -a $PID ping -c 2 10.0.0.2 > /dev/null
sleep 1

echo ""
echo "[5] TEST AFTER CLEAR"
OUT3=$(run_ping)
echo "$OUT3"
FINAL=$(extract_loss "$OUT3")

echo ""
echo "========== SUMMARY =========="
echo "Baseline : $BASE%"
echo "After Drop : $DROP%"
echo "After Clear : $FINAL%"

echo "========== DONE =========="