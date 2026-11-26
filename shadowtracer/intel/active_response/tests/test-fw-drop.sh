#!/bin/bash
# Offline self-check for shadowtracer-fw-drop (bash AR script): add records a timed block, a later
# sweep removes the expired one, delete removes immediately, and private IPs are refused. Uses a stub
# iptables (ST_IPTABLES) and a temp manifest — no root, no real netfilter. Run: bash test-fw-drop.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../shadowtracer-fw-drop"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/iptables" <<'EOF'
#!/bin/bash
store="${STUB_STORE:?}"; op="$1"; ip=""; prev=""
for a in "$@"; do [ "$prev" = "-s" ] && ip="$a"; prev="$a"; done
case "$op" in
  -C) grep -qxF "$ip" "$store" 2>/dev/null ;;
  -I) grep -qxF "$ip" "$store" 2>/dev/null || echo "$ip" >> "$store" ;;
  -D) grep -vxF "$ip" "$store" > "$store.t" 2>/dev/null; mv "$store.t" "$store" ;;
esac
EOF
chmod +x "$TMP/iptables"
export STUB_STORE="$TMP/rules"; : > "$STUB_STORE"
run() { ST_IPTABLES="$TMP/iptables" ST_FW_MANIFEST="$TMP/manifest" STUB_STORE="$STUB_STORE" bash "$SCRIPT"; }

echo '{"version":1,"parameters":{"extra_args":["add","8.8.8.8","2"]}}' | run
grep -q "8.8.8.8" "$TMP/rules" || { echo "FAIL: add did not block"; exit 1; }
grep -q "^8.8.8.8 " "$TMP/manifest" || { echo "FAIL: add did not record manifest"; exit 1; }

echo '{"version":1,"parameters":{"extra_args":["add","10.0.0.5","100"]}}' | run
grep -q "10.0.0.5" "$TMP/rules" && { echo "FAIL: private IP was blocked"; exit 1; }

sleep 3
echo '{"version":1,"parameters":{"extra_args":["sweep"]}}' | run
grep -q "8.8.8.8" "$TMP/rules" && { echo "FAIL: expired block not swept"; exit 1; }

echo '{"version":1,"parameters":{"extra_args":["add","9.9.9.9","0"]}}' | run        # 0 = no agent expiry
echo '{"version":1,"parameters":{"extra_args":["delete","9.9.9.9"]}}' | run
grep -q "9.9.9.9" "$TMP/rules" && { echo "FAIL: delete did not remove"; exit 1; }

echo "shadowtracer-fw-drop self-check ok"
