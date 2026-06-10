#!/bin/sh
# Regenerate the README screenshots: seed a fake DB, run wgroster, drive a
# headless Chrome to capture each page into docs/screenshots/.
# Requires Go and Google Chrome / Chromium.
set -eu

cd "$(dirname "$0")/.."
PORT=8123
TMP="$(mktemp -d)"
trap 'kill "${SRV:-0}" 2>/dev/null || true; rm -rf "$TMP"' EXIT

echo "→ building"
go build -o "$TMP/wgroster" ./cmd/wgroster
go build -o "$TMP/seed" ./tools/seed

echo "→ seeding fake database"
"$TMP/seed" -db "$TMP/fake.db"

HASH="$(printf 'admin' | "$TMP/wgroster" -hash-password)"
cat > "$TMP/config.yaml" <<EOF
listen: "127.0.0.1:$PORT"
base_url: "http://127.0.0.1:$PORT"
session_key: "screenshots-only"
database: "$TMP/fake.db"
vpn_cidr: "10.0.0.0/16"
self_enroll: true
self_enroll_endpoint: "paris"
local_admin: { username: "admin", password_hash: "$HASH" }
EOF

echo "→ starting wgroster"
"$TMP/wgroster" -config "$TMP/config.yaml" >"$TMP/log" 2>&1 &
SRV=$!
# Wait for it to answer.
for _ in $(seq 1 50); do
    curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
    sleep 0.2
done

echo "→ capturing screenshots"
mkdir -p docs/screenshots
( cd tools/screenshots && go run . -url "http://127.0.0.1:$PORT" -out "$(cd ../../docs/screenshots && pwd)" )

echo "✓ screenshots written to docs/screenshots/"
