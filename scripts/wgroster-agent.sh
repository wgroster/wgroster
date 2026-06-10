#!/bin/sh
# wgroster concentrator agent (tracking-only friendly).
#
# It does two things, both driven from the concentrator — the portal never
# connects to this host and never has write access to WireGuard:
#   1. push:      send "wg show <iface> dump" to the portal (status/monitoring)
#   2. reconcile: pull the expected peer list and apply it locally with "wg set"
#                 (add/update/remove peers so the hub matches the portal)
#
# Configure via environment (e.g. in the systemd unit):
#   WG_PORTAL_URL    base URL, e.g. https://wgroster.example.com
#   WG_ENDPOINT_ID   this endpoint's id in the portal
#   WG_TOKEN         the endpoint upload token
#   WG_IFACE         WireGuard interface (default: wg0)
#   WG_RECONCILE     "1" to apply expected peers locally (default: 0 = push only)
set -eu

: "${WG_IFACE:=wg0}"
: "${WG_RECONCILE:=0}"
: "${WG_PORTAL_URL:?set WG_PORTAL_URL}"
: "${WG_ENDPOINT_ID:?set WG_ENDPOINT_ID}"
: "${WG_TOKEN:?set WG_TOKEN}"

api="$WG_PORTAL_URL/api/endpoints/$WG_ENDPOINT_ID"
auth="Authorization: Bearer $WG_TOKEN"

# 1. Push current status.
wg show "$WG_IFACE" dump | curl -fsS -H "$auth" --data-binary @- "$api/status"

# 2. Optionally reconcile peers to match the portal's source of truth.
if [ "$WG_RECONCILE" = "1" ]; then
    expected="$(curl -fsS -H "$auth" "$api/expected-peers?format=tsv")"

    # Remove peers present on the hub but no longer expected.
    wg show "$WG_IFACE" peers | while read -r pub; do
        [ -n "$pub" ] || continue
        if ! printf '%s\n' "$expected" | grep -q "^$pub	"; then
            wg set "$WG_IFACE" peer "$pub" remove
        fi
    done

    # Add/update expected peers (allowed-ips). Empty lines are skipped.
    printf '%s\n' "$expected" | while IFS='	' read -r pub aips; do
        [ -n "$pub" ] && [ -n "$aips" ] || continue
        wg set "$WG_IFACE" peer "$pub" allowed-ips "$aips"
    done
fi
