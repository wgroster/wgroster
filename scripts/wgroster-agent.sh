#!/bin/sh
# wgroster concentrator agent (tracking-only friendly).
#
# It does two things, both driven from the concentrator — the portal never
# connects to this host and never has write access to WireGuard:
#   1. push:      send "wg show <iface> dump" to the portal (status/monitoring)
#   2. reconcile: pull the expected peer list and apply it locally with
#                 "wg syncconf" (add/update/remove peers so the hub matches
#                 the portal)
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

# 1. Push current status. --retry rides out short network blips so transient
# outages don't fail the run (and, under cron, don't trigger mail).
wg show "$WG_IFACE" dump | curl -fsS --retry 3 --retry-connrefused \
    --retry-delay 5 --max-time 30 -H "$auth" --data-binary @- "$api/status"

# 2. Optionally reconcile peers to match the portal's source of truth.
#
# "format=wg" already returns a peer-only file in "wg setconf" syntax, which is
# exactly what syncconf consumes. syncconf applies the whole peer set in one
# call — it adds new peers, updates AllowedIPs and removes peers that are no
# longer expected, while leaving established sessions of unchanged peers alone
# (unlike setconf, which tears them down). The [Interface] section is
# deliberately not part of this: the portal knows neither the private key nor
# the routes, and address/MTU changes need a wg-quick restart anyway.
if [ "$WG_RECONCILE" = "1" ]; then
    peers="$(mktemp)"
    trap 'rm -f "$peers"' EXIT

    curl -fsS --retry 3 --retry-connrefused --retry-delay 5 --max-time 30 \
        -H "$auth" "$api/expected-peers?format=wg" > "$peers"

    # An empty answer would make syncconf remove every peer on the hub. A hub
    # with no expected peers at all is not worth that risk: treat it as a
    # truncated response and leave the interface untouched.
    if [ -s "$peers" ]; then
        wg syncconf "$WG_IFACE" "$peers"
    else
        echo "wgroster-agent: empty peer list, leaving $WG_IFACE untouched" >&2
    fi
fi
