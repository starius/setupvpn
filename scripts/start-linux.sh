#!/bin/sh
set -eu
umask 077
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

mode=tun
profile=01
for arg in "$@"; do
    case "$arg" in
        --socks) mode=socks ;;
        --download-only) mode=download ;;
        *[!0-9]*|'') echo "Usage: sh $0 [--socks] [profile-number]" >&2; exit 1 ;;
        *) profile=$(printf '%02d' "$(echo "$arg" | sed 's/^0*//; s/^$/0/')") ;;
    esac
done
case "$(uname -m)" in
    x86_64) url='@AMD64_URL@'; sha='@AMD64_SHA@' ;;
    aarch64|arm64) url='@ARM64_URL@'; sha='@ARM64_SHA@' ;;
    *) echo "Supported Linux architectures: amd64 and arm64" >&2; exit 1 ;;
esac
binary="$(pwd)/.xray-@VERSION@-$(uname -m)"
if [ ! -x "$binary" ]; then
    for tool in curl unzip sha256sum; do
        command -v "$tool" >/dev/null || { echo "Missing $tool. On Debian/Ubuntu: sudo apt-get install curl unzip iproute2" >&2; exit 1; }
    done
    download=$(mktemp -d)
    trap 'rm -rf "$download"' EXIT HUP INT TERM
    curl --fail --location --retry 3 --connect-timeout 15 --max-time 300 "$url" -o "$download/xray.zip"
    printf '%s  %s\n' "$sha" "$download/xray.zip" | sha256sum --check --status
    unzip -p "$download/xray.zip" xray > "$download/xray"
    chmod 700 "$download/xray"
    mv "$download/xray" "$binary"
    rm -rf "$download"
    trap - EXIT HUP INT TERM
fi
[ "$mode" != download ] || exit 0
config="$(pwd)/xray-$mode-$profile.json"
[ -f "$config" ] || { echo "Missing profile: $config" >&2; exit 1; }
"$binary" run -test -config "$config"
if [ "$mode" = socks ]; then
    echo 'SOCKS5 proxy: 127.0.0.1:10808 (routes and DNS unchanged)'
    exec "$binary" run -config "$config"
fi

[ "$(id -u)" = 0 ] || { echo "For the VPN, run: sudo sh $0 $profile" >&2; exit 1; }
command -v ip >/dev/null || { echo 'Install iproute2 first.' >&2; exit 1; }
command -v flock >/dev/null || { echo 'Install util-linux first (flock is required).' >&2; exit 1; }
exec 9>/run/setupvpn-client.lock
flock -n 9 || { echo 'Another setupvpn client is running.' >&2; exit 1; }
state=/var/lib/setupvpn-client
mkdir -p "$state"
chmod 700 "$state"
saved="$state/resolv.conf.saved"
child=
resolver=
cleanup() {
    trap - EXIT HUP INT TERM
    if [ "$resolver" = resolved ]; then resolvectl revert setupvpn0 2>/dev/null || true; fi
    if [ -f "$saved" ]; then
        if cat "$saved" > /etc/resolv.conf; then rm -f "$saved"; else echo "Restore DNS from $saved" >&2; fi
    fi
    if [ -n "$child" ]; then kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi
}
trap cleanup EXIT
trap 'exit 0' HUP INT TERM
# Recover a static resolver after an interrupted previous session.
if [ -f "$saved" ]; then cat "$saved" > /etc/resolv.conf; rm -f "$saved"; fi
"$binary" run -config "$config" &
child=$!
attempt=0
until ip link show setupvpn0 >/dev/null 2>&1; do
    kill -0 "$child" 2>/dev/null || { echo 'Xray failed to start.' >&2; exit 1; }
    attempt=$((attempt+1))
    [ "$attempt" -lt 100 ] || { echo 'Timed out waiting for the VPN interface.' >&2; exit 1; }
    sleep 0.1
done
# The .2 address belongs to the TUN subnet but not the host. Xray intercepts
# its DNS requests and resolves them over HTTPS through the VLESS tunnel.
if command -v resolvectl >/dev/null && resolvectl status >/dev/null 2>&1 &&
    grep -qE '^nameserver[[:space:]]+127\.0\.0\.(53|54)' /etc/resolv.conf; then
    resolver=resolved
    resolvectl dns setupvpn0 172.19.0.2
    resolvectl domain setupvpn0 '~.'
    resolvectl default-route setupvpn0 yes
else
    cp -L /etc/resolv.conf "$saved"
    printf 'nameserver 172.19.0.2\n' > /etc/resolv.conf
fi
echo 'VPN connected. IPv4, IPv6 and DNS use Xray. Press Ctrl+C to stop.'
wait "$child"
