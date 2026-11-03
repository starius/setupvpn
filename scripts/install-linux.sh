#!/bin/sh
set -eu
umask 077
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "Run: sudo sh $0 [profile-number]" >&2; exit 1; }
command -v systemctl >/dev/null || { echo 'Automatic startup requires systemd; use start-linux.sh instead.' >&2; exit 1; }
profile=${1:-01}
case "$profile" in *[!0-9]*|'') echo 'Profile number must be numeric.' >&2; exit 1 ;; esac
profile=$(printf '%02d' "$(echo "$profile" | sed 's/^0*//; s/^$/0/')")
for kind in tun socks; do
    [ -f "xray-$kind-$profile.json" ] || { echo "Missing xray-$kind-$profile.json" >&2; exit 1; }
done
sh ./start-linux.sh --download-only
systemctl stop setupvpn-client.service 2>/dev/null || true
install -d -m 700 /etc/setupvpn-client
install -m 600 "xray-tun-$profile.json" /etc/setupvpn-client/xray-tun-01.json
install -m 600 "xray-socks-$profile.json" /etc/setupvpn-client/xray-socks-01.json
install -m 700 start-linux.sh /etc/setupvpn-client/start-linux.sh
for binary in .xray-*; do
    [ -f "$binary" ] && install -m 700 "$binary" "/etc/setupvpn-client/$binary"
done
cat > /etc/systemd/system/setupvpn-client.service <<'UNIT'
[Unit]
Description=setupvpn Xray client
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/bin/sh /etc/setupvpn-client/start-linux.sh
# Signal the launcher first so it can restore DNS before stopping Xray.
KillMode=mixed
Restart=on-failure
RestartSec=5
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now setupvpn-client.service
echo 'VPN installed and enabled at boot. Status: systemctl status setupvpn-client'
