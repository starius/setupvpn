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
destination=/etc/setupvpn-client
unit=/etc/systemd/system/setupvpn-client.service
qubes_after=
if [ -d /rw/config ] && command -v qubesdb-read >/dev/null; then
    destination=/rw/config/setupvpn-client
    unit="$destination/setupvpn-client.service"
    qubes_after='After=qubes-misc-post.service'
fi
install -d -m 700 "$destination"
install -m 600 "xray-tun-$profile.json" "$destination/xray-tun-01.json"
install -m 600 "xray-socks-$profile.json" "$destination/xray-socks-01.json"
install -m 700 start-linux.sh "$destination/start-linux.sh"
for binary in .xray-*; do
    [ -f "$binary" ] && install -m 700 "$binary" "$destination/$binary"
done
cat > "$unit" <<UNIT
[Unit]
Description=setupvpn Xray client
Wants=network-online.target
After=network-online.target
$qubes_after

[Service]
Type=simple
ExecStart=/bin/sh $destination/start-linux.sh
# Signal the launcher first so it can restore DNS before stopping Xray.
KillMode=mixed
Restart=on-failure
RestartSec=5
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
UNIT
chmod 644 "$unit"

if [ "$destination" = /rw/config/setupvpn-client ]; then
    # Replace an installation made by the older, nonpersistent installer.
    systemctl disable setupvpn-client.service 2>/dev/null || true
    rm -f /etc/systemd/system/setupvpn-client.service
    cat > "$destination/service.sh" <<'CONTROL'
#!/bin/sh
set -eu
umask 077
[ "$(id -u)" = 0 ] || { echo "Run: sudo sh $0 enable|disable" >&2; exit 1; }
destination=/rw/config/setupvpn-client
case "${1:-}" in
    enable) touch "$destination/enabled" ;;
    disable)
        rm -f "$destination/enabled" ;;
    boot) ;;
    *) echo "Usage: sudo sh $0 enable|disable" >&2; exit 1 ;;
esac
install -d /run/systemd/system
install -m 644 "$destination/setupvpn-client.service" /run/systemd/system/setupvpn-client.service
systemctl daemon-reload
if [ "$1" = disable ]; then
    systemctl stop setupvpn-client.service
elif [ "$1" = boot ]; then
    # The unit waits for qubes-misc-post, which is running this boot hook.
    if [ -f "$destination/enabled" ]; then
        systemctl --no-block start setupvpn-client.service
    fi
else
    systemctl start setupvpn-client.service
fi
CONTROL
    chmod 700 "$destination/service.sh"
    if grep -Fq '/rw/config/rc.local.d/' /usr/lib/qubes/init/misc-post.sh 2>/dev/null; then
        install -d /rw/config/rc.local.d
        cat > /rw/config/rc.local.d/90-setupvpn-client.rc <<'HOOK'
#!/bin/sh
exec /bin/sh /rw/config/setupvpn-client/service.sh boot
HOOK
        chmod 700 /rw/config/rc.local.d/90-setupvpn-client.rc
    else
        # Older Qubes agents only support rc.local. Insert before its commands
        # (including a possible "exit 0") and preserve any existing shebang.
        hook='/bin/sh /rw/config/setupvpn-client/service.sh boot'
        rc=/rw/config/rc.local
        if [ ! -f "$rc" ]; then printf '#!/bin/sh\n' > "$rc"; fi
        if ! grep -Fxq "$hook" "$rc"; then
            temporary=$(mktemp /rw/config/rc.local.setupvpn.XXXXXX)
            awk -v hook="$hook" '
                NR == 1 { if ($0 ~ /^#!/) { print; print hook; next }; print "#!/bin/sh"; print hook }
                { print }
                END { if (NR == 0) { print "#!/bin/sh"; print hook } }
            ' "$rc" > "$temporary"
            cat "$temporary" > "$rc"
            rm -f "$temporary"
        fi
        chmod +x "$rc"
    fi
    sh "$destination/service.sh" enable
    echo 'VPN installed persistently in /rw/config/setupvpn-client and enabled at qube startup.'
    echo 'Stop and disable: sudo sh /rw/config/setupvpn-client/service.sh disable'
    echo 'Status: systemctl status setupvpn-client'
    exit 0
fi
systemctl daemon-reload
systemctl enable --now setupvpn-client.service
echo 'VPN installed and enabled at boot. Status: systemctl status setupvpn-client'
