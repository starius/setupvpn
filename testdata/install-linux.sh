#!/bin/sh
set -eu

if [ "$1" != --inside ]; then
    root=$1
    mode=$2
    mount --make-rprivate /
    mkdir -p "$root/bin" "$root/lib" "$root/usr/lib/qubes/init" "$root/dev" "$root/fakebin"
    # Only the standard executables/libraries are shared with the host, read-only.
    for directory in bin lib lib64; do
        if [ -d "/$directory" ]; then
            mkdir -p "$root/$directory"
            mount --rbind "/$directory" "$root/$directory"
            mount -o remount,bind,ro "$root/$directory"
        fi
    done
    # awk may otherwise resolve through the host's /etc/alternatives.
    cp "$(command -v awk)" "$root/fakebin/awk"
    : > "$root/dev/null"
    exec chroot "$root" /bin/sh /work/test.sh --inside "$mode"
fi

PATH=/fakebin:/bin
export PATH
mode=$2
mkdir -p /etc/systemd/system /run
cat > /fakebin/systemctl <<'MOCK'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> /run/systemctl-calls
case "$*" in
    'start setupvpn-client.service'|'--no-block start setupvpn-client.service'|'enable --now setupvpn-client.service')
        unit=/run/systemd/system/setupvpn-client.service
        [ -f "$unit" ] || unit=/etc/systemd/system/setupvpn-client.service
        launcher=$(sed -n 's/^ExecStart=\/bin\/sh //p' "$unit")
        [ -x "$launcher" ]
        [ -x "$(dirname "$launcher")/.xray-fixture" ]
        [ -f "$(dirname "$launcher")/xray-tun-01.json" ]
        touch /run/mock-active ;;
    'stop setupvpn-client.service') rm -f /run/mock-active ;;
esac
MOCK
chmod +x /fakebin/systemctl

if [ "$mode" != linux ]; then
    mkdir -p /rw/config
    printf '#!/bin/sh\nexit 0\n' > /fakebin/qubesdb-read
    chmod +x /fakebin/qubesdb-read
    printf '#!/bin/sh\necho existing >> /run/existing\nexit 0\n' > /rw/config/rc.local
    chmod +x /rw/config/rc.local
    cp /rw/config/rc.local /work/original-rc.local
    if [ "$mode" = qubes ]; then
        printf 'for rc in /rw/config/rc.local.d/*.rc /rw/config/rc.local; do :; done\n' > /usr/lib/qubes/init/misc-post.sh
    fi
    # Simulate an existing installation made by the original installer.
    echo 'old unit' > /etc/systemd/system/setupvpn-client.service
fi

cd /work
sh ./install-linux.sh
sh ./install-linux.sh 02
if [ "$mode" = linux ]; then
    destination=/etc/setupvpn-client
    grep -Fxq 'enable --now setupvpn-client.service' /run/systemctl-calls
    [ ! -e /rw/config/setupvpn-client ]
else
    destination=/rw/config/setupvpn-client
    [ ! -e /etc/systemd/system/setupvpn-client.service ]
    [ -f "$destination/enabled" ]
    if [ "$mode" = qubes ]; then
        cmp /work/original-rc.local /rw/config/rc.local
        [ -x /rw/config/rc.local.d/90-setupvpn-client.rc ]
    else
        [ "$(grep -Fxc '/bin/sh /rw/config/setupvpn-client/service.sh boot' /rw/config/rc.local)" = 1 ]
        sed '\|^/bin/sh /rw/config/setupvpn-client/service.sh boot$|d' /rw/config/rc.local > /work/restored-rc.local
        cmp /work/original-rc.local /work/restored-rc.local
    fi
fi
cmp xray-tun-02.json "$destination/xray-tun-01.json"
cmp xray-socks-02.json "$destination/xray-socks-01.json"
[ "$(stat -c %a "$destination")" = 700 ]
[ "$(stat -c %a "$destination/xray-tun-01.json")" = 600 ]
[ -e /run/mock-active ]

if [ "$mode" != linux ]; then
    boot() {
        # AppVM private storage survives; its root filesystem and /run do not.
        rm -rf /etc /run
        mkdir -p /etc/systemd/system /run
        for hook in /rw/config/rc.local.d/*.rc /rw/config/rc.local; do
            [ ! -x "$hook" ] || "$hook"
        done
        grep -Fxq existing /run/existing
    }
    boot
    [ -e /run/mock-active ]
    grep -Fxq -- '--no-block start setupvpn-client.service' /run/systemctl-calls
    grep -Fxq 'After=qubes-misc-post.service' /run/systemd/system/setupvpn-client.service
    cmp /work/xray-tun-02.json "$destination/xray-tun-01.json"
    sh "$destination/service.sh" disable
    [ ! -e /run/mock-active ]
    boot
    [ ! -e /run/mock-active ]
    sh "$destination/service.sh" disable
    [ ! -e /run/mock-active ]
    sh "$destination/service.sh" enable
    [ -e /run/mock-active ]
fi
