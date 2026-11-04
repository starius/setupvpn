# setupvpn
Server-side wireguard and VLESS installer written in Go

Build the binary with Go 1.27.3 or newer:
```
$ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -buildid=" -o setupvpn-amd64
$ CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -buildid=" -o setupvpn-arm64
```

Or get the binary from https://github.com/starius/setupvpn/releases

The VLESS setup uses [Xray 26.10.31](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31)
on the server and Linux clients, and [v2rayNG 2.3.14](https://github.com/2dust/v2rayNG/releases/tag/2.3.14)
or newer on Android. Both ML-DSA-65 server authentication and hybrid
X25519MLKEM768 key exchange are enabled. Linux downloads for amd64 and arm64
are pinned with SHA-256 checksums.

Copy the setupvpn binary to your server and run it as root. For VLESS only:

```sh
sudo ./setupvpn-amd64 -skip-wireguard
```

Without the skip flags, it sets up both VLESS and WireGuard (WireGuard and
`wg-quick` must already be installed). The installer selects a REALITY target
automatically, checks its TLS 1.3, HTTP/2, ML-KEM and certificate-chain size,
and verifies an authenticated HTTPS request through the new tunnel before
reporting success. `-vless-domain` optionally selects a specific target; an
incompatible target is rejected rather than silently reducing protection.

Copy the generated `vless` directory to each client. No JSON edits are needed:

- **Android:** install v2rayNG from the official release above, then import the
  complete line from `v2rayng-01.txt` using **Add (+) → Import from clipboard**.
  Select the profile and start the VPN. The link includes the ML-DSA verification
  key (`pqv`), so replace old links when migrating.

  If Start does nothing and no VPN permission prompt appears, check **Android
  Settings → VPN**. Turn off **Always-on VPN** for any other VPN app (such as
  NekoBox), then start v2rayNG again and accept the permission prompt. Android
  can silently prevent a new VPN app from connecting while another app is set
  as always-on. Once connected, you can enable Always-on VPN for v2rayNG instead.
- **Linux, connect now:** run `sudo sh ./start-linux.sh` in that directory.
  It downloads the verified Xray binary, sets up IPv4/IPv6 Internet routes and
  DNS, and restores them on Ctrl+C. Requires `curl`, `unzip`, `sha256sum`,
  `ip` and `flock` (`sudo apt-get install curl unzip iproute2 util-linux` on Debian/Ubuntu).
- **Linux, connect at boot:** run `sudo sh ./install-linux.sh` on a systemd
  machine. This installs and starts `setupvpn-client.service`. Stop it with
  `sudo systemctl disable --now setupvpn-client` on ordinary Linux.
- **Qubes OS, connect at boot:** run the same `sudo sh ./install-linux.sh`
  inside the app qube that should use the VPN. It detects Qubes and installs
  the selected profile, Xray, and service files in `/rw/config/setupvpn-client`.
  A [Qubes boot hook](https://doc.qubes-os.org/en/r4.3/user/advanced-topics/config-files.html)
  restores the systemd service and starts it after each AppVM restart. It uses
  `rc.local.d` when supported, otherwise preserves and updates `rc.local`.
  Install the prerequisites in the qube's template so they persist too.
  Stop and persistently disable with
  `sudo sh /rw/config/setupvpn-client/service.sh disable`; use `enable` to
  re-enable and start it. Disposable qubes discard the installation when destroyed.
- **Linux, SOCKS only:** run `sh ./start-linux.sh --socks` for a proxy on
  `127.0.0.1:10808`, without changing routes or DNS.

Each client number has `xray-tun-NN.json`, `xray-socks-NN.json`, and
`v2rayng-NN.txt`. The scripts default to `01`; append `02`, etc., to choose
another profile. Keep all generated files private. The generated README also
contains these instructions and the server details.

Linux's TUN routes are active while Xray runs; this is not a persistent kill
switch. DNS uses systemd-resolved when available, otherwise the launcher saves
and temporarily updates `/etc/resolv.conf`, restoring it when stopped. After
an abrupt interruption, the saved static resolver is recovered on next start.

Run the checks with the pinned Xray binary:

```sh
XRAY_BIN=/absolute/path/to/xray go test -v ./...
go vet ./...
```

The integration test uses only loopback listeners. It exercises a real
ML-KEM/ML-DSA REALITY tunnel and checks that an incorrect signature key is
rejected; it never creates a TUN interface or changes routes. It skips when
`XRAY_BIN` is unset. Linux TUN and DNS should be tested in a separate network
namespace or disposable client, not on the machine running a remote session.
Installer tests use an isolated filesystem and network namespace with a mocked
service manager. They check ordinary Linux and Qubes startup, reinstallation,
and persistent disabling; they skip if Linux user namespaces are unavailable.

Flags:

```
Usage of ./setupvpn:
  -encrypt
        Put client configs into an encrypted tar.gz archive
  -n-clients int
        Number of client profiles to generate (default 50)
  -server-ip string
        Server IP address (leave empty to determine automatically)
  -skip-vless
        Skip installing Xray (VLESS)
  -skip-wireguard
        Skip installing Wireguard
  -vless-domain string
        REALITY target domain (empty = automatically select an ML-KEM-capable target)
  -wireguard-port int
        Port for wireguard to listen in (0 = random)
```

Use `-skip-vless` and `-skip-wireguard` options to disable the corresponding
server.

Example. Install wireguard only.

```
setupvpn -skip-vless
```

Use `-encrypt` to pack and encrypt all client configs. This is safer,
because raw configs won't be stored on the server's storage.

```
setupvpn -encrypt
Encryption password for client configs:
Client configs were compressed and encrypted and written to file /tmp/setupvpn-configs-1234567890.tar.gz.enc
Copy the file to safe place and unpack using the following command:
openssl enc -d -base64 -A -aes-256-cbc -pbkdf2 -md sha256 -in setupvpn-configs-1234567890.tar.gz.enc -out - | tar -xzf-
```
