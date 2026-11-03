package main

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed scripts/start-linux.sh
var linuxLauncher string

//go:embed scripts/install-linux.sh
var linuxInstaller string

type object = map[string]any

func generateMLDSAKeys() (seed, verify string) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), raw)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

// Probe using the same hybrid group we require for the actual REALITY tunnel.
// A failed probe must not silently downgrade to classical key exchange.
func checkRealityTarget(domain string) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(domain, "443"), &tls.Config{
		ServerName: domain, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}, NextProtos: []string{"h2"},
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if state.CurveID != tls.X25519MLKEM768 {
		return fmt.Errorf("target did not negotiate X25519MLKEM768")
	}
	if state.NegotiatedProtocol != "h2" {
		return fmt.Errorf("target does not support HTTP/2")
	}
	size := 0
	for _, cert := range state.PeerCertificates {
		size += len(cert.Raw)
	}
	if size <= 3500 {
		return fmt.Errorf("target certificate chain is %d bytes; ML-DSA-65 requires more than 3500", size)
	}
	return nil
}

func selectRealityTarget(requested string) (string, error) {
	candidates := []string{"www.google.com", "www.microsoft.com"}
	if requested != "" {
		candidates = []string{requested}
	}
	var failures []string
	for _, domain := range candidates {
		if err := checkRealityTarget(domain); err != nil {
			failures = append(failures, domain+": "+err.Error())
			continue
		}
		return domain, nil
	}
	return "", fmt.Errorf("no suitable REALITY target (TLS 1.3, HTTP/2, ML-KEM, large certificate chain): %s", strings.Join(failures, "; "))
}

func jsonBytes(value any) []byte {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

func xrayClientConfig(publicKey, verify, userID, shortID, server string, tun bool) object {
	inbounds := []object{{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": object{"udp": true}}}
	if tun {
		inbounds = append(inbounds, object{
			"tag": "tun", "protocol": "tun",
			"settings": object{
				"name": "setupvpn0", "mtu": 1500,
				"gateway":                []string{"172.19.0.1/30", "fd19:19::1/126"},
				"autoSystemRoutingTable": []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"},
				"autoOutboundsInterface": "auto",
			},
		})
	}
	return object{
		"log":      object{"loglevel": "warning"},
		"dns":      object{"servers": []string{"https://1.1.1.1/dns-query"}},
		"inbounds": inbounds,
		"outbounds": []object{
			{
				"tag": "proxy", "protocol": "vless",
				"settings": object{"vnext": []object{{"address": server, "port": 443, "users": []object{{"id": userID, "encryption": "none", "flow": "xtls-rprx-vision"}}}}},
				"streamSettings": object{
					"network": "tcp", "security": "reality",
					"realitySettings": object{"fingerprint": "chrome", "serverName": *vlessDomain, "password": publicKey, "shortId": shortID, "mldsa65Verify": verify, "alpn": []string{"h2"}},
				},
			},
			{"tag": "dns", "protocol": "dns"},
		},
		"routing": object{"domainStrategy": "AsIs", "rules": []object{{"type": "field", "inboundTag": []string{"tun"}, "port": "53", "outboundTag": "dns"}}},
	}
}

func vlessShareLink(publicKey, verify, userID, shortID, server string, number int) string {
	query := url.Values{
		"type": {"tcp"}, "encryption": {"none"}, "flow": {"xtls-rprx-vision"},
		"security": {"reality"}, "sni": {*vlessDomain}, "fp": {"chrome"}, "alpn": {"h2"},
		"pbk": {publicKey}, "sid": {shortID}, "pqv": {verify},
	}
	u := url.URL{Scheme: "vless", User: url.User(userID), Host: net.JoinHostPort(server, "443"), RawQuery: query.Encode(), Fragment: fmt.Sprintf("setupvpn-%02d", number)}
	return u.String() + "\n"
}

func generateVlessClientConfigs(publicKey, verify, userID string, shortIDs []string, server string) (files []file) {
	for i, shortID := range shortIDs {
		for _, tun := range []bool{true, false} {
			kind := "socks"
			if tun {
				kind = "tun"
			}
			files = append(files, file{fmt.Sprintf("xray-%s-%02d.json", kind, i+1), jsonBytes(xrayClientConfig(publicKey, verify, userID, shortID, server, tun))})
		}
		files = append(files, file{fmt.Sprintf("v2rayng-%02d.txt", i+1), []byte(vlessShareLink(publicKey, verify, userID, shortID, server, i+1))})
	}
	replacer := strings.NewReplacer("@VERSION@", xrayVersion, "@AMD64_URL@", xrayAMD64URL, "@AMD64_SHA@", xrayAMD64SHA256, "@ARM64_URL@", xrayARM64URL, "@ARM64_SHA@", xrayARM64SHA256)
	files = append(files, file{"start-linux.sh", []byte(replacer.Replace(linuxLauncher))}, file{"install-linux.sh", []byte(linuxInstaller)})
	files = append(files, file{"README", []byte(fmt.Sprintf(`Your Xray VPN is ready. No configuration edits are needed.
Keep this directory private: its files contain access credentials.
Each numbered set contains equivalent Linux and Android profiles. Choose one
number per device. All profiles require ML-DSA-65 server verification and use
the Chrome fingerprint for X25519MLKEM768 key exchange.

ANDROID
Install v2rayNG 2.3.14 or newer from the official project:
%s
Most phones use the arm64-v8a APK; choose universal if unsure.
Copy the entire single line from v2rayng-01.txt, then in v2rayNG choose
Add (+) -> Import from clipboard. Select setupvpn-01 and press Start.
Accept Android's VPN permission prompt. The link includes the ML-DSA-65 key.
Use these new links; old links do not contain the required verification key.

If Start does nothing and no VPN permission prompt appears, open Android
Settings -> VPN and turn off Always-on VPN for any other VPN app (such as
NekoBox). Then start v2rayNG again and accept the permission prompt. Android
can silently prevent a new VPN app from connecting while another app is set
as always-on. Once connected, you can enable Always-on VPN for v2rayNG instead.

LINUX: CONNECT NOW
Copy this directory to your Linux computer, open a terminal in it, and run:
  sudo sh ./start-linux.sh
This downloads and verifies Xray %s for amd64/arm64, then tunnels IPv4,
IPv6 and DNS. Press Ctrl+C to stop and restore DNS and routes.
To use a different profile, append its number: sudo sh ./start-linux.sh 02
Prerequisites: curl, unzip, sha256sum, ip and flock.
On Debian/Ubuntu: sudo apt-get install curl unzip iproute2 util-linux

LINUX: CONNECT AUTOMATICALLY AT BOOT (systemd)
  sudo sh ./install-linux.sh
Or choose a profile: sudo sh ./install-linux.sh 02
The installer copies just that profile and Xray into /etc/setupvpn-client,
enables setupvpn-client.service, and starts it immediately.
Stop and disable: sudo systemctl disable --now setupvpn-client
Status/logs: sudo systemctl status setupvpn-client; sudo journalctl -u setupvpn-client
If the machine lost power during a session, DNS is restored on the next start.

LINUX: OPTIONAL SOCKS PROXY ONLY (does not change routes or DNS)
  sh ./start-linux.sh --socks
  curl --socks5-hostname 127.0.0.1:10808 https://api.ipify.org
This mode needs no root privileges. Applications must explicitly use the proxy.

Server: %s:443
REALITY target: %s
Server config: %s
Restart server: systemctl restart xray
`, androidReleaseURL, xrayVersion, server, *vlessDomain, xrayConfig))})
	return files
}

// Test an authenticated tunnel, rather than only REALITY's unauthenticated
// fallback. Debug output is kept private because Xray can print session keys.
func verifyVlessConnection(binary string, config object) error {
	dir, err := os.MkdirTemp("", "setupvpn-selftest-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	config["inbounds"] = []object{{"listen": "127.0.0.1", "port": port, "protocol": "socks"}}
	config["outbounds"].([]object)[0]["streamSettings"].(object)["realitySettings"].(object)["show"] = true
	path := filepath.Join(dir, "client.json")
	if err := os.WriteFile(path, jsonBytes(config), 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "run", "-config", path)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	ready := false
	for i := 0; i < 100; i++ {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		return fmt.Errorf("self-test SOCKS listener did not start")
	}
	proxyURL := &url.URL{Scheme: "socks5", Host: address}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 25 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.gstatic.com/generate_204", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("authenticated HTTPS request: %w", err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	cmd.Process.Kill()
	cmd.Wait()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("self-test HTTP status %d", response.StatusCode)
	}
	for _, marker := range []string{"is using X25519MLKEM768 for TLS' communication: true", "is using ML-DSA-65 for cert's extra verification: true"} {
		if !strings.Contains(output.String(), marker) {
			return fmt.Errorf("self-test did not confirm %s", marker)
		}
	}
	return nil
}
