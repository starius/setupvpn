package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/Luzifer/go-openssl/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/term"
)

const (
	xrayDir     = "/opt/xray"
	xrayExe     = xrayDir + "/xray"
	xrayConfig  = xrayDir + "/config.json"
	xrayService = "/usr/lib/systemd/system/xray.service"
	sysctlConf  = "/etc/sysctl.conf"
	sysctlDir   = "/etc/sysctl.d"

	wireguardDir  = "/etc/wireguard"
	wireguardConf = wireguardDir + "/wg0.conf"
)

var (
	encrypt       = flag.Bool("encrypt", false, "Put client configs into an encrypted tar.gz archive")
	skipVless     = flag.Bool("skip-vless", false, "Skip installing Xray (VLESS)")
	skipWireguard = flag.Bool("skip-wireguard", false, "Skip installing Wireguard")
	serverIp      = flag.String("server-ip", "", "Server IP address (leave empty to determine automatically)")
	vlessDomain   = flag.String("vless-domain", "", "REALITY target domain (empty = automatically select an ML-KEM-capable target)")
	nClients      = flag.Int("n-clients", 50, "Number of client profiles to generate")
	wireguardPort = flag.Int("wireguard-port", 0, "Port for wireguard to listen in (0 = random)")
)

func installVlessExe() {
	res, err := (&http.Client{Timeout: 3 * time.Minute}).Get(vlessUrl)
	if err != nil {
		panic(err)
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		panic(fmt.Errorf("download Xray: HTTP %d", res.StatusCode))
	}
	vlessZipBytes, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	if err := res.Body.Close(); err != nil {
		panic(err)
	}
	if gotHash := sha256.Sum256(vlessZipBytes); hex.EncodeToString(gotHash[:]) != vlessSha256 {
		panic("mismatch of vless zip hash")
	}
	vlessZipReader, err := zip.NewReader(bytes.NewReader(vlessZipBytes), int64(len(vlessZipBytes)))
	if err != nil {
		panic(err)
	}
	xrayFile, err := vlessZipReader.Open("xray")
	if err != nil {
		panic(err)
	}
	xrayExeFile, err := os.OpenFile(xrayExe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		panic(err)
	}
	if _, err := io.Copy(xrayExeFile, xrayFile); err != nil {
		panic(err)
	}
	if err := xrayExeFile.Close(); err != nil {
		panic(err)
	}
}

func getMyIp() string {
	if *serverIp != "" {
		return *serverIp
	}

	type IP struct {
		Query string
	}

	req, err := http.Get("http://ip-api.com/json/")
	if err != nil {
		panic(err)
	}
	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}

	var ip IP
	if err := json.Unmarshal(body, &ip); err != nil {
		panic(err)
	}

	return ip.Query
}

func getWireguardPort() int {
	if *wireguardPort != 0 {
		return *wireguardPort
	}
	// Generate random port > 1024.
	for {
		portBytes := make([]byte, 2)
		if _, err := rand.Read(portBytes); err != nil {
			panic(err)
		}
		port := int(portBytes[0])<<8 | int(portBytes[1])
		if port > 1024 {
			return port
		}
	}
}

func generateVlessParams() (privateKeyHex, publicKeyHex, userID string, shortIds []string) {
	// See https://github.com/XTLS/Xray-core/blob/main/main/commands/all/x25519.go
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		panic(err)
	}
	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	privateKeyHex = base64.RawURLEncoding.EncodeToString(privateKey)
	publicKeyHex = base64.RawURLEncoding.EncodeToString(publicKey)

	uuid := uuid.New()
	userID = uuid.String()

	shortIds = make([]string, 0, *nClients)
	for i := 0; i < *nClients; i++ {
		shortId := make([]byte, 8)
		if _, err = rand.Read(shortId); err != nil {
			panic(err)
		}
		shortIds = append(shortIds, hex.EncodeToString(shortId))
	}
	return privateKeyHex, publicKeyHex, userID, shortIds
}

func generateVlessConfig(privateKeyHex, userID string, shortIds []string, mldsaSeed string) string {
	shortIdsQuoted := make([]string, 0, len(shortIds))
	for _, shortId := range shortIds {
		shortIdsQuoted = append(shortIdsQuoted, fmt.Sprintf("%q", shortId))
	}

	return fmt.Sprintf(`{
  "log": {
    "loglevel": "none"
  },
  "routing": {
    "rules": [],
    "domainStrategy": "AsIs"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "tag": "vless_tls",
      "settings": {
        "clients": [
          {
            "id": %[1]q,
            "email": "user1@myserver",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "%[2]s:443",
          "xver": 0,
          "serverNames": [
            %[2]q
          ],
          "privateKey": %[3]q,
          "mldsa65Seed": %[5]q,
          "minClientVer": "",
          "maxClientVer": "",
          "maxTimeDiff": 0,
          "shortIds": [
            %[4]s
          ]
        }
      },
      "sniffing": {
        "enabled": false,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
`, userID, *vlessDomain, privateKeyHex, strings.Join(shortIdsQuoted, ","), mldsaSeed)
}

func installVlessConfig(privateKeyHex, userID string, shortIds []string, mldsaSeed string) {
	if err := os.WriteFile(xrayConfig, []byte(generateVlessConfig(privateKeyHex, userID, shortIds, mldsaSeed)), 0644); err != nil {
		panic(err)
	}
}

func installVlessService() {
	var xrayServiceContent = fmt.Sprintf(`[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=%[1]s run -config %[2]s
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
`, xrayExe, xrayConfig)

	if err := os.WriteFile(xrayService, []byte(xrayServiceContent), 0644); err != nil {
		panic(err)
	}
	systemctlExe, err := exec.LookPath("systemctl")
	if err != nil {
		panic(err)
	}
	if output, err := exec.Command(systemctlExe, "daemon-reload").CombinedOutput(); err != nil {
		panic(fmt.Errorf("systemctl daemon-reload: %w: %s", err, output))
	}
	cmd := exec.Command(systemctlExe, "enable", "xray")
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}

func writePerformanceConfig(configDir, fallbackPath string) (string, error) {
	const settings = `
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
`
	if info, err := os.Stat(configDir); err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("%s is not a directory", configDir)
		}
		path := filepath.Join(configDir, "99-setupvpn.conf")
		return path, os.WriteFile(path, []byte(settings), 0644)
	} else if !os.IsNotExist(err) {
		return "", err
	}

	f, err := os.OpenFile(fallbackPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return "", err
	}
	if _, err := f.Write([]byte(settings)); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return fallbackPath, nil
}

func improvePerformace() {
	configPath, err := writePerformanceConfig(sysctlDir, sysctlConf)
	if err != nil {
		panic(err)
	}

	sysctlExe, err := exec.LookPath("sysctl")
	if err != nil {
		panic(err)
	}
	cmd := exec.Command(sysctlExe, "-p", configPath)
	if err := cmd.Run(); err != nil {
		panic(err)
	}

	qdisk, err := os.ReadFile("/proc/sys/net/core/default_qdisc")
	if err != nil {
		panic(err)
	}
	if string(bytes.TrimSpace(qdisk)) != "fq" {
		fmt.Println("Warning! Failed to set /proc/sys/net/core/default_qdisc")
	}

	tcc, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil {
		panic(err)
	}
	if string(bytes.TrimSpace(tcc)) != "bbr" {
		fmt.Println("Warning! Failed to set /proc/sys/net/ipv4/tcp_congestion_control")
	}
}

func httpsWorks(myIp string) bool {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		// DualStack: true, // this is deprecated as of go 1.16
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == fmt.Sprintf("%s:443", *vlessDomain) {
				addr = net.JoinHostPort(myIp, "443")
			}
			return dialer.DialContext(ctx, network, addr)

		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	res, err := client.Get(fmt.Sprintf("https://%s/", *vlessDomain))
	if res != nil {
		res.Body.Close()
	}
	return err == nil
}

func checkTcpServer(address string) bool {
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return false
	}
	if err := conn.Close(); err != nil {
		panic(err)
	}
	return true
}

func startAndCheckVless(myIp string) {
	if httpsWorks(myIp) {
		panic("control check for https proxying passed before starting the service")
	}

	systemctlExe, err := exec.LookPath("systemctl")
	if err != nil {
		panic(err)
	}
	cmd := exec.Command(systemctlExe, "restart", "xray")
	if err := cmd.Run(); err != nil {
		panic(err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for !checkTcpServer(net.JoinHostPort(myIp, "443")) {
		if time.Now().After(deadline) {
			panic("Xray did not start within 30 seconds; check journalctl -u xray")
		}
		fmt.Println("Waiting for server to start on port 443.")
		time.Sleep(time.Second)
	}

	if !httpsWorks(myIp) {
		panic("check for https proxying failed after starting the service")
	}
}

type file struct {
	name    string
	content []byte
}

func installVless(myIp string) []file {
	if checkTcpServer(net.JoinHostPort(myIp, "443")) {
		panic("port 443 on the machine is already used")
	}

	domain, err := selectRealityTarget(*vlessDomain)
	if err != nil {
		panic(err)
	}
	*vlessDomain = domain
	fmt.Println("REALITY target:", domain)
	if err := os.Mkdir(xrayDir, 0755); os.IsExist(err) {
		panic("Remove " + xrayDir)
	} else if err != nil {
		panic(err)
	}
	privateKeyHex, publicKeyHex, userID, shortIds := generateVlessParams()
	seed, verify := generateMLDSAKeys()
	installVlessExe()
	installVlessConfig(privateKeyHex, userID, shortIds, seed)
	installVlessService()
	improvePerformace()
	startAndCheckVless(myIp)

	if err := verifyVlessConnection(xrayExe, xrayClientConfig(publicKeyHex, verify, userID, shortIds[0], myIp, false)); err != nil {
		panic(fmt.Errorf("Xray tunnel self-test failed: %w", err))
	}
	fmt.Println("Xray tunnel verified: X25519MLKEM768 + ML-DSA-65")
	return generateVlessClientConfigs(publicKeyHex, verify, userID, shortIds, myIp)
}

func generateWireguardKeys() (privateKey, publicKey string) {
	wgExe, err := exec.LookPath("wg")
	if err != nil {
		panic(err)
	}
	privateKeyBytes, err := exec.Command(wgExe, "genkey").Output()
	if err != nil {
		panic(err)
	}
	cmd := exec.Command(wgExe, "pubkey")
	cmd.Stdin = bytes.NewReader(privateKeyBytes)
	publicKeyBytes, err := cmd.Output()
	if err != nil {
		panic(err)
	}
	return string(bytes.TrimSpace(privateKeyBytes)), string(bytes.TrimSpace(publicKeyBytes))
}

type WireguardPeer struct {
	PrivateKey string
	PublicKey  string
}

const wg0Template = `[Interface]
PrivateKey = {{ .PrivateKey }}
Address = 192.168.30.1/32
ListenPort = {{ .Port }}
PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -A FORWARD -i %i -o %i -j DROP; iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o %i -j DROP; iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
{{ range $i, $peer := .Peers }}
[Peer]
PublicKey = {{ $peer.PublicKey }}
AllowedIPs = 192.168.30.{{ add 2 $i }}/32
{{ end }}
`

func installWireguardConfig(serverPrivate string, port int, peers []WireguardPeer) {
	funcs := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
	}
	tmpl := template.Must(template.New("wg0Template").Funcs(funcs).Parse(wg0Template))
	vars := struct {
		PrivateKey string
		Port       int
		Peers      []WireguardPeer
	}{
		PrivateKey: serverPrivate,
		Port:       port,
		Peers:      peers,
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		panic(err)
	}
	if err := os.WriteFile(wireguardConf, buf.Bytes(), 0600); err != nil {
		panic(err)
	}
}

func startWireguard() {
	wgQuickExe, err := exec.LookPath("wg-quick")
	if err != nil {
		panic(err)
	}
	cmd := exec.Command(wgQuickExe, "up", "wg0")
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}

func installWireguardService() {
	systemctlExe, err := exec.LookPath("systemctl")
	if err != nil {
		panic(err)
	}
	cmd := exec.Command(systemctlExe, "enable", "wg-quick@wg0.service")
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}

const wgClientTemplate = `[Interface]
PrivateKey = {{ .ClientPrivateKey }}
Address = 192.168.30.{{ add 2 .ClientIndex }}/32
DNS = 1.1.1.1
PostUp = iptables -t nat -I PREROUTING 1 -p udp -m udp --dport 53 -j DNAT --to-destination 1.1.1.1; iptables -t nat -I POSTROUTING 3 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

[Peer]
PublicKey = {{ .ServerPublicKey }}
Endpoint = {{ .ServerIp }}:{{ .ServerPort }}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`

func generateWireguardClientConfigs(myIp, serverPublic string, port int, peers []WireguardPeer) (files []file) {
	funcs := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
	}
	tmpl := template.Must(template.New("wgClientTemplate").Funcs(funcs).Parse(wgClientTemplate))

	for i, peer := range peers {
		vars := struct {
			ServerPublicKey  string
			ServerIp         string
			ServerPort       int
			ClientIndex      int
			ClientPrivateKey string
		}{
			ServerPublicKey:  serverPublic,
			ServerIp:         myIp,
			ServerPort:       port,
			ClientIndex:      i,
			ClientPrivateKey: peer.PrivateKey,
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, vars); err != nil {
			panic(err)
		}
		name := fmt.Sprintf("wg%02d.conf", i+2)
		files = append(files, file{
			name:    name,
			content: buf.Bytes(),
		})
	}

	readmeContent := fmt.Sprintf(`To run on Linux, install wireguard.

On Debian 11+:
$ sudo apt-get install wireguard resolvconf
$ sudo modprobe wireguard
$ echo $?
0

Copy one of client files (e.g. wg02.conf) to /etc/wireguard/wg02.conf and run:
$ sudo wg-quick up wg02

Check connection. If everything works well, run to start it automatically:
$ sudo systemctl enable wg-quick@wg02.service

If you want to put the config somewhere else (e.g. /home/user/wg02.conf),
you can use the following command to start it manually:
$ sudo wg-quick up /home/user/wg02.conf

To run on mobile, install Wireguard from Play store or App store and import
config file to it. Remove PostUp section from the config, it is not needed.

Server config: %s
Restart server: sudo wg-quick down wg0 ; sudo wg-quick up wg0

See https://forum.qubes-os.org/t/wireguard/19082 for more info.
`, wireguardConf)
	files = append(files, file{
		name:    "README",
		content: []byte(readmeContent),
	})

	return files
}

func installWireguard(myIp string) []file {
	if _, err := os.Stat(wireguardDir); os.IsNotExist(err) {
		panic("Wireguard dir does not exist: " + wireguardDir + " . Install wireguard: sudo apt-get install wireguard resolvconf")
	}
	if _, err := os.Stat(wireguardConf); err == nil {
		panic("Wireguard conf already exists: " + wireguardConf)
	}

	serverPrivate, serverPublic := generateWireguardKeys()
	port := getWireguardPort()
	peers := make([]WireguardPeer, 0, *nClients)
	for i := 0; i < *nClients; i++ {
		peerPrivate, peerPublic := generateWireguardKeys()
		peers = append(peers, WireguardPeer{
			PrivateKey: peerPrivate,
			PublicKey:  peerPublic,
		})
	}
	installWireguardConfig(serverPrivate, port, peers)
	startWireguard()
	installWireguardService()

	return generateWireguardClientConfigs(myIp, serverPublic, port, peers)
}

func main() {
	flag.Parse()
	if *nClients < 1 {
		panic("-n-clients must be at least 1")
	}

	myIp := getMyIp()

	dir2files := map[string][]file{}
	if !*skipVless {
		dir2files["vless"] = installVless(myIp)
	}
	if !*skipWireguard {
		dir2files["wireguard"] = installWireguard(myIp)
	}

	if *encrypt {
		var buf bytes.Buffer
		gzw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gzw)
		for dir, files := range dir2files {
			for _, f := range files {
				hdr := &tar.Header{
					Name: filepath.Join(dir, f.name),
					Mode: 0600,
					Size: int64(len(f.content)),
				}
				if err := tw.WriteHeader(hdr); err != nil {
					panic(err)
				}
				if _, err := tw.Write(f.content); err != nil {
					panic(err)
				}
			}
		}
		if err := tw.Close(); err != nil {
			panic(err)
		}
		if err := gzw.Close(); err != nil {
			panic(err)
		}

		fmt.Printf("Encryption password for client configs: ")
		passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			panic(err)
		}
		fmt.Println()
		enc, err := openssl.New().EncryptBytes(string(passphrase), buf.Bytes(), openssl.PBKDF2SHA256)
		if err != nil {
			panic(err)
		}

		f, err := os.CreateTemp("", "setupvpn-configs-*.tar.gz.enc")
		if err != nil {
			panic(err)
		}
		n, err := f.Write(enc)
		if err != nil {
			panic(err)
		}
		if n != len(enc) {
			panic("short write")
		}
		encFile := f.Name()
		if err := f.Close(); err != nil {
			panic(err)
		}
		fmt.Printf("Client configs were compressed and encrypted and written to file %s\n", encFile)
		fmt.Println("Copy the file to safe place and unpack using the following command:")
		fmt.Printf("openssl enc -d -base64 -A -aes-256-cbc -pbkdf2 -md sha256 -in %s -out - | tar -xzf-\n", filepath.Base(encFile))
	} else {
		root, err := os.MkdirTemp("", "setupvpn-configs-*")
		if err != nil {
			panic(err)
		}
		for dir, files := range dir2files {
			if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
				panic(err)
			}
			for _, f := range files {
				path := filepath.Join(root, dir, f.name)
				if err := os.WriteFile(path, []byte(f.content), 0600); err != nil {
					panic(err)
				}
			}
		}
		fmt.Printf("Client configs were written to directory %s\n", root)
	}
}
