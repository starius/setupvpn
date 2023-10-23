package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
)

const (
	vlessUrl    = "https://github.com/XTLS/Xray-core/releases/download/v1.8.4/Xray-linux-64.zip"
	vlessSha256 = "2a855f610008a598b88424435aefaee1df2c1b0fa1296d4f8f60080b528c9971"
	xrayDir     = "/opt/xray"
	xrayExe     = xrayDir + "/xray"
	xrayConfig  = xrayDir + "/config.json"
	xrayService = "/usr/lib/systemd/system/xray.service"
	sysctlConf  = "/etc/sysctl.conf"
)

var (
	skipVless   = flag.Bool("skip-vless", false, "Skip installing VLESS")
	vlessDomain = flag.String("vless-domain", "google.com", "Masking domain used by VLESS server")
	nClients    = flag.Int("n-clients", 50, "Number of client configs to generate")
)

func installVlessExe() {
	res, err := http.Get(vlessUrl)
	if err != nil {
		panic(err)
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
	xrayExeFile, err := os.OpenFile(xrayExe, os.O_CREATE|os.O_WRONLY, 0755)
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
	type IP struct {
		Query string
	}

	req, err := http.Get("http://ip-api.com/json/")
	if err != nil {
		panic(err)
	}
	defer req.Body.Close()

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}

	var ip IP
	if err := json.Unmarshal(body, &ip); err != nil {
		panic(err)
	}

	return ip.Query
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

func installVlessConfig(privateKeyHex, userID string, shortIds []string) {
	shortIdsQuoted := make([]string, 0, len(shortIds))
	for _, shortId := range shortIds {
		shortIdsQuoted = append(shortIdsQuoted, fmt.Sprintf("%q", shortId))
	}

	var xrayConfigContent = fmt.Sprintf(`{
  "log": {
    "loglevel": "info"
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
          "minClientVer": "",
          "maxClientVer": "",
          "maxTimeDiff": 0,
          "shortIds": [
            %[4]s
          ]
        }
      },
      "sniffing": {
        "enabled": true,
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
`, userID, *vlessDomain, privateKeyHex, strings.Join(shortIdsQuoted, ","))

	if err := os.WriteFile(xrayConfig, []byte(xrayConfigContent), 0644); err != nil {
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
	cmd := exec.Command(systemctlExe, "enable", "xray")
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}

func improvePerformace() {
	var sysctlConfAppendix = `
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
`
	f, err := os.OpenFile(sysctlConf, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		panic(err)
	}
	if _, err := f.Write([]byte(sysctlConfAppendix)); err != nil {
		panic(err)
	}
	if err := f.Close(); err != nil {
		panic(err)
	}

	sysctlExe, err := exec.LookPath("sysctl")
	if err != nil {
		panic(err)
	}
	cmd := exec.Command(sysctlExe, "-p")
	if err := cmd.Run(); err != nil {
		panic(err)
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
				addr = fmt.Sprintf("%s:443", myIp)
			}
			return dialer.DialContext(ctx, network, addr)

		},
	}
	client := &http.Client{Transport: tr}
	_, err := client.Get(fmt.Sprintf("https://%s/"))
	return err == nil
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

	if !httpsWorks(myIp) {
		panic("check for https proxying failed after starting the service")
	}
}

const singboxConfigTemplate = `{
  "dns": {
    "independent_cache": true,
    "rules": [
      {
        "query_type": [
          32,
          33
        ],
        "server": "dns-block"
      },
      {
        "domain_suffix": ".lan",
        "server": "dns-block"
      }
    ],
    "servers": [
      {
        "address": "https://8.8.8.8/dns-query",
        "detour": "proxy",
        "strategy": "",
        "tag": "dns-remote"
      }
    ]
  },
  "inbounds": [
    {
      "auto_route": true,
      "domain_strategy": "",
      "endpoint_independent_nat": true,
      "inet4_address": "172.19.0.1/28",
      "interface_name": "nekoray-tun",
      "mtu": 1500,
      "sniff": true,
      "sniff_override_destination": false,
      "stack": "gvisor",
      "strict_route": false,
      "tag": "tun-in",
      "type": "tun"
    }
  ],
  "log": {
    "level": "info"
  },
  "outbounds": [
    {
      "domain_strategy": "",
      "flow": "xtls-rprx-vision",
      "packet_encoding": "xudp",
      "server": %[1]q,
      "server_port": 443,
      "tag": "proxy",
      "tls": {
        "alpn": [
          "h2"
        ],
        "enabled": true,
        "reality": {
          "enabled": true,
          "public_key": %[4]q,
          "short_id": %[5]q
        },
        "server_name": %[2]q,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      },
      "type": "vless",
      "uuid": %[3]q
    },
    {
      "tag": "dns-remote",
      "type": "dns"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "final": "proxy",
    "rules": [
      {
        "outbound": "dns-remote",
        "protocol": "dns"
      }
    ]
  }
}
`

const nekoboxConfigTemplate = `vless://%[3]q@%[1]q:443/?type=tcp&encryption=none&flow=xtls-rprx-vision&sni=%[2]q&alpn=h2&fp=chrome&security=reality&pbk=%[4]q&sid=%[5]q&packetEncoding=xudp#conn1`

func generateClientConfigs(publicKeyHex, userID string, shortIds []string, myIp string) {
	dir, err := os.MkdirTemp("", "vless-configs-*")
	if err != nil {
		panic(err)
	}

	for i := 1; i <= *nClients; i++ {
		var name, configTemplate string
		if i < *nClients/2 {
			name = fmt.Sprintf("sing-box-config-%02d.json", i)
			configTemplate = singboxConfigTemplate
		} else {
			name = fmt.Sprintf("nekobox-link-%02d.txt", i)
			configTemplate = nekoboxConfigTemplate
		}
		config := fmt.Sprintf(configTemplate, myIp, *vlessDomain, userID, publicKeyHex, shortIds[i-1])
		if err := os.WriteFile(filepath.Join(dir, name), []byte(config), 0644); err != nil {
			panic(err)
		}
	}

	const readmeContent = `To run on Linux, download https://github.com/SagerNet/sing-box/releases/download/v1.3.6/sing-box-1.3.6-linux-amd64v3.tar.gz
(Sha256 is 10f0c2f12e594af112594af9e54fae0c0d79cd91d2460d09377a89176a24141f )
Run:
$ sudo sing-box run -c sing-box-config-01.json
Use any of sing-box-config-XX.json
You can use different config on different machines.

To run on Android, install APK from https://github.com/MatsuriDayo/NekoBoxForAndroid/releases
then open any of nekobox-link-XX.txt, copy the link, click (+) button and
select "Import from clipboard". Enable the tunnel by clicking pink
button in the bottom of the app.

See https://forum.qubes-os.org/t/vless-obfuscation-vpn/20438 for more info.
`
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte(readmeContent), 0644); err != nil {
		panic(err)
	}

	fmt.Printf("Configs were written to directory %s\n", dir)
	fmt.Printf("See %s/README\n", dir)
}

func installVless() {
	if err := os.Mkdir(xrayDir, 0755); os.IsExist(err) {
		panic("Remove " + xrayDir)
	} else if err != nil {
		panic(err)
	}

	privateKeyHex, publicKeyHex, userID, shortIds := generateVlessParams()
	myIp := getMyIp()
	installVlessExe()
	installVlessConfig(privateKeyHex, userID, shortIds)
	installVlessService()
	improvePerformace()
	startAndCheckVless(myIp)

	generateClientConfigs(publicKeyHex, userID, shortIds, myIp)
}

func main() {
	flag.Parse()

	if !*skipVless {
		installVless()
	}
}
