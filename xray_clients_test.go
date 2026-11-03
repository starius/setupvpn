package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGeneratedClients(t *testing.T) {
	_, pub, id, shortIDs := generateVlessParams()
	_, verify := generateMLDSAKeys()
	files := generateVlessClientConfigs(pub, verify, id, shortIDs[:1], "2001:db8::1")
	for _, f := range files {
		if strings.HasSuffix(f.name, ".json") {
			var config object
			if err := json.Unmarshal(f.content, &config); err != nil {
				t.Fatal(err)
			}
			out := config["outbounds"].([]any)[0].(map[string]any)
			reality := out["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
			if reality["mldsa65Verify"] != verify || reality["password"] != pub {
				t.Fatal("client keys do not match")
			}
			if strings.Contains(string(f.content), "mldsa65Seed") {
				t.Fatal("private seed leaked to client")
			}
		}
		if strings.HasSuffix(f.name, ".txt") {
			u, err := url.Parse(strings.TrimSpace(string(f.content)))
			if err != nil {
				t.Fatal(err)
			}
			if u.Hostname() != "2001:db8::1" || u.Port() != "443" || u.User.Username() != id {
				t.Fatal("invalid share-link address or user")
			}
			q := u.Query()
			if q.Get("pqv") != verify || q.Get("pbk") != pub || q.Get("sid") != shortIDs[0] || q.Get("fp") != "chrome" {
				t.Fatal("share link lost authentication parameters")
			}
		}
		if strings.HasSuffix(f.name, ".sh") {
			if strings.Contains(string(f.content), "@VERSION@") || strings.Contains(string(f.content), "@AMD64") {
				t.Fatal("unexpanded launcher placeholders")
			}
			cmd := exec.Command("sh", "-n")
			cmd.Stdin = strings.NewReader(string(f.content))
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s: %v: %s", f.name, err, output)
			}
		}
	}
}

func writeTestConfig(t *testing.T, config any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, jsonBytes(config), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func unusedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startTestXray(t *testing.T, binary string, config object, port int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	config["log"] = object{"loglevel": "debug"}
	cmd := exec.CommandContext(ctx, binary, "run", "-config", writeTestConfig(t, config))
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	// Logs can contain REALITY authentication secrets. Keep them out of test output.
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		cmd.Wait()
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	for i := 0; i < 100; i++ {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("Xray listener did not start")
}

// This integration test uses only loopback SOCKS listeners, never TUN or routes.
// It verifies actual hybrid REALITY handshakes and rejection of a wrong ML-DSA key.
func TestXrayHandshake(t *testing.T) {
	binary := os.Getenv("XRAY_BIN")
	if binary == "" {
		t.Skip("set XRAY_BIN to the pinned Xray binary")
	}
	oldDomain := *vlessDomain
	*vlessDomain = "localhost"
	t.Cleanup(func() { *vlessDomain = oldDomain })
	private, public, id, shorts := generateVlessParams()
	seed, verify := generateMLDSAKeys()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: make([]byte, 4000)}},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	target.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	target.StartTLS()
	defer target.Close()

	var server object
	if err := json.Unmarshal([]byte(generateVlessConfig(private, id, shorts, seed)), &server); err != nil {
		t.Fatal(err)
	}
	// Recent Xray releases block private destinations by default. This exception
	// is only for the loopback test HTTP server, never for generated configs.
	server["outbounds"].([]any)[0].(map[string]any)["settings"] = object{"finalRules": []object{{"action": "allow", "ip": []string{"127.0.0.1"}}}}
	serverPort := unusedPort(t)
	inbound := server["inbounds"].([]any)[0].(map[string]any)
	inbound["listen"], inbound["port"] = "127.0.0.1", serverPort
	inbound["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)["dest"] = target.Listener.Addr().String()
	startTestXray(t, binary, server, serverPort)
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "tunneled successfully") }))
	defer echo.Close()
	for _, wrong := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrong-key=%t", wrong), func(t *testing.T) {
			clientVerify := verify
			if wrong {
				_, clientVerify = generateMLDSAKeys()
			}
			config := xrayClientConfig(public, clientVerify, id, shorts[0], "127.0.0.1", false)
			clientPort := unusedPort(t)
			config["inbounds"].([]object)[0]["port"] = clientPort
			config["outbounds"].([]object)[0]["settings"].(object)["vnext"].([]object)[0]["port"] = serverPort
			startTestXray(t, binary, config, clientPort)
			proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", clientPort))
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			res, err := httpClient.Get(echo.URL)
			if err != nil {
				if wrong {
					return
				}
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if wrong {
				t.Fatal("connection accepted a wrong ML-DSA verification key")
			}
			if err != nil || string(body) != "tunneled successfully" {
				t.Fatalf("unexpected tunneled response: %q, %v", body, err)
			}
		})
	}
	for _, f := range generateVlessClientConfigs(public, verify, id, shorts[:1], "127.0.0.1") {
		if !strings.HasSuffix(f.name, ".json") {
			continue
		}
		path := filepath.Join(t.TempDir(), f.name)
		if err := os.WriteFile(path, f.content, 0600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "run", "-test", "-config", path).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", f.name, err, output)
		}
	}
}
