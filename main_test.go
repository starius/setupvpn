package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWritePerformanceConfig(t *testing.T) {
	const original = "net.ipv4.ip_forward=1\n"
	const settings = "\nnet.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n"
	for _, tc := range []struct {
		name      string
		hasDir    bool
		hasLegacy bool
	}{
		{"drop-in without legacy file", true, false},
		{"drop-in preserves legacy file", true, true},
		{"append to legacy file", false, true},
		{"create missing legacy file", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "sysctl.d")
			legacy := filepath.Join(root, "sysctl.conf")
			if tc.hasDir {
				if err := os.Mkdir(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.hasLegacy {
				if err := os.WriteFile(legacy, []byte(original), 0644); err != nil {
					t.Fatal(err)
				}
			}
			path, err := writePerformanceConfig(dir, legacy)
			if err != nil {
				t.Fatal(err)
			}
			wantPath, wantContent := legacy, settings
			if tc.hasDir {
				wantPath = filepath.Join(dir, "99-setupvpn.conf")
				// Re-running must replace the managed file without duplicating settings.
				if _, err := writePerformanceConfig(dir, legacy); err != nil {
					t.Fatal(err)
				}
				content, err := os.ReadFile(legacy)
				if tc.hasLegacy {
					if err != nil || string(content) != original {
						t.Fatalf("legacy file changed: %q, %v", content, err)
					}
				} else if !os.IsNotExist(err) {
					t.Fatalf("legacy file should remain absent: %v", err)
				}
			} else if tc.hasLegacy {
				wantContent = original + settings
			}
			if path != wantPath {
				t.Fatalf("config path = %q, want %q", path, wantPath)
			}
			content, err := os.ReadFile(path)
			if err != nil || string(content) != wantContent {
				t.Fatalf("config content = %q, %v; want %q", content, err, wantContent)
			}
		})
	}
}

// Run with XRAY_BIN and SING_BOX_BIN pointing to the pinned release binaries.
// Their validation commands do not install services or change network settings.
func TestVlessConfigCompatibility(t *testing.T) {
	privateKey, publicKey, userID, shortIDs := generateVlessParams()
	t.Run("xray", func(t *testing.T) {
		binary := os.Getenv("XRAY_BIN")
		if binary == "" {
			t.Skip("set XRAY_BIN to validate the server config")
		}
		config := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(config, []byte(generateVlessConfig(privateKey, userID, shortIDs)), 0600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "run", "-test", "-config", config).CombinedOutput(); err != nil {
			t.Fatalf("Xray rejected the generated config: %v\n%s", err, output)
		}
	})
	t.Run("sing-box", func(t *testing.T) {
		binary := os.Getenv("SING_BOX_BIN")
		if binary == "" {
			t.Skip("set SING_BOX_BIN to validate the client configs")
		}
		checked := 0
		for _, f := range generateVlessClientConfigs(publicKey, userID, shortIDs, "192.0.2.1") {
			if !strings.HasSuffix(f.name, ".json") {
				continue
			}
			config := filepath.Join(t.TempDir(), f.name)
			if err := os.WriteFile(config, f.content, 0600); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command(binary, "check", "-c", config).CombinedOutput(); err != nil {
				t.Fatalf("sing-box rejected %s: %v\n%s", f.name, err, output)
			}
			checked++
		}
		if checked == 0 {
			t.Fatal("no sing-box configs were generated")
		}
	})
}
