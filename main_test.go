package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
