package main

import (
	"os"
	"path/filepath"
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
