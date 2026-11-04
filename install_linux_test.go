package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Exercise the installer in a disposable root with a mocked systemctl. User,
// mount and network namespaces keep the host's services and routes untouched.
func TestLinuxInstaller(t *testing.T) {
	t.Setenv("PATH", os.Getenv("PATH")+":/usr/sbin:/sbin")
	for _, tool := range []string{"unshare", "mount", "chroot", "awk"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("installer sandbox requires %s", tool)
		}
	}
	flags := []string{"--user", "--map-root-user", "--mount", "--net", "--pid", "--fork"}
	if output, err := exec.Command("unshare", append(flags, "true")...).CombinedOutput(); err != nil {
		t.Skipf("installer sandbox requires user namespaces: %v: %s", err, output)
	}
	for _, mode := range []string{"linux", "qubes", "qubes-legacy"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			work := filepath.Join(root, "work")
			if err := os.Mkdir(work, 0700); err != nil {
				t.Fatal(err)
			}
			fixture, err := os.ReadFile("testdata/install-linux.sh")
			if err != nil {
				t.Fatal(err)
			}
			for name, content := range map[string]string{
				"install-linux.sh": linuxInstaller,
				"test.sh":          string(fixture),
				"start-linux.sh":   "#!/bin/sh\n[ \"$1\" = --download-only ] || exit 99\n",
				".xray-fixture":    "#!/bin/sh\nexit 99\n",
				"xray-tun-01.json": "tun profile one", "xray-socks-01.json": "socks profile one",
				"xray-tun-02.json": "tun profile two", "xray-socks-02.json": "socks profile two",
			} {
				if err := os.WriteFile(filepath.Join(work, name), []byte(content), 0700); err != nil {
					t.Fatal(err)
				}
			}
			args := append(flags, "sh", "testdata/install-linux.sh", root, mode)
			if output, err := exec.Command("unshare", args...).CombinedOutput(); err != nil {
				t.Fatalf("installer sandbox: %v\n%s", err, output)
			}
		})
	}
}
