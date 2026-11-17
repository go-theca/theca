package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// startSwtpmDevice launches a fresh software TPM and returns the --tpm-device
// naming it. Skipped when swtpm is not installed, unless THECA_REQUIRE_SWTPM is
// set (CI sets it): a skipped test is not a pass.
func startSwtpmDevice(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("swtpm")
	if err != nil {
		if os.Getenv("THECA_REQUIRE_SWTPM") != "" {
			t.Fatal("swtpm not installed and THECA_REQUIRE_SWTPM is set")
		}
		t.Skip("swtpm not installed")
	}
	dir, err := os.MkdirTemp("", "sw") // short: unix socket paths are limited to ~100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "d")
	cmd := exec.Command(bin, "socket", "--tpm2", "--tpmstate", "dir="+state,
		"--server", "type=unixio,path="+sock, "--ctrl", "type=unixio,path="+filepath.Join(dir, "c"),
		"--flags", "not-need-init,startup-clear", "--log", "level=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(sock); err == nil {
			return "unix:" + sock
		}
	}
	t.Fatal("swtpm did not create its socket")
	return ""
}
