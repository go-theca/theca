package tpmcounter

// End to end against a software TPM: swtpm's raw TPM 2.0 stream on a unix
// socket, reached through the real connect, with a real container on top.
// Skipped when swtpm is not installed, unless THECA_REQUIRE_SWTPM is set (CI
// sets it on Linux): a skipped test is not a pass.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-theca/theca"
)

// StartSwtpm launches a fresh swtpm and returns the "unix:" device naming it.
func startSwtpm(t *testing.T) string {
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

func TestSwtpmRollbackProtection(t *testing.T) {
	dev := startSwtpm(t)
	opts := Options{Device: dev, Auth: []byte("index secret")}
	ctr, err := Create(opts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ctr.Handle() != First {
		t.Fatalf("handle %#x, want the first free one", ctr.Handle())
	}

	f, err := os.CreateTemp("", "theca")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	pw := []byte("correct horse")
	c, _, err := theca.Create(theca.FileBacking{File: f}, theca.CreateOptions{
		Sectors: 256, Password: pw, Counter: ctr})
	if err != nil {
		t.Fatalf("theca.Create: %v", err)
	}
	if !c.Info().RollbackProtected || c.Info().CounterHandle != First {
		t.Fatalf("info %+v", c.Info())
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// The state a stolen copy of the container would have: now, before any mount.
	old, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	open := func() (*theca.Container, error) {
		return theca.Open(context.Background(), theca.FileBacking{File: f},
			theca.Unlock{Password: pw}, theca.OpenOptions{
				CounterFor: func(h uint32, name []byte) (theca.Counter, error) {
					o := opts
					o.Handle = h
					return Open(o)
				}})
	}
	// Two honest mounts: the counter moves once per mount.
	before, _ := ctr.Read()
	for i := 0; i < 2; i++ {
		c, err := open()
		if err != nil {
			t.Fatalf("mount %d: %v", i, err)
		}
		c.Close()
	}
	after, _ := ctr.Read()
	if after != before+2 {
		t.Fatalf("counter %d -> %d after two mounts", before, after)
	}
	// Put the older image back: refused, and the counter does not move.
	if _, err := f.WriteAt(old, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := open(); !errors.Is(err, theca.ErrRollback) {
		t.Fatalf("rolled-back image: %v", err)
	}
	if v, _ := ctr.Read(); v != after {
		t.Fatalf("a refused mount moved the counter: %d -> %d", after, v)
	}
	// A wrong counter authValue is refused by the TPM.
	bad := Options{Device: dev, Auth: []byte("wrong")}
	wrong, err := Open(Options{Device: dev, Handle: First, Auth: bad.Auth})
	if err != nil {
		t.Fatal(err) // reading the public area needs no authorization
	}
	if _, err := wrong.Read(); err == nil {
		t.Fatal("read with a wrong authValue")
	}
	// Undo: delete the index (owner password empty on swtpm).
	if err := ctr.Destroy(); err != nil {
		t.Fatal(err)
	}
}
