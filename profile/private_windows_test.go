//go:build windows

package profile

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A profile file made in the user's own temp directory inherits that directory's
// DACL (the user, the system, the administrators) and loads; once Everyone has
// read access, it is refused.
func TestLoadChecksTheDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "containers.toml")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Store{Path: path}).Load(); err != nil {
		t.Fatalf("a private file: %v", err)
	}
	if out, err := exec.Command("icacls", path, "/grant", "*S-1-1-0:R").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
	}
	_, err := (Store{Path: path}).Load()
	if err == nil || !strings.Contains(err.Error(), "S-1-1-0") {
		t.Fatalf("a file Everyone can read: %v", err)
	}
}
