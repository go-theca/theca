//go:build unix

package session

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestListenEndpointDirErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := listenEndpoint(filepath.Join(file, "s.sock"))
	var pe *fs.PathError
	if !errors.As(err, &pe) || pe.Op != "mkdir" {
		t.Errorf("a parent that is a file: %v", err)
	}
	if os.Getuid() == 0 {
		t.Skip("root can chmod /")
	}
	// "/" exists, and is not ours to chmod.
	_, err = listenEndpoint("/theca-test.sock")
	if !errors.As(err, &pe) || pe.Op != "chmod" {
		t.Errorf("a directory we cannot chmod: %v", err)
	}
}
