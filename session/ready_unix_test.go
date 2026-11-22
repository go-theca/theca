//go:build unix

package session

import (
	"os"
	"os/exec"
	"testing"
)

func TestReadyFileUnix(t *testing.T) {
	if f := ReadyFile(); f == nil || f.Name() != "ready" {
		t.Errorf("ReadyFile = %v", f)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	c := exec.Command("true")
	if err := inheritReady(c, w); err != nil || len(c.ExtraFiles) != 1 || c.ExtraFiles[0] != w {
		t.Errorf("inheritReady: %v %v", err, c.ExtraFiles)
	}
}
