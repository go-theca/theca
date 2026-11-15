package main

import (
	"os"
	"path/filepath"
	"testing"
)

func profile(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "c.out")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRun(t *testing.T) {
	devnull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	defer devnull.Close()
	cases := []struct {
		name, body string
		want       int
		err        bool
	}{
		{"covered", "mode: set\na/b.go:1.1,2.2 3 1\n", 0, false},
		{"gap", "mode: set\na/b.go:1.1,2.2 3 0\na/b.go:3.1,4.2 2 1\n", 3, false},
		{"tools ignored", "mode: set\nx/internal/tools/t/main.go:1.1,2.2 9 0\n", 0, false},
		{"bad fields", "mode: set\njunk\n", 0, true},
		{"bad numbers", "mode: set\na.go:1.1,2.2 x y\n", 0, true},
	}
	for _, c := range cases {
		got, err := run(profile(t, c.body), devnull)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("%s: got %d, %v", c.name, got, err)
		}
	}
	if _, err := run(filepath.Join(t.TempDir(), "missing"), devnull); err == nil {
		t.Error("missing file accepted")
	}
}
