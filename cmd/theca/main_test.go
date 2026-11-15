package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/internal/format"
	"github.com/go-theca/theca/internal/kdf"
)

func TestMain(m *testing.M) {
	// Small Argon2id profiles: the production table is 2 GiB and up.
	kdf.Table = [3]kdf.Profile{{Time: 1, MemKiB: 64, Threads: 1}, {Time: 2, MemKiB: 64, Threads: 2}, {Time: 1, MemKiB: 128, Threads: 1}}
	os.Exit(m.Run())
}

type result struct {
	out, err string
	e        error
}

func run(stdin []byte, args ...string) result {
	c := RootCmd()
	var o, e bytes.Buffer
	c.SetArgs(args)
	c.SetOut(&o)
	c.SetErr(&e)
	c.SetIn(bytes.NewReader(stdin))
	err := c.Execute()
	return result{o.String(), e.String(), err}
}

// terminal replaces the terminal with canned answers, in order.
func terminal(t *testing.T, answers ...string) {
	t.Helper()
	saved := readTerminal
	t.Cleanup(func() { readTerminal = saved })
	readTerminal = func(_ *cobra.Command, _ string) ([]byte, error) {
		if len(answers) == 0 {
			return nil, errors.New("terminal closed")
		}
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
}

func secretFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// newContainer creates a 1 MiB container and returns its path, the password
// file and the recovery code.
func newContainer(t *testing.T) (dir, path, pwFile, code string) {
	t.Helper()
	dir = t.TempDir()
	pwFile = secretFile(t, dir, "pw", "correct horse\n", 0o600)
	path = filepath.Join(dir, "c.theca")
	r := run(nil, "create", path, "--size", "1M", "--password-file", pwFile)
	if r.e != nil {
		t.Fatalf("create: %v %s", r.e, r.err)
	}
	code = strings.TrimSpace(r.out)
	if _, err := format.ParseRecoveryCode(code); err != nil {
		t.Fatalf("printed code %q: %v", code, err)
	}
	if !strings.Contains(r.err, "shown once") || !strings.Contains(r.err, "no rollback counter") {
		t.Fatalf("create did not state the code's status and the missing counter: %s", r.err)
	}
	return
}

func TestRoundTrip(t *testing.T) {
	dir, path, pw, code := newContainer(t)
	data := make([]byte, 300000)
	rand.Read(data)
	r := run(data, "import", path, "--password-file", pw, "--offset", "4000")
	if r.e != nil || !strings.Contains(r.out, "300000 bytes written at 4000") {
		t.Fatalf("import: %v %q %s", r.e, r.out, r.err)
	}
	r = run(nil, "export", path, "--password-file", pw, "--offset", "4000", "--length", "300000")
	if r.e != nil || r.out != string(data) {
		t.Fatalf("export range: %v (%d bytes)", r.e, len(r.out))
	}
	r = run(nil, "export", path, "--password-file", pw)
	if r.e != nil || len(r.out) != 1<<20 || r.out[4000:304000] != string(data) {
		t.Fatalf("export all: %v (%d bytes)", r.e, len(r.out))
	}
	// The recovery code alone opens it (policy any).
	rc := secretFile(t, dir, "rc", strings.ToLower(code)+"\r\n", 0o400)
	r = run(nil, "info", path, "--recovery-file", rc)
	if r.e != nil || !strings.Contains(r.out, "size:               1048576 bytes (256 sectors)") ||
		!strings.Contains(r.out, "rollback protected: false") || !strings.Contains(r.err, "no rollback counter") {
		t.Fatalf("info: %v %q %q", r.e, r.out, r.err)
	}
	r = run(nil, "verify", path, "--password-file", pw)
	if r.e != nil || !strings.Contains(r.out, "ok: 256 sectors verified") {
		t.Fatalf("verify: %v %q", r.e, r.out)
	}
}

func TestTwoOfThreeNeedsBoth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c")
	terminal(t, "pw", "pw")
	r := run(nil, "create", path, "--size", "64K", "--policy", "2of3")
	if r.e != nil {
		t.Fatal(r.e, r.err)
	}
	rc := secretFile(t, dir, "rc", strings.TrimSpace(r.out), 0o600)
	pw := secretFile(t, dir, "pw", "pw", 0o600)
	if r := run(nil, "info", path, "--password-file", pw); !errors.Is(r.e, theca.ErrNoMatch) {
		t.Fatalf("password alone: %v", r.e)
	}
	if r := run(nil, "info", path, "--recovery-file", rc); !errors.Is(r.e, theca.ErrNoMatch) {
		t.Fatalf("recovery alone: %v", r.e)
	}
	if r := run(nil, "info", path, "--recovery-file", rc, "--password-file", pw); r.e != nil {
		t.Fatalf("both: %v", r.e)
	}
	// Recovery file plus the password from the terminal is not offered:
	// with --recovery-file and no --password-file, only the code is used.
}

func TestCreateRefusals(t *testing.T) {
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "x", 0o600)
	for name, args := range map[string][]string{
		"no size":       {"create", filepath.Join(dir, "a"), "--password-file", pw},
		"zero":          {"create", filepath.Join(dir, "a"), "--size", "0", "--password-file", pw},
		"unaligned":     {"create", filepath.Join(dir, "a"), "--size", "5000", "--password-file", pw},
		"not a number":  {"create", filepath.Join(dir, "a"), "--size", "lots", "--password-file", pw},
		"overflow":      {"create", filepath.Join(dir, "a"), "--size", "99999999999T", "--password-file", pw},
		"policy":        {"create", filepath.Join(dir, "a"), "--size", "64K", "--policy", "3of5", "--password-file", pw},
		"no file":       {"create", filepath.Join(dir, "a"), "--size", "64K", "--password-file", filepath.Join(dir, "none")},
		"existing file": {"create", pw, "--size", "64K", "--password-file", pw},
		"no directory":  {"create", filepath.Join(dir, "x", "y"), "--size", "64K", "--password-file", pw},
		"bad journal":   {"create", filepath.Join(dir, "a"), "--size", "64K", "--journal", "4000000000", "--password-file", pw},
		"no arg":        {"create", "--size", "64K"},
	} {
		if r := run(nil, args...); r.e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A failed Create leaves no file behind.
	if _, err := os.Stat(filepath.Join(dir, "a")); !os.IsNotExist(err) {
		t.Fatalf("partial container left: %v", err)
	}
	// Terminal: the two entries must match, and a closed terminal is an error.
	terminal(t, "one", "two")
	if r := run(nil, "create", filepath.Join(dir, "b"), "--size", "64K"); r.e == nil || !strings.Contains(r.e.Error(), "differ") {
		t.Fatalf("mismatch: %v", r.e)
	}
	terminal(t, "one")
	if r := run(nil, "create", filepath.Join(dir, "b"), "--size", "64K"); r.e == nil {
		t.Fatal("closed terminal at the second prompt")
	}
	terminal(t)
	if r := run(nil, "create", filepath.Join(dir, "b"), "--size", "64K"); r.e == nil {
		t.Fatal("closed terminal at the first prompt")
	}
}

func TestSecretFiles(t *testing.T) {
	dir := t.TempDir()
	for name, mode := range map[string]os.FileMode{"group": 0o640, "others": 0o604, "group write": 0o620} {
		p := secretFile(t, dir, name, "x", mode)
		if _, err := readSecretFile(p); err == nil || !strings.Contains(err.Error(), "group or others") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := readSecretFile(dir); err == nil {
		t.Error("a directory was read as a secret")
	}
	long := secretFile(t, dir, "long", strings.Repeat("x", maxSecretFile+1), 0o600)
	if _, err := readSecretFile(long); err == nil {
		t.Error("oversized secret file accepted")
	}
	exact := secretFile(t, dir, "exact", strings.Repeat("x", maxSecretFile), 0o600)
	if b, err := readSecretFile(exact); err != nil || len(b) != maxSecretFile {
		t.Errorf("secret of exactly the limit: %d %v", len(b), err)
	}
	for in, want := range map[string]string{"a\n": "a", "a\r\n": "a", "a": "a", "\n": "", "": "", "a\n\n": "a\n"} {
		p := secretFile(t, dir, "nl", in, 0o600)
		if b, err := readSecretFile(p); err != nil || string(b) != want {
			t.Errorf("%q: got %q %v", in, b, err)
		}
	}
}

func TestOpenRefusals(t *testing.T) {
	dir, path, pw, _ := newContainer(t)
	wrong := secretFile(t, dir, "wrong", "nope", 0o600)
	missing := filepath.Join(dir, "missing")
	for _, sub := range []string{"info", "verify", "export"} {
		if r := run(nil, sub, missing, "--password-file", pw); !os.IsNotExist(r.e) {
			t.Errorf("%s missing container: %v", sub, r.e)
		}
		if r := run(nil, sub, path, "--password-file", wrong); !errors.Is(r.e, theca.ErrNoMatch) {
			t.Errorf("%s wrong password: %v", sub, r.e)
		}
		if r := run(nil, sub, path, "--password-file", missing); !os.IsNotExist(r.e) {
			t.Errorf("%s missing password file: %v", sub, r.e)
		}
		if r := run(nil, sub, path, "--recovery-file", missing); !os.IsNotExist(r.e) {
			t.Errorf("%s missing recovery file: %v", sub, r.e)
		}
	}
	if r := run(nil, "import", missing, "--password-file", pw); !os.IsNotExist(r.e) {
		t.Errorf("import missing container: %v", r.e)
	}
	// import reads data from stdin, so it never prompts.
	if r := run([]byte("x"), "import", path); r.e == nil || !strings.Contains(r.e.Error(), "standard input") {
		t.Errorf("import without a secret file: %v", r.e)
	}
	// The password from the terminal.
	terminal(t, "correct horse")
	if r := run(nil, "info", path); r.e != nil {
		t.Errorf("terminal password: %v", r.e)
	}
}

func TestRanges(t *testing.T) {
	_, path, pw, _ := newContainer(t)
	for _, a := range [][]string{
		{"--offset", "-1"}, {"--offset", "1048577"}, {"--length", "1048577"}, {"--offset", "10", "--length", "1048570"}, {"--length", "-5"},
	} {
		if r := run(nil, append([]string{"export", path, "--password-file", pw}, a...)...); !errors.Is(r.e, theca.ErrRange) {
			t.Errorf("export %v: %v", a, r.e)
		}
	}
	if r := run(nil, "export", path, "--password-file", pw, "--offset", "1048576"); r.e != nil || r.out != "" {
		t.Errorf("empty export at the end: %v %d", r.e, len(r.out))
	}
	for _, off := range []string{"-1", "1048577"} {
		if r := run([]byte("x"), "import", path, "--password-file", pw, "--offset", off); !errors.Is(r.e, theca.ErrRange) {
			t.Errorf("import at %s: %v", off, r.e)
		}
	}
	// Input past the end is refused; what fitted before the refusal stays.
	if r := run(make([]byte, 10), "import", path, "--password-file", pw, "--offset", "1048570"); !errors.Is(r.e, theca.ErrRange) {
		t.Errorf("import past the end: %v", r.e)
	}
	if r := run(bytes.Repeat([]byte{7}, 6), "import", path, "--password-file", pw, "--offset", "1048570"); r.e != nil {
		t.Errorf("import up to the end: %v", r.e)
	}
	r := run(nil, "export", path, "--password-file", pw, "--offset", "1048570")
	if r.e != nil || r.out != strings.Repeat("\x07", 6) {
		t.Errorf("tail: %v %q", r.e, r.out)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	_, path, pw, _ := newContainer(t)
	if r := run(bytes.Repeat([]byte{1}, 8192), "import", path, "--password-file", pw); r.e != nil {
		t.Fatal(r.e)
	}
	geo, err := format.NewGeometry(256, theca.DefaultJournalEntries)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	f.ReadAt(b, int64(geo.DataOff+100))
	b[0] ^= 1
	f.WriteAt(b, int64(geo.DataOff+100))
	f.Close()
	if r := run(nil, "verify", path, "--password-file", pw); !errors.Is(r.e, theca.ErrSector) {
		t.Fatalf("tampered sector: %v", r.e)
	}
	if r := run(nil, "export", path, "--password-file", pw, "--length", "8192"); !errors.Is(r.e, theca.ErrSector) {
		t.Fatalf("export of a tampered sector: %v", r.e)
	}
}

func TestCloseBoth(t *testing.T) {
	_, path, pw, _ := newContainer(t)
	s := &secrets{passwordFile: pw}
	cmd := RootCmd()
	c, f, err := open(cmd, path, s, false)
	if err != nil {
		t.Fatal(err)
	}
	f.Close() // a second Close fails
	if err := closeBoth(c, f, nil); err == nil {
		t.Fatal("file close error swallowed")
	}
	c2, f2, err := open(cmd, path, s, false)
	if err != nil {
		t.Fatal(err)
	}
	c2.Close() // a second Close fails
	if err := closeBoth(c2, f2, nil); !errors.Is(err, theca.ErrClosed) {
		t.Fatalf("container close error: %v", err)
	}
	first := errors.New("first")
	c3, f3, _ := open(cmd, path, s, false)
	if err := closeBoth(c3, f3, first); err != first {
		t.Fatalf("the first error must win: %v", err)
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]uint64{"4096": 4096, "4k": 4096, "1M": 1 << 20, " 2G ": 2 << 30, "1T": 1 << 40} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
}

func TestTerminalReader(t *testing.T) {
	savedIs, savedRead := isTerminal, readPassword
	defer func() { isTerminal, readPassword = savedIs, savedRead }()
	isTerminal = func(int) bool { return false }
	if _, err := readTerminal(RootCmd(), "x"); err == nil || !strings.Contains(err.Error(), "--password-file") {
		t.Fatalf("no terminal: %v", err)
	}
	isTerminal = func(int) bool { return true }
	readPassword = func(int) ([]byte, error) { return []byte("s3cret"), nil }
	cmd := RootCmd()
	var e bytes.Buffer
	cmd.SetErr(&e)
	b, err := readTerminal(cmd, "Password: ")
	if err != nil || string(b) != "s3cret" || e.String() != "Password: \n" {
		t.Fatalf("%q %v, stderr %q", b, err, e.String())
	}
	if strings.Contains(e.String(), "s3cret") {
		t.Fatal("the secret was echoed")
	}
}

func TestMainExitStatus(t *testing.T) {
	saved, args := osExit, os.Args
	defer func() { osExit, os.Args = saved, args }()
	code := -1
	osExit = func(c int) { code = c }
	os.Args = []string{"theca", "no-such-command"}
	main()
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	// A library error, which already names theca, is not prefixed twice.
	saved2 := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	code = -1
	dir, path, _, _ := newContainer(t)
	wrong := secretFile(t, dir, "wrong", "nope", 0o600)
	os.Args = []string{"theca", "info", path, "--password-file", wrong}
	main()
	w.Close()
	os.Stderr = saved2
	var e bytes.Buffer
	e.ReadFrom(r)
	if code != 1 || strings.Count(e.String(), "theca:") != 1 {
		t.Fatalf("exit %d, stderr %q", code, e.String())
	}
	code = -1
	os.Args = []string{"theca", "--help"}
	main()
	if code != -1 {
		t.Fatalf("help exited %d", code)
	}
}
