package profile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func good() Profile {
	p := New("bio", "/vault/bio.theca")
	p.PasswordFrom = "keepassxc:https://theca.invalid/bio"
	p.Device = "bio"
	p.Counter = "tpm"
	p.TPMDevice = "unix:/run/swtpm.sock"
	p.RecoveryFrom = "keychain:theca/rec"
	p.PINFrom = "secretservice:theca/pin"
	p.Hint = 1
	p.FIDO2 = true
	p.Share = "mine"
	p.Sync = 7 * time.Second
	p.CloseOnLock = false
	return p
}

func TestRoundTrip(t *testing.T) {
	in := map[string]Profile{"bio": good(), "plain": New("plain", "/x.theca")}
	out, err := Parse(Marshal(in))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("got %+v want %+v", out, in)
	}
	if !good().UsesKey() || New("a", "/a").UsesKey() {
		t.Fatal("UsesKey")
	}
	q := New("q", "/a\"b\\c")
	if o, err := Parse(Marshal(map[string]Profile{"q": q})); err != nil || o["q"].File != q.File {
		t.Fatalf("quote: %v %q", err, o["q"].File)
	}
}

func TestValidate(t *testing.T) {
	long := strings.Repeat("a", 2000)
	cases := map[string]func(*Profile){
		"name":      func(p *Profile) { p.Name = "a/b" },
		"relative":  func(p *Profile) { p.File = "x.theca" },
		"longfile":  func(p *Profile) { p.File = "/" + long },
		"control":   func(p *Profile) { p.Device = "a\x01" },
		"utf8":      func(p *Profile) { p.Device = "\xff" },
		"badref":    func(p *Profile) { p.PasswordFrom = "nonsense" },
		"fileref":   func(p *Profile) { p.PasswordFrom = "file:/x" },
		"hint":      func(p *Profile) { p.Hint = 3 },
		"counter":   func(p *Profile) { p.Counter = "usb" },
		"tpmdev":    func(p *Profile) { p.Counter = ""; p.TPMDevice = "/dev/x" },
		"share":     func(p *Profile) { p.Share = "" },
		"sync":      func(p *Profile) { p.Sync = 0 },
		"synclarge": func(p *Profile) { p.Sync = 2 * time.Hour },
	}
	for n, mut := range cases {
		p := good()
		p.Counter, p.TPMDevice = "tpm", "unix:/s"
		mut(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", n)
		}
	}
	if err := good().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"", strings.Repeat("a", 65), ".a", "a b", "é"} {
		if ValidName(n) == nil {
			t.Errorf("name %q accepted", n)
		}
	}
	if ValidName("a.b-C_9") != nil {
		t.Fatal("good name refused")
	}
	if clip(long) == long {
		t.Fatal("clip")
	}
}

func TestParseRefusals(t *testing.T) {
	long := strings.Repeat("a", MaxLineBytes+1)
	bad := []string{
		"file = \"/x\"\n",
		"[a\nfile=\"/x\"\n",
		"[a/b]\nfile=\"/x\"\n",
		"[a]\nfile=\"/x\"\n[a]\nfile=\"/y\"\n",
		"[a]\nfile \"/x\"\n",
		"[a]\n= \"/x\"\n",
		"[a]\nfile=\"/x\"\nfile=\"/y\"\n",
		"[a]\nfile=\"/x\"\nbogus=\"1\"\n",
		"[a]\nfile=\"/x\"\nfido2=\"yes\"\n",
		"[a]\nfile=7\n",
		"[a]\nhint=\"1\"\nfile=\"/x\"\n",
		"[a]\nhint=99999999999\nfile=\"/x\"\n",
		"[a]\nfile=\"/x\" junk\n",
		"[a]\nfile=\"/x\nz\n",
		"[a]\nfile=\"\\q\"\n",
		"[a]\nfile=\"x\\",
		"[a]\nfile=\"/x\"\nsync=5\n",
		"[a]\nfile=\"/x\"\nsync=\"soon\"\n",
		"[a]\nfile=\"/x\"\ncounter=\"usb\"\n",
		"[a]\nfile=maybe\n",
		"[a]\n#c\nfile=\"" + long + "\"\n",
		"\xff",
	}
	for _, s := range bad {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("accepted %q", clip(s))
		}
	}
	if _, err := Parse(make([]byte, MaxFileBytes+1)); err == nil {
		t.Error("big file accepted")
	}
	var sb strings.Builder
	for i := 0; i <= MaxProfiles; i++ {
		sb.WriteString("[p" + strings.Repeat("a", i%5) + string(rune('a'+i/26)) + string(rune('a'+i%26)) + "]\nfile=\"/x\"\n")
	}
	if _, err := Parse([]byte(sb.String())); err == nil {
		t.Error("too many profiles accepted")
	}
}

func TestParseTolerates(t *testing.T) {
	src := "# c\r\n\r\n[a]\r\nfile = \"/x\" # where\r\nfido2 = true # yes\r\nhint = 2 # two\r\nclose-on-lock = false\r\nsync = \"1s\"\r\n"
	ps, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	a := ps["a"]
	if a.File != "/x" || !a.FIDO2 || a.Hint != 2 || a.CloseOnLock || a.Sync != time.Second {
		t.Fatalf("%+v", a)
	}
	if _, err := Parse([]byte("[a]\nfile=\"/x\"\nfido2 = false\nshare=\"s\"\ndevice=\"d\"\ntpm-device=\"\"\nrecovery-from=\"keychain:a/b\"\n")); err != nil {
		t.Fatal(err)
	}
}

func TestStore(t *testing.T) {
	dir := t.TempDir()
	s := Store{Path: filepath.Join(dir, "sub", "containers.toml")}
	if ps, err := s.Load(); err != nil || len(ps) != 0 {
		t.Fatalf("missing: %v %v", ps, err)
	}
	if _, err := s.Get("x"); err == nil {
		t.Fatal("Get on empty")
	}
	if err := s.Remove("x"); err == nil {
		t.Fatal("Remove on empty")
	}
	if err := s.Add(New("bad name", "/x"), false); err == nil {
		t.Fatal("invalid added")
	}
	if err := s.Add(good(), false); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(good(), false); err == nil {
		t.Fatal("duplicate added")
	}
	if err := s.Add(good(), true); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(New("alpha", "/a"), false); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(s.Path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if d, _ := os.Stat(filepath.Dir(s.Path)); d.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", d.Mode().Perm())
	}
	l, err := s.List()
	if err != nil || len(l) != 2 || l[0].Name != "alpha" {
		t.Fatalf("%v %v", l, err)
	}
	if p, err := s.Get("bio"); err != nil || p.Device != "bio" {
		t.Fatal(p, err)
	}
	if err := s.Remove("alpha"); err != nil {
		t.Fatal(err)
	}
	// Refusals on the file itself.
	os.Chmod(s.Path, 0o644)
	if _, err := s.Load(); err == nil {
		t.Fatal("world-readable file accepted")
	}
	if _, err := s.List(); err == nil {
		t.Fatal("List on bad mode")
	}
	if _, err := s.Get("bio"); err == nil {
		t.Fatal("Get on bad mode")
	}
	if err := s.Add(New("z", "/z"), false); err == nil {
		t.Fatal("Add on bad mode")
	}
	if err := s.Remove("bio"); err == nil {
		t.Fatal("Remove on bad mode")
	}
	os.Chmod(s.Path, 0o600)
	os.WriteFile(s.Path, []byte("garbage"), 0o600)
	if _, err := s.Load(); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := (Store{Path: dir}).Load(); err == nil {
		t.Fatal("directory accepted")
	}
	big := filepath.Join(dir, "big.toml")
	os.WriteFile(big, make([]byte, MaxFileBytes+1), 0o600)
	if _, err := (Store{Path: big}).Load(); err == nil {
		t.Fatal("big file accepted")
	}
	if _, err := (Store{Path: filepath.Join(big, "x")}).Load(); err == nil {
		t.Fatal("ENOTDIR accepted")
	}
}

func TestStoreLimitsAndSaveErrors(t *testing.T) {
	dir := t.TempDir()
	s := Store{Path: filepath.Join(dir, "c.toml")}
	ps := map[string]Profile{}
	for i := 0; i < MaxProfiles; i++ {
		n := "p" + string(rune('a'+i/26)) + string(rune('a'+i%26))
		ps[n] = New(n, "/x")
	}
	if err := s.Save(ps); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(New("overflow", "/x"), false); err == nil {
		t.Fatal("257th accepted")
	}
	// Directory is a file: MkdirAll fails.
	if err := (Store{Path: filepath.Join(s.Path, "x", "y")}).Save(ps); err == nil {
		t.Fatal("save under a file")
	}
	// Read-only directory: CreateTemp fails.
	ro := filepath.Join(dir, "ro")
	os.Mkdir(ro, 0o500)
	if os.Getuid() != 0 {
		if err := (Store{Path: filepath.Join(ro, "c.toml")}).Save(ps); err == nil {
			t.Fatal("save into read-only dir")
		}
	}
	// Destination is a directory: Rename fails.
	dd := filepath.Join(dir, "dd")
	os.MkdirAll(filepath.Join(dd, "inner"), 0o700)
	if err := (Store{Path: dd}).Save(ps); err == nil {
		t.Fatal("rename onto a directory")
	}
}

func TestDefaultPath(t *testing.T) {
	old := userConfigDir
	defer func() { userConfigDir = old }()
	userConfigDir = func() (string, error) { return "/cfg", nil }
	if p, err := DefaultPath(); err != nil || p != "/cfg/theca/containers.toml" {
		t.Fatal(p, err)
	}
	userConfigDir = func() (string, error) { return "", os.ErrNotExist }
	if _, err := DefaultPath(); err == nil {
		t.Fatal("error lost")
	}
}

func TestIOSeams(t *testing.T) {
	dir := t.TempDir()
	s := Store{Path: filepath.Join(dir, "c.toml")}
	if err := s.Save(map[string]Profile{"a": New("a", "/x")}); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	oldS, oldR, oldW := statFile, readAll, writeTmp
	defer func() { statFile, readAll, writeTmp = oldS, oldR, oldW }()
	statFile = func(*os.File) (os.FileInfo, error) { return nil, boom }
	if _, err := s.Load(); !errors.Is(err, boom) {
		t.Fatal("stat error lost", err)
	}
	statFile = oldS
	readAll = func(io.Reader) ([]byte, error) { return nil, boom }
	if _, err := s.Load(); !errors.Is(err, boom) {
		t.Fatal("read error lost", err)
	}
	readAll = oldR
	writeTmp = func(*os.File, []byte) error { return boom }
	if err := s.Save(nil); !errors.Is(err, boom) {
		t.Fatal("write error lost", err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".containers-*")); len(m) != 0 {
		t.Fatalf("temp file left: %v", m)
	}
}

func TestQuoteEscapes(t *testing.T) {
	s := "a\"b\\c\nd\te"
	got, rest, err := unquote(quote(s) + " #x")
	if err != nil || got != s || rest != " #x" {
		t.Fatalf("%q %q %v", got, rest, err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(Marshal(map[string]Profile{"bio": good()}))
	f.Add([]byte("[a]\nfile=\"/x\"\n"))
	f.Add([]byte("[a]\nfile=\"\\"))
	f.Add([]byte("file=1\n[\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ps, err := Parse(b)
		if err != nil {
			return
		}
		// Whatever parses is valid, and survives a round trip.
		for _, p := range ps {
			if err := p.Validate(); err != nil {
				t.Fatalf("parsed an invalid profile: %v", err)
			}
		}
		again, err := Parse(Marshal(ps))
		if err != nil || !reflect.DeepEqual(ps, again) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
