package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-theca/theca"
)

// anyContainer is a policy-any container (the password alone, and the recovery
// code alone, each open it) with a fake key attached.
func anyContainer(t *testing.T) (path, pw, rc, pin string, k *cliKey) {
	t.Helper()
	dir, path, pw, code := newContainer(t)
	rc = secretFile(t, dir, "rc", code, 0o600)
	pin = secretFile(t, dir, "pin", "123456\n", 0o600)
	k = &cliKey{}
	withKey(t, k, nil)
	return path, pw, rc, pin, k
}

func opensWith(path string, args ...string) bool {
	return run(nil, append([]string{"verify", path}, args...)...).e == nil
}

// hintOf is what enroll-key says after the pairing: the notes, without the
// deprecation warnings the test's own -file inputs print first.
func hintOf(stderr string) string {
	_, hint, _ := strings.Cut(stderr, "\nnote:")
	return hint
}

func TestEnrollKeyNamesWhatStillOpens(t *testing.T) {
	path, pw, rc, pin, _ := anyContainer(t)
	// Only the password presented: it still opens alone; the recovery code was
	// not looked at, and the output says so.
	r := run(nil, "enroll-key", path, "--password-file", pw, "--pin-file", pin)
	want := "theca slots remove " + path + " --remove password --keep password+fido2 --password-from REF"
	if r.e != nil || !strings.Contains(r.err, "(REF is keychain:SERVICE/ACCOUNT, secretservice:SERVICE/ACCOUNT or keepassxc:URL)") || strings.Contains(hintOf(r.err), "-file") ||
		!strings.Contains(r.err, "the password alone still opens this container") || !strings.Contains(r.err, want) ||
		!strings.Contains(r.err, "recovery code was not presented") || !strings.Contains(r.out, "paired with 1 factor(s)") {
		t.Fatalf("%v out=%q err=%q", r.e, r.out, r.err)
	}
	// Both presented, a key chosen: both still open alone, each with its command.
	r = run(nil, "enroll-key", path, "--password-file", pw, "--recovery-file", rc, "--pin-file", pin, "--device", "iokit:1")
	if r.e != nil || !strings.Contains(r.err, "the password alone still opens") || !strings.Contains(r.err, "the recovery code alone still opens") ||
		!strings.Contains(r.err, "--remove recovery --keep password+fido2 --password-from REF --recovery-from REF --device iokit:1") || strings.Contains(hintOf(r.err), "-file") {
		t.Fatalf("%v err=%q", r.e, r.err)
	}
	// The command it printed works.
	r = run(nil, "slots", "remove", path, "--remove", "password", "--keep", "password+fido2", "--password-file", pw, "--pin-file", pin)
	if r.e != nil || !strings.Contains(r.out, "removed 1 slot(s) opened by the password; the password+fido2 still opens it") {
		t.Fatalf("%v %q", r.e, r.out)
	}
}

func TestEnrollKeyUnderTwoOfThreeSaysNothingStillOpens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c")
	pw := secretFile(t, dir, "pw", "correct horse", 0o600)
	r := run(nil, "create", path, "--size", "64K", "--policy", "2of3", "--password-file", pw)
	rc := secretFile(t, dir, "rc", strings.TrimSpace(r.out), 0o600)
	pin := secretFile(t, dir, "pin", "123456\n", 0o600)
	k := &cliKey{}
	withKey(t, k, nil)
	r = run(nil, "enroll-key", path, "--password-file", pw, "--recovery-file", rc, "--pin-file", pin)
	if r.e != nil || strings.Contains(r.err, "alone still opens") || strings.Contains(r.err, "not presented") {
		t.Fatalf("%v err=%q", r.e, r.err)
	}
	// --require finds nothing to remove: the key was required already, and no
	// proof (no third touch) is asked.
	k.pins = nil
	r = run(nil, "enroll-key", path, "--password-file", pw, "--recovery-file", rc, "--pin-file", pin, "--require")
	if r.e != nil || !strings.Contains(r.out, "the password alone did not open this container already") || len(k.pins) != 1 {
		t.Fatalf("%v out=%q pins=%d", r.e, r.out, len(k.pins))
	}
}

func TestEnrollKeyRequireMakesTheKeyMandatory(t *testing.T) {
	path, pw, rc, pin, k := anyContainer(t)
	r := run(nil, "enroll-key", path, "--password-file", pw, "--recovery-file", rc, "--pin-file", pin, "--require")
	if r.e != nil || !strings.Contains(r.out, "ok: removed 1 password-only slot(s)") || !strings.Contains(r.err, "Touch the security key once more") {
		t.Fatalf("%v out=%q err=%q", r.e, r.out, r.err)
	}
	if len(k.pins) != 2 { // the enrolment, then ONE proof
		t.Fatalf("the key was asked %d times, want 2", len(k.pins))
	}
	// The password alone no longer opens it; with the key it does. The
	// recovery code alone still does, and the output says so with the command.
	if opensWith(path, "--password-file", pw) {
		t.Fatal("the password alone still opens it")
	}
	if !opensWith(path, "--password-file", pw, "--fido2", "--pin-file", pin) {
		t.Fatal("the password with the key does not open it")
	}
	if !opensWith(path, "--recovery-file", rc) {
		t.Fatal("the recovery code stopped working")
	}
	if strings.Contains(r.err, "the password alone still opens") || !strings.Contains(r.err, "the recovery code alone still opens") {
		t.Fatalf("what remains is misreported: %q", r.err)
	}
}

func TestEnrollKeyRequireRefusals(t *testing.T) {
	path, pw, rc, pin, k := anyContainer(t)
	// It needs the password: refused before the key is asked.
	if r := run(nil, "enroll-key", path, "--recovery-file", rc, "--pin-file", pin, "--require"); r.e == nil || !strings.Contains(r.e.Error(), "needs the password") || len(k.pins) != 0 {
		t.Fatalf("recovery only: %v, %d touches", r.e, len(k.pins))
	}
	// The key answers the proof with a credential of ANOTHER key: the key is
	// paired, the removal is refused, the password still opens the container.
	other := cliKey{creds: [][]byte{[]byte(strings.Repeat("z", 32))}}
	k.deriveCreds = other.creds
	r := run(nil, "enroll-key", path, "--password-file", pw, "--pin-file", pin, "--require")
	if !errors.Is(r.e, theca.ErrLastWay) || !strings.Contains(r.e.Error(), "the key is paired, but --require did not complete") {
		t.Fatalf("another key: %v", r.e)
	}
	if !opensWith(path, "--password-file", pw) {
		t.Fatal("a refused --require removed the password-only slot")
	}
	// The key holds no credential at proof time, or fails to answer.
	k.deriveCreds = [][]byte{}
	if r := run(nil, "enroll-key", path, "--password-file", pw, "--pin-file", pin, "--require"); !errors.Is(r.e, theca.ErrNoCredential) {
		t.Fatalf("no credential: %v", r.e)
	}
	if !opensWith(path, "--password-file", pw) {
		t.Fatal("the password-only slot is gone")
	}
}

func TestEnrollKeyCannotCheckWhatRemains(t *testing.T) {
	path, pw, rc, pin, _ := anyContainer(t)
	saved := slotsOf
	t.Cleanup(func() { slotsOf = saved })
	boom := errors.New("read failed")
	calls := 0
	for failOn := 1; failOn <= 2; failOn++ {
		calls = 0
		slotsOf = func(c *theca.Container, fs ...theca.Factor) ([]int, error) {
			calls++
			if calls == failOn {
				return nil, boom
			}
			return saved(c, fs...)
		}
		r := run(nil, "enroll-key", path, "--password-file", pw, "--recovery-file", rc, "--pin-file", pin)
		if !errors.Is(r.e, boom) || !strings.Contains(r.e.Error(), "the key is paired") {
			t.Fatalf("fail on call %d: %v", failOn, r.e)
		}
	}
}

func TestSlotsRemoveWithTheKey(t *testing.T) {
	path, pw, rc, pin, k := anyContainer(t)
	if r := run(nil, "enroll-key", path, "--password-file", pw, "--recovery-file", rc, "--pin-file", pin); r.e != nil {
		t.Fatal(r.e, r.err)
	}
	key := []string{"--pin-file", pin}
	args := func(more ...string) []string {
		return append(append([]string{"slots", "remove", path, "--password-file", pw, "--recovery-file", rc}, key...), more...)
	}
	// Refusals write nothing: syntax, a missing partner (before any touch), the
	// key itself, a keep that overlaps the removal, a key that is not this one.
	k.pins = nil
	for name, tc := range map[string][]string{
		"fido2 alone":            {"--remove", "fido2", "--keep", "password"},
		"three factors":          {"--remove", "password", "--keep", "password+recovery+fido2"},
		"twice":                  {"--remove", "password", "--keep", "password+password"},
		"unknown":                {"--remove", "password", "--keep", "password+key"},
		"empty member":           {"--remove", "password", "--keep", "password+"},
		"remove nothing opens":   {"--remove", "password+recovery", "--keep", "password+fido2"},
		"keep overlaps removal":  {"--remove", "password+fido2", "--keep", "password+fido2"},
		"keep is the removed":    {"--remove", "password+fido2", "--keep", "fido2+password"},
		"same partner, key only": {"--remove", "password", "--keep", "password"},
	} {
		if r := run(nil, args(tc...)...); r.e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !opensWith(path, "--password-file", pw) || !opensWith(path, "--recovery-file", rc) {
		t.Fatal("a refusal changed the container")
	}

	// A key that is not the one enrolled here proves nothing: ErrLastWay.
	k.deriveCreds = [][]byte{[]byte(strings.Repeat("y", 32))}
	r := run(nil, args("--remove", "password", "--keep", "password+fido2")...)
	if !errors.Is(r.e, theca.ErrLastWay) || !strings.Contains(r.e.Error(), "THIS container") {
		t.Fatalf("a stranger key: %v", r.e)
	}
	// A key with no Theca credential cannot be part of a set.
	k.deriveCreds = [][]byte{}
	if r := run(nil, args("--remove", "password", "--keep", "password+fido2")...); !errors.Is(r.e, theca.ErrNoCredential) || !strings.Contains(r.e.Error(), "cannot be part of a set") {
		t.Fatalf("no credential: %v", r.e)
	}
	k.deriveCreds = nil
	if !opensWith(path, "--password-file", pw) {
		t.Fatal("a refused removal removed the password slot")
	}
	// A partner that was not presented is refused before the key is touched.
	k.pins = nil
	r = run(nil, "slots", "remove", path, "--recovery-file", rc, "--pin-file", pin, "--remove", "recovery", "--keep", "password+fido2")
	if r.e == nil || !strings.Contains(r.e.Error(), "needs the password") || len(k.pins) != 0 {
		t.Fatalf("missing partner: %v, %d touches", r.e, len(k.pins))
	}
	// No key to open: the error is the key layer's.
	boom := errors.New("no key attached")
	withKey(t, nil, boom)
	if r := run(nil, args("--remove", "password", "--keep", "password+fido2")...); !errors.Is(r.e, boom) {
		t.Fatalf("no key: %v", r.e)
	}
	withKey(t, k, nil)

	// The same key, one touch, both partners: remove the recovery-only slot
	// keeping the key paired with the password.
	k.pins = nil
	r = run(nil, args("--remove", "recovery", "--keep", "password+fido2")...)
	if r.e != nil || len(k.pins) != 1 || !strings.Contains(r.err, "Touch the security key once") {
		t.Fatalf("%v pins=%d err=%q", r.e, len(k.pins), r.err)
	}
	if opensWith(path, "--recovery-file", rc) || !opensWith(path, "--password-file", pw) {
		t.Fatal("the recovery-only slot was not the one removed")
	}
	// The key names either side, in any order, and a removal can be a key slot
	// (the recovery code with the key) while the password stays.
	k.pins = nil
	r = run(nil, args("--remove", "fido2+recovery", "--keep", "password")...)
	if r.e != nil || len(k.pins) != 1 || !strings.Contains(r.out, "removed 1 slot(s) opened by the fido2+recovery") {
		t.Fatalf("%v pins=%d out=%q", r.e, len(k.pins), r.out)
	}
	// Remove the password-only slot, keeping the key: now it takes both.
	r = run(nil, args("--remove", "password", "--keep", "password+fido2")...)
	if r.e != nil {
		t.Fatal(r.e)
	}
	if opensWith(path, "--password-file", pw) || !opensWith(path, "--password-file", pw, "--fido2", "--pin-file", pin) {
		t.Fatal("the password-only slot was not the one removed")
	}
	// Both sides need the key, and the container is opened with it too (a
	// second touch, said in the help); the last way in is still refused.
	k.pins = nil
	r = run(nil, "slots", "remove", path, "--password-file", pw, "--pin-file", pin, "--fido2", "--remove", "password+fido2", "--keep", "password+fido2")
	if !errors.Is(r.e, theca.ErrLastWay) || len(k.pins) != 2 {
		t.Fatalf("%v pins=%d", r.e, len(k.pins))
	}
	// slots list takes the key's flags too.
	if r := run(nil, "slots", "list", path, "--password-file", pw, "--fido2", "--pin-file", pin); r.e != nil || !strings.Contains(r.out, "opened by the password: none") {
		t.Fatalf("%v %q", r.e, r.out)
	}
}

// Each refusal names the flag and the value it refused, so the person knows
// which of the two sets is wrong, and none of them asks the key.
func TestSlotsRemoveNamesTheSetThatIsWrong(t *testing.T) {
	path, pw, rc, pin, k := anyContainer(t)
	if r := run(nil, "enroll-key", path, "--password-file", pw, "--recovery-file", rc, "--pin-file", pin); r.e != nil {
		t.Fatal(r.e)
	}
	k.pins = nil
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"bad remove":         {[]string{"--remove", "fido2", "--keep", "password"}, `--remove "fido2": a key opens`},
		"bad keep":           {[]string{"--remove", "password", "--keep", "key"}, `--keep "key": want `},
		"remove not given":   {[]string{"--remove", "password"}, "give --remove and --keep"},
		"keep not given":     {[]string{"--keep", "password"}, "give --remove and --keep"},
		"remove twice named": {[]string{"--remove", "password+password", "--keep", "recovery"}, "password twice"},
	} {
		r := run(nil, append([]string{"slots", "remove", path, "--password-file", pw, "--pin-file", pin}, tc.args...)...)
		if r.e == nil || !strings.Contains(r.e.Error(), tc.want) {
			t.Errorf("%s: %v (want %q)", name, r.e, tc.want)
		}
	}
	// A factor that was not presented: named, per side, before the key is asked.
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"remove side": {[]string{"--remove", "recovery+fido2", "--keep", "password"}, "--remove recovery+fido2 needs the recovery code: give --recovery-from REF"},
		"keep side":   {[]string{"--remove", "password", "--keep", "recovery+fido2"}, "--keep recovery+fido2 needs the recovery code: give --recovery-from REF"},
	} {
		r := run(nil, append([]string{"slots", "remove", path, "--password-file", pw, "--pin-file", pin}, tc.args...)...)
		if r.e == nil || r.e.Error() != tc.want {
			t.Errorf("%s: %v (want %q)", name, r.e, tc.want)
		}
	}
	if len(k.pins) != 0 {
		t.Fatalf("the key was touched %d times by refusals that need no key", len(k.pins))
	}
}

func TestParseSet(t *testing.T) {
	for in, want := range map[string]factorSet{
		"password":          {kinds: []string{"pw"}},
		"recovery":          {kinds: []string{"rc"}},
		"password+recovery": {kinds: []string{"pw", "rc"}},
		"recovery+password": {kinds: []string{"pw", "rc"}},
		"password+fido2":    {kinds: []string{"pw"}, key: true},
		"fido2+password":    {kinds: []string{"pw"}, key: true},
		"recovery+fido2":    {kinds: []string{"rc"}, key: true},
	} {
		got, err := parseSet("keep", in)
		if err != nil || got.key != want.key || strings.Join(got.kinds, ",") != strings.Join(want.kinds, ",") {
			t.Errorf("%q: %+v, %v (want %+v)", in, got, err, want)
		}
	}
	for _, in := range []string{"", "fido2", "key", "password+", "+password", "password+password", "fido2+fido2",
		"password+recovery+fido2", "Password", "password recovery", "password++fido2"} {
		if got, err := parseSet("keep", in); err == nil || !strings.HasPrefix(err.Error(), `--keep "`) {
			t.Errorf("%q accepted as %+v (%v)", in, got, err)
		}
	}
}

func FuzzParseSet(f *testing.F) {
	for _, s := range []string{"password", "recovery+fido2", "fido2+password", "password+recovery+fido2", "", "+", "fido2", "password+password"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		fs, err := parseSet("keep", s)
		if err != nil {
			return
		}
		// Whatever is accepted is one of the five sets a slot can have, named
		// by the words themselves and nothing else.
		if len(fs.kinds) == 0 || len(fs.kinds) > 2 || fs.key && len(fs.kinds) != 1 {
			t.Fatalf("%q accepted as %+v", s, fs)
		}
		for _, tok := range strings.Split(s, "+") {
			if tok != "password" && tok != "recovery" && tok != "fido2" {
				t.Fatalf("%q accepted with the word %q", s, tok)
			}
		}
		if again, err := parseSet("keep", s); err != nil || again.key != fs.key || strings.Join(again.kinds, ",") != strings.Join(fs.kinds, ",") {
			t.Fatalf("%q parses two ways", s)
		}
	})
}

func TestShellWordAndSecretFlag(t *testing.T) {
	for in, want := range map[string]string{
		"/a/b-c_d.e": "/a/b-c_d.e",
		"a b":        "'a b'",
		"it's":       `'it'\''s'`,
		"":           "''",
		"$(x)":       "'$(x)'",
	} {
		if got := shellWord(in); got != want {
			t.Errorf("shellWord(%q) = %q, want %q", in, got, want)
		}
	}
	for from, want := range map[string]string{
		"keychain:theca/pw":    "--password-from keychain:theca/pw",
		"keepassxc:https://x/": "--password-from keepassxc:https://x/",
		"file:/p w":            "--password-from REF", // a file: reference is not echoed
		"":                     "--password-from REF", // the terminal or a file flag
		"nonsense":             "--password-from REF",
	} {
		if got := secretFlag("password", from); got != want {
			t.Errorf("secretFlag(%q) = %q, want %q", from, got, want)
		}
	}
}
