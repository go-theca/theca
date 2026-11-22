// Package profile is the file of named containers: containers.toml, in the
// per-user configuration directory, mode 0600.
//
// A profile holds REFERENCES, never a secret: where the container is, which
// secret-manager entry holds its password (keychain:, secretservice:,
// keepassxc:; file: is refused, a path to a secret is not a reference to a
// manager), which security key, which counter. Anyone who reads the file learns
// which container and which entry; they learn no password. Validate checks the
// references' syntax WITHOUT reading what they point to.
//
// The format is the small subset of TOML this file needs: [name] tables of
// key = "string", true/false or an integer. Parse refuses everything else, in
// bounded memory, so the file can be fuzzed (FuzzParse).
package profile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-authn/secretsource"
)

// Limits on what a profile file may hold.
const (
	MaxFileBytes = 1 << 20
	MaxProfiles  = 256
	MaxLineBytes = 4096
	maxNameLen   = 64
)

// Profile is one container and how to open it.
type Profile struct {
	Name         string
	File         string // absolute path of the container
	PasswordFrom string // keychain:, secretservice: or keepassxc: reference; empty: ask on the terminal
	RecoveryFrom string // idem, the recovery code
	PINFrom      string // idem, the security key's PIN (unused by a key with a fingerprint)
	FIDO2        bool   // use a security key (implied by Device)
	Device       string // the key's ID or name (fido list prints them)
	Hint         int    // Argon2id profile of the password (0, 1 or 2)
	Counter      string // "" or "tpm"
	TPMDevice    string // TPM device path or unix:SOCKET
	// TPMAuthFrom is the counter's authValue of a container made with an
	// explicit one; empty for the usual derived authValue (nothing to store).
	TPMAuthFrom string
	// TPMEndorsementFrom is the TPM's endorsement password, empty if it has none.
	TPMEndorsementFrom string
	Share              string // share name, default "theca"
	Sync               time.Duration
	// CloseOnLock closes the container when the screen locks, the machine
	// sleeps or the user logs out. Default true.
	CloseOnLock bool
}

// Defaults.
const (
	DefaultShare = "theca"
	DefaultSync  = 5 * time.Second
)

// New returns a profile with the defaults filled in.
func New(name, file string) Profile {
	return Profile{Name: name, File: file, Share: DefaultShare, Sync: DefaultSync, CloseOnLock: true}
}

// UsesKey reports whether opening the profile asks the security key.
func (p Profile) UsesKey() bool { return p.FIDO2 || p.Device != "" }

// ValidName reports whether s can name a profile: it becomes a socket file
// name, so letters, digits, "-", "_" and "." (not first), at most 64.
func ValidName(s string) error {
	if s == "" || len(s) > maxNameLen {
		return fmt.Errorf("profile name %q: 1 to %d characters", clip(s), maxNameLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || (c == '.' && i > 0)
		if !ok {
			return fmt.Errorf("profile name %q: letters, digits, - _ and . (not first) only", clip(s))
		}
	}
	return nil
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

// checkRef validates a manager reference's syntax; it never reads the secret.
// file: is refused: the profile names managers, and a path to a secret file is
// the thing a manager replaces.
func checkRef(key, ref string) error {
	if ref == "" {
		return nil
	}
	r, err := secretsource.Parse(ref)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	if r.Scheme == "file" {
		return fmt.Errorf("%s: file: references are refused in a profile (use keychain:, secretservice: or keepassxc:)", key)
	}
	return nil
}

func noControl(key, v string) error {
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s: control character", key)
		}
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("%s: not UTF-8", key)
	}
	return nil
}

// Validate checks every field without reading a secret or touching the file.
func (p Profile) Validate() error {
	if err := ValidName(p.Name); err != nil {
		return err
	}
	if !filepath.IsAbs(p.File) {
		return fmt.Errorf("file %q: must be an absolute path", clip(p.File))
	}
	if len(p.File) > 1024 {
		return errors.New("file: longer than 1024 bytes")
	}
	for _, kv := range [][2]string{{"file", p.File}, {"device", p.Device}, {"tpm-device", p.TPMDevice}, {"share", p.Share}} {
		if err := noControl(kv[0], kv[1]); err != nil {
			return err
		}
	}
	for _, kv := range [][2]string{{"password-from", p.PasswordFrom}, {"recovery-from", p.RecoveryFrom}, {"pin-from", p.PINFrom},
		{"tpm-auth-from", p.TPMAuthFrom}, {"tpm-endorsement-auth-from", p.TPMEndorsementFrom}} {
		if err := checkRef(kv[0], kv[1]); err != nil {
			return err
		}
	}
	if p.Hint < 0 || p.Hint > 2 {
		return fmt.Errorf("hint %d: want 0, 1 or 2", p.Hint)
	}
	if p.Counter != "" && p.Counter != "tpm" {
		return fmt.Errorf("counter %q: want tpm or empty", clip(p.Counter))
	}
	if (p.TPMDevice != "" || p.TPMAuthFrom != "" || p.TPMEndorsementFrom != "") && p.Counter == "" {
		return errors.New("tpm-* options without counter = \"tpm\"")
	}
	if p.Share == "" {
		return errors.New("share: empty")
	}
	if p.Sync <= 0 || p.Sync > time.Hour {
		return fmt.Errorf("sync %s: want more than 0 and at most 1h", p.Sync)
	}
	// Parse refuses a line over MaxLineBytes: so must Add, or the profile would
	// be written and the whole file then refused at every later read. The
	// lines are the ones Marshal writes, after quoting.
	for _, line := range strings.Split(string(Marshal(map[string]Profile{p.Name: p})), "\n") {
		if len(line) > MaxLineBytes {
			key, _, _ := strings.Cut(line, " ")
			return fmt.Errorf("%s: longer than %d bytes once written", key, MaxLineBytes)
		}
	}
	return nil
}

// ---- file format ----

// Parse reads a profile file. It refuses what it does not know.
func Parse(data []byte) (map[string]Profile, error) {
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf("profile file: more than %d bytes", MaxFileBytes)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("profile file: not UTF-8")
	}
	out := map[string]Profile{}
	var cur *Profile
	seen := map[string]bool{}
	flush := func() {
		if cur != nil {
			out[cur.Name] = *cur
		}
	}
	for n, line := range strings.Split(string(data), "\n") {
		n++
		if len(line) > MaxLineBytes {
			return nil, fmt.Errorf("line %d: longer than %d bytes", n, MaxLineBytes)
		}
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			name, ok := strings.CutSuffix(strings.TrimPrefix(line, "["), "]")
			if !ok {
				return nil, fmt.Errorf("line %d: unterminated table header", n)
			}
			if err := ValidName(name); err != nil {
				return nil, fmt.Errorf("line %d: %w", n, err)
			}
			flush()
			if _, dup := out[name]; dup {
				return nil, fmt.Errorf("line %d: profile %q twice", n, name)
			}
			if len(out) >= MaxProfiles {
				return nil, fmt.Errorf("line %d: more than %d profiles", n, MaxProfiles)
			}
			p := New(name, "")
			cur = &p
			seen = map[string]bool{}
			continue
		}
		if cur == nil {
			return nil, fmt.Errorf("line %d: a key before any [name] table", n)
		}
		key, rest, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("line %d: want key = value", n)
		}
		if seen[key] {
			return nil, fmt.Errorf("line %d: key %q twice", n, key)
		}
		seen[key] = true
		if err := cur.set(key, strings.TrimSpace(rest)); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
	}
	flush()
	for _, p := range out {
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("profile %s: %w", p.Name, err)
		}
	}
	return out, nil
}

// value is a decoded right-hand side: exactly one of s, b, i is meaningful.
type value struct {
	kind byte // 's', 'b', 'i'
	s    string
	b    bool
	i    int64
}

func parseValue(v string) (value, error) {
	switch {
	case strings.HasPrefix(v, `"`):
		s, rest, err := unquote(v)
		if err != nil {
			return value{}, err
		}
		if t := strings.TrimSpace(rest); t != "" && t[0] != '#' {
			return value{}, errors.New("text after the string")
		}
		return value{kind: 's', s: s}, nil
	}
	if i := strings.IndexByte(v, '#'); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	switch v {
	case "true":
		return value{kind: 'b', b: true}, nil
	case "false":
		return value{kind: 'b'}, nil
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return value{}, fmt.Errorf("value %q: want a \"string\", true, false or an integer", clip(v))
	}
	return value{kind: 'i', i: n}, nil
}

// unquote reads a basic string at the start of v and returns the rest.
func unquote(v string) (string, string, error) {
	var sb strings.Builder
	for i := 1; i < len(v); i++ {
		switch c := v[i]; c {
		case '"':
			return sb.String(), v[i+1:], nil
		case '\\':
			i++
			if i == len(v) {
				return "", "", errors.New("unterminated string")
			}
			switch v[i] {
			case '"', '\\':
				sb.WriteByte(v[i])
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			default:
				return "", "", fmt.Errorf("escape \\%c not supported", v[i])
			}
		default:
			sb.WriteByte(c)
		}
	}
	return "", "", errors.New("unterminated string")
}

func (p *Profile) set(key, raw string) error {
	v, err := parseValue(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	str := func(dst *string) error {
		if v.kind != 's' {
			return fmt.Errorf("%s: want a string", key)
		}
		*dst = v.s
		return nil
	}
	switch key {
	case "file":
		return str(&p.File)
	case "password-from":
		return str(&p.PasswordFrom)
	case "recovery-from":
		return str(&p.RecoveryFrom)
	case "pin-from":
		return str(&p.PINFrom)
	case "device":
		return str(&p.Device)
	case "counter":
		return str(&p.Counter)
	case "tpm-device":
		return str(&p.TPMDevice)
	case "tpm-auth-from":
		return str(&p.TPMAuthFrom)
	case "tpm-endorsement-auth-from":
		return str(&p.TPMEndorsementFrom)
	case "share":
		return str(&p.Share)
	case "fido2", "close-on-lock":
		if v.kind != 'b' {
			return fmt.Errorf("%s: want true or false", key)
		}
		if key == "fido2" {
			p.FIDO2 = v.b
		} else {
			p.CloseOnLock = v.b
		}
	case "hint":
		if v.kind != 'i' {
			return fmt.Errorf("%s: want an integer", key)
		}
		p.Hint = int(v.i)
	case "sync":
		var s string
		if err := str(&s); err != nil {
			return err
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("sync: %w", err)
		}
		p.Sync = d
	default:
		return fmt.Errorf("unknown key %q", clip(key))
	}
	return nil
}

func quote(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case '\n':
			sb.WriteString(`\n`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// Marshal writes profiles in name order, only the fields that differ from the
// defaults except the file.
func Marshal(ps map[string]Profile) []byte {
	names := make([]string, 0, len(ps))
	for n := range ps {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	sb.WriteString("# theca containers: references only, never a secret.\n")
	for _, n := range names {
		p := ps[n]
		fmt.Fprintf(&sb, "\n[%s]\nfile = %s\n", n, quote(p.File))
		for _, kv := range [][2]string{
			{"password-from", p.PasswordFrom}, {"recovery-from", p.RecoveryFrom}, {"pin-from", p.PINFrom},
			{"device", p.Device}, {"counter", p.Counter}, {"tpm-device", p.TPMDevice},
			{"tpm-auth-from", p.TPMAuthFrom}, {"tpm-endorsement-auth-from", p.TPMEndorsementFrom},
		} {
			if kv[1] != "" {
				fmt.Fprintf(&sb, "%s = %s\n", kv[0], quote(kv[1]))
			}
		}
		if p.FIDO2 {
			sb.WriteString("fido2 = true\n")
		}
		if p.Hint != 0 {
			fmt.Fprintf(&sb, "hint = %d\n", p.Hint)
		}
		if p.Share != DefaultShare {
			fmt.Fprintf(&sb, "share = %s\n", quote(p.Share))
		}
		if p.Sync != DefaultSync {
			fmt.Fprintf(&sb, "sync = %s\n", quote(p.Sync.String()))
		}
		if !p.CloseOnLock {
			sb.WriteString("close-on-lock = false\n")
		}
	}
	return []byte(sb.String())
}

// ---- the file on disk ----

// Store is a profile file.
type Store struct{ Path string }

// userConfigDir is replaced by tests.
var userConfigDir = os.UserConfigDir

// DefaultPath is os.UserConfigDir()/theca/containers.toml.
func DefaultPath() (string, error) {
	d, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "theca", "containers.toml"), nil
}

// Load reads the file; a missing file is an empty set. A file another user could
// read or write is refused: it names which container and which entry to attack.
func (s Store) Load() (map[string]Profile, error) {
	f, err := os.Open(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Profile{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := statFile(f)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", s.Path)
	}
	if err := checkPrivate(f, s.Path, st); err != nil {
		return nil, err
	}
	// The size bound is held by the limited read and by Parse, not by st.Size().
	data, err := readAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Seams the tests replace.
var (
	statFile = (*os.File).Stat
	readAll  = io.ReadAll
	writeTmp = func(f *os.File, b []byte) error { _, err := f.Write(b); return err }
)

// Save replaces the file atomically, mode 0600, in a 0700 directory.
func (s Store) Save(ps map[string]Profile) error {
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".containers-*.tmp")
	if err != nil {
		return err
	}
	werr := writeTmp(tmp, Marshal(ps))
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), s.Path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// Get returns one profile.
func (s Store) Get(name string) (Profile, error) {
	ps, err := s.Load()
	if err != nil {
		return Profile{}, err
	}
	p, ok := ps[name]
	if !ok {
		return Profile{}, fmt.Errorf("no profile %q (theca profile add %s FILE ...)", clip(name), clip(name))
	}
	return p, nil
}

// Add stores p, refusing a name already taken unless replace.
func (s Store) Add(p Profile, replace bool) error {
	if err := p.Validate(); err != nil {
		return err
	}
	ps, err := s.Load()
	if err != nil {
		return err
	}
	if _, ok := ps[p.Name]; ok && !replace {
		return fmt.Errorf("profile %q exists (--replace to overwrite)", p.Name)
	}
	if _, ok := ps[p.Name]; !ok && len(ps) >= MaxProfiles {
		return fmt.Errorf("more than %d profiles", MaxProfiles)
	}
	ps[p.Name] = p
	return s.Save(ps)
}

// Remove deletes one profile; the container and its secrets are untouched.
func (s Store) Remove(name string) error {
	ps, err := s.Load()
	if err != nil {
		return err
	}
	if _, ok := ps[name]; !ok {
		return fmt.Errorf("no profile %q", clip(name))
	}
	delete(ps, name)
	return s.Save(ps)
}

// List returns the profiles in name order.
func (s Store) List() ([]Profile, error) {
	ps, err := s.Load()
	if err != nil {
		return nil, err
	}
	out := make([]Profile, 0, len(ps))
	for _, p := range ps {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
