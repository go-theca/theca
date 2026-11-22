package session

import (
	"errors"
	"net"
	"strings"
	"testing"
)

const testSID = "S-1-5-21-1004336348-1177238915-682003330-1001"

func TestValidSID(t *testing.T) {
	for s, want := range map[string]bool{
		testSID:         true,
		"S-1-5-18":      true,
		"":              false,
		"S-1":           false,
		"X-1-5-18":      false,
		"S-1-5-18)(A;;": false,
		"S-1-5-1a":      false,
		"S-1-5-18 ":     false,
	} {
		if got := validSID(s); got != want {
			t.Errorf("validSID(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestPipePath(t *testing.T) {
	p, err := PipePath(testSID, "work")
	if err != nil || p != `\\.\pipe\theca-`+testSID+`-work` {
		t.Fatalf("PipePath = %q, %v", p, err)
	}
	if _, err := PipePath("bad", "work"); err == nil {
		t.Error("bad SID accepted")
	}
	if _, err := PipePath(testSID, "../x"); err == nil {
		t.Error("bad name accepted")
	}
	long := strings.Repeat("a", maxPipeName)
	if _, err := PipePath(testSID, long); err == nil {
		t.Error("name over the pipe limit accepted")
	}
}

func TestPipeSDDL(t *testing.T) {
	if got := pipeSDDL(testSID); got != "D:P(A;;GA;;;"+testSID+")" {
		t.Errorf("pipeSDDL = %q", got)
	}
}

type fdConn struct {
	net.Conn
	fd uintptr
}

func (c fdConn) Fd() uintptr { return c.fd }

func TestAuthorizeSID(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ok := func(fd uintptr) (string, error) {
		if fd != 7 {
			t.Errorf("fd = %d", fd)
		}
		return testSID, nil
	}
	if err := authorizeSID(a, testSID, ok); err == nil || errors.Is(err, ErrPeer) {
		t.Errorf("a non-pipe: %v", err)
	}
	c := fdConn{a, 7}
	if err := authorizeSID(c, testSID, ok); err != nil {
		t.Errorf("same SID: %v", err)
	}
	if err := authorizeSID(c, "S-1-5-18", ok); !errors.Is(err, ErrPeer) {
		t.Errorf("other SID: %v", err)
	}
	fail := func(uintptr) (string, error) { return "", errors.New("no") }
	if err := authorizeSID(c, testSID, fail); !errors.Is(err, ErrPeer) {
		t.Errorf("lookup error: %v", err)
	}
}

func TestParseReadyHandle(t *testing.T) {
	for v, want := range map[string]uintptr{"1": 1, "424": 424} {
		if got, ok := parseReadyHandle(v); !ok || got != want {
			t.Errorf("parseReadyHandle(%q) = %d, %v", v, got, ok)
		}
	}
	for _, v := range []string{"", "0", "-1", " 5", "5 ", "x", "99999999999999999999999"} {
		if _, ok := parseReadyHandle(v); ok {
			t.Errorf("parseReadyHandle(%q) accepted", v)
		}
	}
	if got := readyEnvEntry(12); got != "THECA_READY_HANDLE=12" {
		t.Errorf("readyEnvEntry = %q", got)
	}
}

func FuzzParseReadyHandle(f *testing.F) {
	for _, s := range []string{"1", "0", "", "-3", "18446744073709551615"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if h, ok := parseReadyHandle(s); ok && h == 0 {
			t.Fatalf("%q gave handle 0", s)
		}
	})
}
