package session

import (
	"errors"
	"testing"
)

func TestBreakawayFlag(t *testing.T) {
	for _, c := range []struct {
		name   string
		limits uint32
		err    error
		want   uint32
	}{
		{"no job", 0, errors.New("no job"), 0},
		{"job without breakaway", 0x2000, nil, 0},
		{"breakaway allowed", 0x2000 | jobLimitBreakawayOK, nil, createBreakawayFromJob},
		{"silent breakaway", jobLimitBreakawayOK | jobLimitSilentBreakaway, nil, 0},
		{"silent only", jobLimitSilentBreakaway, nil, 0},
		{"query failed, flags set", jobLimitBreakawayOK, errors.New("denied"), 0},
	} {
		if got := breakawayFlag(c.limits, c.err); got != c.want {
			t.Errorf("%s: %#x, want %#x", c.name, got, c.want)
		}
	}
}
