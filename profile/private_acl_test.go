package profile

import (
	"strings"
	"testing"
)

func TestPrivateDACL(t *testing.T) {
	const me = "S-1-5-21-1-2-3-1001"
	for _, c := range []struct {
		name    string
		owner   string
		null    bool
		allowed []string
		want    string // "" = accepted; else a fragment of the refusal
	}{
		{"user only", me, false, []string{me}, ""},
		{"user, system, admins", me, false, []string{me, sidSystem, sidAdministrators, sidCreatorOwner}, ""},
		{"owned by the administrators", sidAdministrators, false, []string{sidAdministrators, sidSystem}, ""},
		{"empty list", me, false, nil, ""},
		{"null DACL", me, true, nil, "everyone"},
		{"foreign owner", "S-1-5-21-9-9-9-500", false, []string{me}, "owned by"},
		{"everyone", me, false, []string{me, "S-1-1-0"}, "S-1-1-0"},
		{"users group", me, false, []string{"S-1-5-32-545"}, "S-1-5-32-545"},
	} {
		err := privateDACL("f", me, c.owner, c.null, c.allowed)
		if c.want == "" && err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}
