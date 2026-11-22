package profile

import "fmt"

// The access control of a Windows file is its DACL, not the mode bits Go
// reports (always 0666 or 0444 there). The decision about a DACL is plain Go, so
// that every system tests it; private_windows.go reads the DACL.

// Well-known SIDs a private file may name besides its user: LocalSystem, the
// built-in Administrators (a file made by an elevated process is owned by that
// group) and CREATOR OWNER.
const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
	sidCreatorOwner   = "S-1-3-0"
)

// privateDACL says whether a file whose owner is owner and whose DACL is
// described by nullDACL and allowed (the SIDs of its access-allowed entries) is
// closed to every account but the user self and the system's own. A null DACL
// grants everyone access. An access-denied entry changes nothing here: only the
// entries that allow are looked at.
func privateDACL(path, self, owner string, nullDACL bool, allowed []string) error {
	trusted := func(s string) bool {
		return s == self || s == sidSystem || s == sidAdministrators || s == sidCreatorOwner
	}
	if nullDACL {
		return fmt.Errorf("%s: no access control list: everyone may use it", path)
	}
	if !trusted(owner) {
		return fmt.Errorf("%s: owned by %s, not by this user", path, owner)
	}
	for _, s := range allowed {
		if !trusted(s) {
			return fmt.Errorf("%s: access granted to %s: only this user, the system and the administrators may have access", path, s)
		}
	}
	return nil
}
