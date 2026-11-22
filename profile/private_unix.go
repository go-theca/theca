//go:build !windows

package profile

import (
	"fmt"
	"os"
)

// checkPrivate refuses a file that group or others can touch: the mode bits are
// the access control of a Unix file.
func checkPrivate(_ *os.File, path string, st os.FileInfo) error {
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s: mode %04o: group and others must have no access (chmod 600)", path, st.Mode().Perm())
	}
	return nil
}
