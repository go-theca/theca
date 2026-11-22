//go:build windows

package profile

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// checkPrivate reads the owner and the DACL of the open file and applies
// privateDACL.
func checkPrivate(f *os.File, path string, _ os.FileInfo) error {
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s: no owner: %v", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if dacl == nil {
		return privateDACL(path, self.User.Sid.String(), owner.String(), true, nil)
	}
	var allowed []string
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		allowed = append(allowed, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	return privateDACL(path, self.User.Sid.String(), owner.String(), false, allowed)
}
