//go:build darwin

package lockwatch

import (
	"context"

	"github.com/ebitengine/purego"
)

// watch reads CGSSessionScreenIsLocked from the current session's dictionary
// (CoreGraphics; no run loop needed) every pollInterval. A session without the
// dictionary (ssh) reads as not locked.
func watch(ctx context.Context) (<-chan string, error) {
	cg, err := purego.Dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, err
	}
	cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, err
	}
	var (
		sessionDict func() uintptr
		dictGet     func(d, k uintptr) uintptr
		strCreate   func(alloc uintptr, s *byte, enc uint32) uintptr
		boolValue   func(b uintptr) bool
		release     func(o uintptr)
	)
	purego.RegisterLibFunc(&sessionDict, cg, "CGSessionCopyCurrentDictionary")
	purego.RegisterLibFunc(&dictGet, cf, "CFDictionaryGetValue")
	purego.RegisterLibFunc(&strCreate, cf, "CFStringCreateWithCString")
	purego.RegisterLibFunc(&boolValue, cf, "CFBooleanGetValue")
	purego.RegisterLibFunc(&release, cf, "CFRelease")
	name := append([]byte("CGSSessionScreenIsLocked"), 0)
	key := strCreate(0, &name[0], 0x08000100) // kCFStringEncodingUTF8
	locked := func() bool {
		d := sessionDict()
		if d == 0 {
			return false
		}
		defer release(d)
		v := dictGet(d, key)
		return v != 0 && boolValue(v)
	}
	return newPoll(ctx, locked), nil
}
