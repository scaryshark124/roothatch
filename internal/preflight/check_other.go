//go:build !linux

package preflight

import "errors"

// Check is implemented only on Linux, where descriptor-confined resolution
// (O_PATH, readlinkat) is available.
func Check(dir string) (Report, error) {
	return Report{}, &RootError{Dir: dir, Err: errors.New("check is supported only on Linux")}
}

// CheckShell is implemented only on Linux; elsewhere it returns the same
// RootError as Check.
func CheckShell(dir string) (Report, error) {
	return Check(dir)
}
