//go:build !windows

package payload

import "os"

// prepareOutput has nothing to do where truncating an image already leaves its unwritten ranges as holes.
func prepareOutput(*os.File) {}
