//go:build !windows && !android && !darwin

package hardware

import "context"

func Collect(context.Context) (Info, error) {
	return Info{}, nil
}
