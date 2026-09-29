//go:build linux || darwin

package progress

import (
	"syscall"
	"unsafe"
)

func consoleColumns(fd uintptr) int {
	var size struct{ rows, columns, xpixels, ypixels uint16 }
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&size))); errno != 0 {
		return 0
	}
	return int(size.columns)
}
