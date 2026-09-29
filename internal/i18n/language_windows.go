package i18n

import (
	"syscall"
	"unsafe"
)

var preferredUILanguages = syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserPreferredUILanguages")

func systemTag() string {
	var count, size uint32
	result, _, _ := preferredUILanguages.Call(0, uintptr(unsafe.Pointer(&count)), 0, uintptr(unsafe.Pointer(&size)))
	if result == 0 || size < 2 || size > 1024 {
		return ""
	}
	buffer := make([]uint16, size)
	result, _, _ = preferredUILanguages.Call(0, uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if result == 0 || count == 0 {
		return ""
	}
	return syscall.UTF16ToString(buffer)
}
