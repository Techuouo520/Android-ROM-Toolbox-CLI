package progress

import (
	"syscall"
	"unsafe"
)

var getConsoleScreenBufferInfo = syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleScreenBufferInfo")

func consoleColumns(fd uintptr) int {
	// Mirrors CONSOLE_SCREEN_BUFFER_INFO: size, cursor, attributes, window {left, top, right, bottom}, maximum size.
	var info struct {
		size, cursor [2]int16
		attributes   uint16
		window       [4]int16
		maximum      [2]int16
	}
	if ok, _, _ := getConsoleScreenBufferInfo.Call(fd, uintptr(unsafe.Pointer(&info))); ok == 0 {
		return 0
	}
	return int(info.window[2]-info.window[0]) + 1
}
