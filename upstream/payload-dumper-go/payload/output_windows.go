package payload

import (
	"os"
	"syscall"
)

// fsctlSetSparse is FSCTL_SET_SPARSE from winioctl.h.
const fsctlSetSparse = 0x000900C4

// prepareOutput marks a new image sparse before it is sized; otherwise NTFS zero-fills the gap below every write past the valid data length under the file lock, serializing the parallel operation writes. File systems without sparse support keep the old behaviour.
func prepareOutput(file *os.File) {
	conn, err := file.SyscallConn()
	if err != nil {
		return
	}
	conn.Control(func(handle uintptr) {
		var returned uint32
		syscall.DeviceIoControl(syscall.Handle(handle), fsctlSetSparse, nil, 0, nil, 0, &returned, nil)
	})
}
