//go:build windows

package cpu

import "syscall"

const allProcessorGroups = 0xffff

// runtime.NumCPU reads the process affinity mask, which covers only one processor group of at most 64 processors.
const raiseProcs = true

var getActiveProcessorCount = syscall.NewLazyDLL("kernel32.dll").NewProc("GetActiveProcessorCount")

func logical() int {
	if getActiveProcessorCount.Find() != nil {
		return 0
	}
	count, _, _ := getActiveProcessorCount.Call(allProcessorGroups)
	return int(uint32(count))
}
