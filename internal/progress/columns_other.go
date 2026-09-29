//go:build !linux && !darwin && !windows

package progress

func consoleColumns(uintptr) int { return 0 }
