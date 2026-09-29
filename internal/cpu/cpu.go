// Package cpu reports how many logical processors artb keeps busy by default.
package cpu

import "runtime"

// Logical returns the logical processors available to the process, counted across all Windows processor groups.
func Logical() int {
	if count := logical(); count > 0 {
		return count
	}
	return max(runtime.NumCPU(), 1)
}

// UseAll lets the Go scheduler run on every logical processor that Logical reports.
func UseAll() {
	if count := Logical(); count > runtime.GOMAXPROCS(0) && raiseProcs {
		runtime.GOMAXPROCS(count)
	}
}
