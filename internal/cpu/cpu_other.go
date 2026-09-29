//go:build !windows && !linux

package cpu

import "runtime"

// The runtime already sizes GOMAXPROCS from the affinity mask and container CPU limits.
const raiseProcs = false

func logical() int { return runtime.NumCPU() }
