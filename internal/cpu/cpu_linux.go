//go:build linux

package cpu

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Android's core_ctl pauses idle cores, so the runtime starts with fewer procs than the cores that wake up under load.
const raiseProcs = runtime.GOOS == "android"

// logical counts allowed CPUs that are online; paused cores leave sched_getaffinity, which the runtime reads once at startup, but stay in both lists.
func logical() int {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	online, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return 0
	}
	var allowed string
	for _, line := range strings.Split(string(status), "\n") {
		if value, ok := strings.CutPrefix(line, "Cpus_allowed_list:"); ok {
			allowed = value
			break
		}
	}
	permitted, present := cpuList(allowed), cpuList(string(online))
	count := 0
	for cpu := range permitted {
		if present[cpu] {
			count++
		}
	}
	return count
}

// cpuList parses a kernel CPU list such as 0-3,6 and returns nil when it is malformed.
func cpuList(text string) map[int]bool {
	set := map[int]bool{}
	for _, part := range strings.Split(strings.TrimSpace(text), ",") {
		low, high, ranged := strings.Cut(part, "-")
		first, err := strconv.Atoi(low)
		last := first
		if err == nil && ranged {
			last, err = strconv.Atoi(high)
		}
		if err != nil || first < 0 || last < first || last-first > 1<<16 {
			return nil
		}
		for cpu := first; cpu <= last; cpu++ {
			set[cpu] = true
		}
	}
	return set
}
