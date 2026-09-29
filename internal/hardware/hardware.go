package hardware

import "strings"

type Disk struct {
	Model      string
	SizeBytes  uint64
	DataVolume bool
}

type Info struct {
	CPUModel    string
	GPUs        []string
	Disks       []Disk
	MemoryBytes uint64
}

func CleanName(name string) string {
	return strings.Join(strings.Fields(name), " ")
}
