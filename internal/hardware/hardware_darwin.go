package hardware

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// CPU, memory and the data volume come from sysctl and statfs in-process; the GPU is only listed in the IORegistry, so one short ioreg call reads it.

var (
	ioregModel = regexp.MustCompile(`"model" = <?"([^"]*)">?`)
	ioregCores = regexp.MustCompile(`"gpu-core-count" = (\d+)`)
)

func Collect(ctx context.Context) (Info, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var info Info
	var errs []error
	if model, err := syscall.Sysctl("machdep.cpu.brand_string"); err != nil {
		errs = append(errs, fmt.Errorf("machdep.cpu.brand_string: %w", err))
	} else {
		info.CPUModel = CleanName(model)
	}
	if memory, err := sysctlUint64("hw.memsize"); err != nil {
		errs = append(errs, fmt.Errorf("hw.memsize: %w", err))
	} else {
		info.MemoryBytes = memory
	}
	if output, err := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-r", "-d", "1", "-c", "IOAccelerator").Output(); err != nil {
		errs = append(errs, fmt.Errorf("ioreg: %w", err))
	} else {
		info.GPUs = darwinGPUs(output)
	}
	if disk, err := dataVolume(); err != nil {
		errs = append(errs, err)
	} else {
		info.Disks = append(info.Disks, disk)
	}
	return info, errors.Join(errs...)
}

// sysctlUint64 decodes the little-endian integer syscall.Sysctl returns as a string, which loses a trailing zero byte as if it ended text.
func sysctlUint64(name string) (uint64, error) {
	value, err := syscall.Sysctl(name)
	if err != nil {
		return 0, err
	}
	if len(value) == 0 || len(value) > 8 {
		return 0, fmt.Errorf("unexpected %d-byte value", len(value))
	}
	buffer := make([]byte, 8)
	copy(buffer, value)
	return binary.LittleEndian.Uint64(buffer), nil
}

// darwinGPUs reads each IOAccelerator node's model and, on Apple silicon, its GPU core count from ioreg's text output.
func darwinGPUs(output []byte) []string {
	var gpus []string
	for _, node := range strings.Split(string(output), "+-o ")[1:] {
		model := ioregModel.FindStringSubmatch(node)
		if model == nil || CleanName(model[1]) == "" {
			continue
		}
		name := CleanName(model[1])
		if cores := ioregCores.FindStringSubmatch(node); cores != nil {
			name += " (" + cores[1] + " GPU cores)"
		}
		gpus = append(gpus, name)
	}
	return gpus
}

// dataVolume reports the APFS data volume, whose statfs size is that of its whole container.
func dataVolume() (Disk, error) {
	var stat syscall.Statfs_t
	path := "/System/Volumes/Data"
	if err := syscall.Statfs(path, &stat); err != nil {
		path = "/"
		if err = syscall.Statfs(path, &stat); err != nil {
			return Disk{}, fmt.Errorf("statfs %s: %w", path, err)
		}
	}
	if stat.Bsize == 0 || stat.Blocks == 0 || stat.Blocks > ^uint64(0)/uint64(stat.Bsize) {
		return Disk{}, fmt.Errorf("statfs %s: invalid size", path)
	}
	name := make([]byte, 0, len(stat.Fstypename))
	for _, c := range stat.Fstypename {
		if c == 0 {
			break
		}
		name = append(name, byte(c))
	}
	model := strings.ToUpper(string(name))
	if model == "" {
		model = "Internal storage"
	}
	return Disk{Model: model, SizeBytes: uint64(stat.Bsize) * stat.Blocks, DataVolume: true}, nil
}
