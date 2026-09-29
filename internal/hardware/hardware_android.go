package hardware

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"artb/internal/androidprop"
)

func Collect(ctx context.Context) (Info, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	info := Info{}
	if model := androidprop.Get("ro.soc.model"); model != "" {
		info.CPUModel = CleanName(androidprop.Get("ro.soc.manufacturer") + " " + model)
	} else {
		info.CPUModel = CleanName(androidprop.Get("ro.board.platform"))
	}
	if memory, err := androidMemory(); err == nil {
		info.MemoryBytes = memory
	}
	if output, err := exec.CommandContext(ctx, "dumpsys", "SurfaceFlinger").Output(); err == nil {
		if gpu := androidGPU(output); gpu != "" {
			info.GPUs = append(info.GPUs, gpu)
		}
	}
	if len(info.GPUs) == 0 {
		if gpu := CleanName(androidprop.Get("ro.hardware.egl")); gpu != "" {
			info.GPUs = append(info.GPUs, gpu)
		}
	}
	if size, err := androidDataVolume(); err == nil {
		model := "Internal storage"
		switch device := strings.ToLower(androidprop.Get("ro.boot.boot_devices")); {
		case strings.Contains(device, "ufs"):
			model = "UFS"
		case strings.Contains(device, "mmc"):
			model = "eMMC"
		}
		info.Disks = append(info.Disks, Disk{Model: model, SizeBytes: size, DataVolume: true})
	}
	if err := ctx.Err(); err != nil {
		return info, fmt.Errorf("Android hardware query: %w", err)
	}
	return info, nil
}

func androidMemory() (uint64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[0] != "MemTotal:" || fields[2] != "kB" {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || kb > ^uint64(0)/1024 {
			return 0, fmt.Errorf("invalid MemTotal: %q", fields[1])
		}
		return kb * 1024, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("MemTotal missing")
}

func androidGPU(output []byte) string {
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "GLES:") {
			continue
		}
		parts := strings.SplitN(strings.TrimSpace(strings.TrimPrefix(line, "GLES:")), ",", 3)
		if len(parts) >= 2 {
			return CleanName(parts[1])
		}
	}
	return ""
}

func androidDataVolume() (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/data", &stat); err != nil {
		return 0, err
	}
	if stat.Bsize <= 0 || stat.Blocks == 0 || uint64(stat.Bsize) > ^uint64(0)/stat.Blocks {
		return 0, fmt.Errorf("invalid data volume size")
	}
	return uint64(stat.Bsize) * stat.Blocks, nil
}
