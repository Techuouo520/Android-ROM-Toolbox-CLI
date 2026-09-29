package cli

import (
	"fmt"
	"runtime"

	"artb/internal/buildinfo"
	"artb/internal/cpu"
	"artb/internal/hardware"
	"artb/internal/i18n"
	"artb/xz"
	"github.com/spf13/cobra"
)

func newVersionCommand(language i18n.Language) *cobra.Command {
	words := i18n.Text(language)
	return &cobra.Command{Use: "version", Short: words.VersionShort, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		// The LZMA decoder line shows whether the bundle assembled LzmaDecOpt, measured 1.3-1.9x faster on XZ payload operations.
		decoder := "c"
		if xz.AsmEnabled() {
			decoder = "asm"
		}
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Android ROM Toolbox %s\n%s %s/%s\n%s %d\n%s %s\n", buildinfo.Version, words.Platform, runtime.GOOS, runtime.GOARCH, words.LogicalCPUs, cpu.Logical(), words.Decoder, decoder); err != nil {
			return err
		}
		info, probeErr := hardware.Collect(cmd.Context())
		if probeErr != nil {
			if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "%s: %v\n", words.HardwareQuery, probeErr); err != nil {
				return err
			}
		}
		model := info.CPUModel
		if model == "" {
			model = words.Unavailable
		}
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", words.CPUModel, model); err != nil {
			return err
		}
		if info.MemoryBytes == 0 {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", words.Memory, words.Unavailable); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %.2f%s\n", words.Memory, float64(info.MemoryBytes)/1_000_000, words.MemoryUnit); err != nil {
			return err
		}
		if len(info.GPUs) == 0 {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", words.GPU, words.Unavailable); err != nil {
				return err
			}
		}
		for i, gpu := range info.GPUs {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s_%d %s\n", words.GPU, i, gpu); err != nil {
				return err
			}
		}
		if len(info.Disks) == 0 {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", words.Disk, words.Unavailable); err != nil {
				return err
			}
		}
		for i, disk := range info.Disks {
			label := disk.Model
			if disk.DataVolume {
				label += " " + words.DataVolume
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s_%d %s (%.2f MB)\n", words.Disk, i, label, float64(disk.SizeBytes)/1_000_000); err != nil {
				return err
			}
		}
		return nil
	}}
}
