package cli

import (
	"fmt"

	"artb/internal/cpu"
	"artb/internal/detect"
	"github.com/spf13/cobra"
)

// newGroupCommand builds a format command that only holds actions and prints help when called bare.
func newGroupCommand(use, short string, children ...*cobra.Command) *cobra.Command {
	cmd := &cobra.Command{Use: use, Short: short, Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())
		}
		return nil
	}, RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
	cmd.AddCommand(children...)
	return cmd
}

// newFormatUnpackCommand builds <format> unpack, which extracts like artb unpack but rejects other formats.
func newFormatUnpackCommand(expect detect.Type, use, short, example string, partitions, jobs bool) (*cobra.Command, *unpackOptions) {
	options := &unpackOptions{jobs: cpu.Logical(), expect: expect}
	cmd := &cobra.Command{Use: use, Short: short, Example: example, Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		return unpackDetected(cmd.Context(), cmd, args[0], *options)
	}}
	if partitions {
		cmd.Flags().StringVarP(&options.partitions, "partitions", "p", "", "Extract comma-separated partitions")
	}
	cmd.Flags().StringVarP(&options.output, "output", "o", "", "Set output directory")
	if jobs {
		cmd.Flags().IntVarP(&options.jobs, "jobs", "j", options.jobs, "Set concurrent extraction workers")
	}
	cmd.Flags().BoolVarP(&options.quiet, "quiet", "q", false, "Suppress success output")
	return cmd, options
}

func newPayloadCommand() *cobra.Command {
	unpack, options := newFormatUnpackCommand(detect.Payload, "unpack <payload.bin|ota.zip>", "Extract partition images from a payload or OTA zip", "  artb payload unpack ota.zip\n  artb payload unpack payload.bin -p boot,vendor_boot\n  artb payload unpack incremental.zip --old old_images", true, true)
	unpack.Flags().StringVar(&options.old, "old", "", "Set source image directory for delta payloads")
	unpack.Flags().BoolVar(&options.noVerify, "no-verify", false, "Skip source and output SHA-256 verification")
	return newGroupCommand("payload", "List and extract OTA payload partitions", newPayloadListCommand(), unpack)
}

func newSuperCommand() *cobra.Command {
	unpack, _ := newFormatUnpackCommand(detect.Super, "unpack <super.img>", "Extract logical partitions from a raw or sparse super image", "  artb super unpack super.img\n  artb super unpack super.img -p system_a,vendor_a -o rom", true, true)
	return newGroupCommand("super", "Extract and assemble dynamic partition super images", unpack, newSuperPackCommand())
}

func newEROFSCommand() *cobra.Command {
	unpack, _ := newFormatUnpackCommand(detect.EROFS, "unpack <image>", "Extract an EROFS image with fs_config and file_contexts", "  artb erofs unpack system_a.img\n  artb erofs unpack system.img -o system_unpacked", false, true)
	return newGroupCommand("erofs", "Extract and build EROFS partition images", unpack, newEROFSPackCommand())
}

func newEXT4Command() *cobra.Command {
	unpack, _ := newFormatUnpackCommand(detect.Ext4, "unpack <image>", "Extract an EXT4 image with fs_config and file_contexts", "  artb ext4 unpack vendor.img\n  artb ext4 unpack vendor.img -o vendor_unpacked", false, true)
	return newGroupCommand("ext4", "Extract and build EXT4 partition images", unpack, newEXT4PackCommand())
}

func newF2FSCommand() *cobra.Command {
	unpack, _ := newFormatUnpackCommand(detect.F2FS, "unpack <image>", "Extract an F2FS image with fs_config and file_contexts", "  artb f2fs unpack system.img\n  artb f2fs unpack userdata.img -o userdata_unpacked", false, true)
	return newGroupCommand("f2fs", "Extract and build F2FS partition images", unpack, newF2FSPackCommand())
}
