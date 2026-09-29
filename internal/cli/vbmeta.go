package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"artb/internal/avb"
	"artb/internal/cpu"
	"github.com/spf13/cobra"
)

func newVBMetaCommand() *cobra.Command {
	cmd := newGroupCommand("vbmeta", "Inspect, verify, sign and patch Android Verified Boot metadata", newVBMetaInfoCommand(), newVBMetaVerifyCommand(), newVBMetaSyncCommand(), newVBMetaSignCommand(), newVBMetaFlagsCommand(true), newVBMetaFlagsCommand(false))
	cmd.Long = `Read vbmeta.img, vbmeta_system.img or any partition image carrying an AVB footer, verify the dm-verity
hashtree, FEC or image hash of partition images, copy their footer descriptors into vbmeta images, re-sign
vbmeta with your own RSA key, and switch the verification flags that fastboot --disable-verity and
--disable-verification set.

Only the top-level vbmeta partition decides these flags on boot; flags in chained vbmeta images such as
vbmeta_system are ignored by the bootloader. Patching flags or descriptors invalidates the vbmeta signature,
which an unlocked bootloader accepts; a device that trusts your key (a user-settable root of trust) needs the
images re-signed with it. artb pack rebuilds the hashtree footer of modified partitions and updates the
digests in the workspace vbmeta images, so verity can stay enabled.`
	cmd.Example = "  artb vbmeta info vbmeta.img\n  artb vbmeta verify vendor.img\n  artb vbmeta sync vbmeta.img boot.img vendor_boot.img\n  artb vbmeta sign vbmeta.img --key rsa4096.pem --chain vbmeta_system\n  artb vbmeta disable vbmeta.img\n  artb vbmeta enable vbmeta.img --verification"
	return cmd
}

func newVBMetaVerifyCommand() *cobra.Command {
	var quiet bool
	cmd := &cobra.Command{Use: "verify <image>", Short: "Recompute the hashtree and FEC, or the image hash, of a partition image and compare them", Example: "  artb vbmeta verify vendor.img\n  artb vbmeta verify boot.img -q", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		path, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("resolve %q: %w", args[0], err)
		}
		started := time.Now()
		descriptor, err := avb.VerifyFooter(path, cpu.Logical())
		if err != nil || quiet {
			return err
		}
		text := fmt.Sprintf("%s\npartition %s\n", path, descriptor.Partition)
		if descriptor.Kind == "hash" {
			text += fmt.Sprintf("digest %s ok\n", descriptor.Digest)
		} else {
			fec := "none"
			if descriptor.FECRoots > 0 {
				fec = "ok"
			}
			text += fmt.Sprintf("root_digest %s ok\nhashtree ok\nfec %s\n", descriptor.Digest, fec)
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%selapsed %.3fs\n", text, time.Since(started).Seconds())
		return err
	}}
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress success output")
	return cmd
}

func newVBMetaSyncCommand() *cobra.Command {
	var keyPath string
	var quiet bool
	cmd := &cobra.Command{Use: "sync <vbmeta.img> <image>...", Short: "Copy the hashtree and hash descriptors of partition footers into a vbmeta image", Example: "  artb vbmeta sync vbmeta.img boot.img vendor_boot.img\n  artb vbmeta sync vbmeta_system.img system.img product.img --key rsa4096.pem", Args: cobra.MinimumNArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		paths := make([]string, len(args))
		for index, arg := range args {
			path, err := filepath.Abs(arg)
			if err != nil {
				return fmt.Errorf("resolve %q: %w", arg, err)
			}
			paths[index] = path
		}
		replacements := map[string][]byte{}
		for _, image := range paths[1:] {
			descriptors, err := avb.FooterDescriptors(image)
			if err != nil {
				return err
			}
			for name, descriptor := range descriptors {
				replacements[name] = descriptor
			}
		}
		replaced, err := avb.ReplaceDescriptors(paths[0], replacements)
		if err != nil {
			return err
		}
		for name := range replacements {
			if !slices.Contains(replaced.Matched, name) {
				return fmt.Errorf("%s has no %s descriptor", paths[0], name)
			}
		}
		if keyPath != "" {
			key, err := avb.LoadKey(keyPath)
			if err != nil {
				return err
			}
			if err = avb.SignFile(paths[0], "", key, nil); err != nil {
				return err
			}
		} else if replaced.StaleSignature {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s: the signature no longer matches the updated descriptors; flash it on an unlocked bootloader or pass --key\n", paths[0])
		}
		if quiet {
			return nil
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\nmatched %s\nupdated %s\n", paths[0], strings.Join(replaced.Matched, ","), strings.Join(replaced.Updated, ","))
		return err
	}}
	cmd.Flags().StringVar(&keyPath, "key", "", "Re-sign the vbmeta image with this RSA private key (PEM)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress success output")
	return cmd
}

func newVBMetaSignCommand() *cobra.Command {
	var keyPath, output, chain string
	var quiet bool
	cmd := &cobra.Command{Use: "sign <image> --key <key.pem>", Short: "Re-sign a vbmeta image or partition footer with an RSA key", Long: "Re-sign a vbmeta image or the footer vbmeta of a partition image. The algorithm follows the key size (2048, 4096 or 8192 bits) and keeps the SHA256 or SHA512 family of the original; --chain points the named chain descriptors at the new key.", Example: "  artb vbmeta sign vbmeta.img --key rsa4096.pem --chain vbmeta_system\n  artb vbmeta sign vbmeta_system.img --key rsa4096.pem -o vbmeta_system_signed.img", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		if keyPath == "" {
			return fmt.Errorf("--key is required")
		}
		path, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("resolve %q: %w", args[0], err)
		}
		target := path
		if output != "" {
			if target, err = filepath.Abs(output); err != nil {
				return fmt.Errorf("resolve %q: %w", output, err)
			}
		}
		key, err := avb.LoadKey(keyPath)
		if err != nil {
			return err
		}
		chains := map[string][]byte{}
		for _, name := range splitPartitions(chain) {
			chains[name] = avb.PublicKeyBlob(&key.PublicKey)
		}
		if err = avb.SignFile(path, target, key, chains); err != nil || quiet {
			return err
		}
		meta, err := avb.Read(target)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\nalgorithm %s\npublic_key_sha1 %s\n", target, meta.Algorithm, meta.PublicKeySHA1)
		return err
	}}
	cmd.Flags().StringVar(&keyPath, "key", "", "RSA private key (PEM, PKCS#1 or PKCS#8)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write the signed image here instead of signing in place")
	cmd.Flags().StringVar(&chain, "chain", "", "Comma-separated chain descriptors whose public key becomes the signing key")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress success output")
	return cmd
}

func newVBMetaInfoCommand() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{Use: "info <image>", Short: "Print vbmeta header, footer and descriptors", Example: "  artb vbmeta info vbmeta.img\n  artb vbmeta info boot.img --json", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		path, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("resolve %q: %w", args[0], err)
		}
		meta, err := avb.Read(path)
		if err != nil {
			return err
		}
		if jsonOutput {
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetEscapeHTML(false)
			return encoder.Encode(struct {
				Path string `json:"path"`
				*avb.VBMeta
			}{path, meta})
		}
		return writeVBMetaInfo(cmd.OutOrStdout(), path, meta)
	}}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Print JSON output")
	return cmd
}

func newVBMetaFlagsCommand(disable bool) *cobra.Command {
	var output string
	var verity, verification, quiet bool
	use, short, example := "disable <image>", "Disable dm-verity and verification (flags 1 and 2)", "  artb vbmeta disable vbmeta.img\n  artb vbmeta disable vbmeta.img --verity -o vbmeta_noverity.img"
	if !disable {
		use, short, example = "enable <image>", "Re-enable dm-verity and verification", "  artb vbmeta enable vbmeta.img\n  artb vbmeta enable vbmeta.img --verification"
	}
	cmd := &cobra.Command{Use: use, Short: short, Long: short + ". Without --verity or --verification both flags change. The image is patched in place unless -o is given.", Example: example, Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		path, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("resolve %q: %w", args[0], err)
		}
		target := path
		if output != "" {
			if target, err = filepath.Abs(output); err != nil {
				return fmt.Errorf("resolve %q: %w", output, err)
			}
		}
		var mask uint32
		if verity {
			mask |= avb.FlagHashtreeDisabled
		}
		if verification {
			mask |= avb.FlagVerificationDisabled
		}
		if mask == 0 {
			mask = avb.FlagHashtreeDisabled | avb.FlagVerificationDisabled
		}
		set, clear := mask, uint32(0)
		if !disable {
			set, clear = 0, mask
		}
		before, after, err := avb.SetFlags(path, target, set, clear)
		if err != nil {
			return err
		}
		if quiet {
			return nil
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\nflags %d -> %d\nverity %s\nverification %s\n", target, before, after, flagState(after, avb.FlagHashtreeDisabled), flagState(after, avb.FlagVerificationDisabled))
		return err
	}}
	cmd.Flags().BoolVar(&verity, "verity", false, "Only change the dm-verity (hashtree) flag")
	cmd.Flags().BoolVar(&verification, "verification", false, "Only change the verification flag")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write the patched image here instead of patching in place")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress success output")
	return cmd
}

func flagState(flags, bit uint32) string {
	if flags&bit != 0 {
		return "disabled"
	}
	return "enabled"
}

func writeVBMetaInfo(out io.Writer, path string, meta *avb.VBMeta) error {
	hash := "unchecked"
	if meta.HashMatches != nil {
		hash = "mismatch"
		if *meta.HashMatches {
			hash = "ok"
		}
	}
	text := fmt.Sprintf("path %s\n", path)
	if meta.Footer != nil {
		text += fmt.Sprintf("footer original_image_size=%d vbmeta_offset=%d vbmeta_size=%d\n", meta.Footer.OriginalImageSize, meta.Footer.VBMetaOffset, meta.Footer.VBMetaSize)
	}
	signature := "none"
	if meta.SignatureValid != nil {
		signature = "mismatch"
		if *meta.SignatureValid {
			signature = "ok"
		}
	}
	text += fmt.Sprintf("libavb %d.%d\nalgorithm %s\nrollback_index %d\nrollback_index_location %d\nflags %d\nverity %s\nverification %s\nrelease %s\npublic_key_sha1 %s\nhash %s\nsignature %s\n", meta.VersionMajor, meta.VersionMinor, meta.Algorithm, meta.RollbackIndex, meta.RollbackIndexLocation, meta.Flags, flagState(meta.Flags, avb.FlagHashtreeDisabled), flagState(meta.Flags, avb.FlagVerificationDisabled), meta.Release, meta.PublicKeySHA1, hash, signature)
	for _, descriptor := range meta.Descriptors {
		switch descriptor.Kind {
		case "hash":
			text += fmt.Sprintf("descriptor hash %s image_size=%d algorithm=%s flags=%d salt=%s digest=%s\n", descriptor.Partition, descriptor.ImageSize, descriptor.HashAlgorithm, descriptor.Flags, descriptor.Salt, descriptor.Digest)
		case "hashtree":
			text += fmt.Sprintf("descriptor hashtree %s image_size=%d tree_offset=%d tree_size=%d data_block=%d hash_block=%d fec_roots=%d fec_offset=%d fec_size=%d algorithm=%s flags=%d salt=%s root_digest=%s\n", descriptor.Partition, descriptor.ImageSize, descriptor.TreeOffset, descriptor.TreeSize, descriptor.DataBlockSize, descriptor.HashBlockSize, descriptor.FECRoots, descriptor.FECOffset, descriptor.FECSize, descriptor.HashAlgorithm, descriptor.Flags, descriptor.Salt, descriptor.Digest)
		case "chain":
			text += fmt.Sprintf("descriptor chain %s rollback_index_location=%d flags=%d public_key_sha1=%s\n", descriptor.Partition, descriptor.RollbackIndexLocation, descriptor.Flags, descriptor.PublicKeySHA1)
		case "property":
			text += fmt.Sprintf("descriptor property %s=%s\n", descriptor.Key, descriptor.Value)
		case "cmdline":
			text += fmt.Sprintf("descriptor cmdline flags=%d %s\n", descriptor.Flags, descriptor.Cmdline)
		default:
			text += fmt.Sprintf("descriptor unknown tag=%d\n", descriptor.Tag)
		}
	}
	_, err := io.WriteString(out, text)
	return err
}
