package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"artb/internal/buildinfo"
	"artb/internal/fdt"
	"artb/internal/nativebin"
	"artb/internal/qcomdt"

	"github.com/spf13/cobra"
)

// boardFlags collects the SMEM values ABL compares; unset values are 0 as on boards that do not report them.
type boardFlags struct {
	msmID, rev, platformType, platformVersion, subtype, hlosSubtype, foundry, pkg, softsku, oem, pmic, miboard string
}

func (flags *boardFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flags.msmID, "msm-id", "", "SoC id, as in /sys/devices/soc0/soc_id (for example 519 or 0x207)")
	cmd.Flags().StringVar(&flags.rev, "rev", "", "SoC revision as major.minor or raw value (for example 2.0 or 0x20000)")
	cmd.Flags().StringVar(&flags.platformType, "platform-type", "", "Hardware platform: a number or CDP, MTP, QRD, RUMI, RCM, HDK, ATP")
	cmd.Flags().StringVar(&flags.platformVersion, "platform-version", "", "Platform version as major.minor, compared with qcom,board-id")
	cmd.Flags().StringVar(&flags.subtype, "platform-subtype", "", "Platform subtype")
	cmd.Flags().StringVar(&flags.hlosSubtype, "hlos-subtype", "", "HLOS subtype with DDR bits 10:8 (default: the platform subtype)")
	cmd.Flags().StringVar(&flags.foundry, "foundry", "", "Foundry id")
	cmd.Flags().StringVar(&flags.pkg, "package", "", "Package id")
	cmd.Flags().StringVar(&flags.softsku, "softsku", "", "Soft SKU id")
	cmd.Flags().StringVar(&flags.oem, "oem-variant", "", "OEM variant id matched against qcom,oem-id")
	cmd.Flags().StringVar(&flags.pmic, "pmic", "", "Comma-separated PMIC values (model | revision) in qcom,pmic-id order")
	cmd.Flags().StringVar(&flags.miboard, "miboard-id", "", "Xiaomi only: keep overlays whose xiaomi,miboard-id starts with this value")
}

var platformNames = map[string]uint32{"cdp": 1, "surf": 1, "mtp": 8, "qrd": 11, "rumi": 15, "rcm": 21, "hdk": 31, "atp": 33}

func parseNumber(name, text string) (uint32, error) {
	if text == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(text, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("--%s %q is not a number", name, text)
	}
	return uint32(value), nil
}

// parseVersion turns major.minor into (major<<majorShift)|(minor<<minorShift) and passes raw numbers through.
func parseVersion(name, text string, majorShift, minorShift uint) (uint32, error) {
	major, minor, dotted := strings.Cut(text, ".")
	if !dotted {
		return parseNumber(name, text)
	}
	high, err := parseNumber(name, major)
	if err != nil {
		return 0, err
	}
	low, err := parseNumber(name, minor)
	if err != nil {
		return 0, err
	}
	return high<<majorShift | low<<minorShift, nil
}

func (flags *boardFlags) board() (qcomdt.Board, error) {
	var board qcomdt.Board
	var err error
	if flags.msmID == "" {
		return board, errors.New("pass --msm-id (and usually --rev) to describe the board")
	}
	for _, field := range []struct {
		name, text string
		target     *uint32
	}{{"msm-id", flags.msmID, &board.ChipID}, {"platform-subtype", flags.subtype, &board.PlatformSubtype}, {"foundry", flags.foundry, &board.FoundryID}, {"package", flags.pkg, &board.PackageID}, {"softsku", flags.softsku, &board.SoftSKU}, {"oem-variant", flags.oem, &board.OEMVariant}} {
		if *field.target, err = parseNumber(field.name, field.text); err != nil {
			return board, err
		}
	}
	if board.SocRev, err = parseVersion("rev", flags.rev, 16, 0); err != nil {
		return board, err
	}
	if board.TargetID, err = parseVersion("platform-version", flags.platformVersion, 16, 8); err != nil {
		return board, err
	}
	if id, ok := platformNames[strings.ToLower(flags.platformType)]; ok {
		board.PlatformType = id
	} else if board.PlatformType, err = parseNumber("platform-type", flags.platformType); err != nil {
		return board, err
	}
	board.HlosSubtype = board.PlatformSubtype
	if flags.hlosSubtype != "" {
		if board.HlosSubtype, err = parseNumber("hlos-subtype", flags.hlosSubtype); err != nil {
			return board, err
		}
	}
	if flags.pmic != "" {
		for _, field := range strings.Split(flags.pmic, ",") {
			value, err := parseNumber("pmic", strings.TrimSpace(field))
			if err != nil {
				return board, err
			}
			board.Pmic = append(board.Pmic, value)
		}
	}
	return board, nil
}

type matchCandidate struct {
	Index int          `json:"index"`
	Model string       `json:"model,omitempty"`
	Score qcomdt.Score `json:"score"`
}

type matchResult struct {
	Board       qcomdt.Board     `json:"board"`
	Trees       []matchCandidate `json:"trees"`
	Tree        int              `json:"selected_tree"`
	TreeTies    []int            `json:"tree_ties,omitempty"`
	DTBONeeded  bool             `json:"dtbo_needed"`
	Entries     []matchCandidate `json:"dtbo_entries,omitempty"`
	Entry       int              `json:"selected_entry"`
	EntryTies   []int            `json:"entry_ties,omitempty"`
	baseImage   *deviceTreeImage
	dtboImage   *deviceTreeImage
	miboardSkip int
}

func scoreTrees(image *deviceTreeImage, board qcomdt.Board, miboard string) ([]matchCandidate, []qcomdt.Score, int, error) {
	var filter uint32
	var err error
	if miboard != "" {
		if filter, err = parseNumber("miboard-id", miboard); err != nil {
			return nil, nil, 0, err
		}
	}
	skipped := 0
	var candidates []matchCandidate
	var scores []qcomdt.Score
	for _, tree := range image.trees {
		score := qcomdt.Evaluate(tree.Tree, board)
		if miboard != "" {
			if property := tree.Tree.Root.Property("xiaomi,miboard-id"); property != nil {
				if cells := property.Cells(); len(cells) > 0 && cells[0] != filter {
					score = qcomdt.Score{Reason: fmt.Sprintf("xiaomi,miboard-id 0x%x is not 0x%x", cells[0], filter)}
					skipped++
				}
			}
		}
		candidates = append(candidates, matchCandidate{Index: tree.Index, Model: tree.Tree.Summarize().Model, Score: score})
		scores = append(scores, score)
	}
	return candidates, scores, skipped, nil
}

// matchBoard picks the base tree and, when dtboPath is given, the DTBO overlay ABL would use for board.
func matchBoard(imagePath, dtboPath string, board qcomdt.Board, miboard string) (*matchResult, error) {
	image, err := loadDeviceTreeImage(imagePath)
	if err != nil {
		return nil, err
	}
	if len(image.trees) == 0 {
		return nil, fmt.Errorf("%s holds no device trees", imagePath)
	}
	result := &matchResult{Board: board, Entry: -1, baseImage: image}
	candidates, scores, _, err := scoreTrees(image, board, "")
	if err != nil {
		return nil, err
	}
	result.Trees = candidates
	result.Tree, result.TreeTies = qcomdt.Select(scores, qcomdt.SocMatch)
	result.DTBONeeded = result.Tree < 0 || !scores[result.Tree].AllBitsSet()
	if dtboPath == "" {
		return result, nil
	}
	if result.dtboImage, err = loadDeviceTreeImage(dtboPath); err != nil {
		return nil, err
	}
	if result.Entries, scores, result.miboardSkip, err = scoreTrees(result.dtboImage, board, miboard); err != nil {
		return nil, err
	}
	result.Entry, result.EntryTies = qcomdt.Select(scores, qcomdt.VariantMatch)
	return result, nil
}

func printCandidates(builder *strings.Builder, label string, candidates []matchCandidate, required int) {
	rejected := 0
	for _, candidate := range candidates {
		if candidate.Score.MatchVal&(1<<required) == 0 {
			rejected++
			continue
		}
		fmt.Fprintf(builder, "%s %02d score=0x%x bits=%s model=%q\n", label, candidate.Index, candidate.Score.MatchVal, candidate.Score.Describe(), candidate.Model)
	}
	if rejected > 0 {
		fmt.Fprintf(builder, "%s rejected %d of %d\n", label, rejected, len(candidates))
	}
}

func printMatch(out io.Writer, result *matchResult, showRejected bool) error {
	var builder strings.Builder
	board := result.Board
	fmt.Fprintf(&builder, "board msm_id=0x%x soc_rev=0x%x platform_type=%d platform_version=0x%x platform_subtype=%d foundry=%d package=%d\n", board.ChipID, board.SocRev, board.PlatformType, board.TargetID, board.PlatformSubtype, board.FoundryID, board.PackageID)
	printCandidates(&builder, "tree", result.Trees, qcomdt.SocMatch)
	if showRejected {
		for _, candidate := range result.Trees {
			if candidate.Score.MatchVal&(1<<qcomdt.SocMatch) == 0 {
				fmt.Fprintf(&builder, "tree %02d rejected: %s model=%q\n", candidate.Index, candidate.Score.Reason, candidate.Model)
			}
		}
	}
	if result.Tree < 0 {
		builder.WriteString("selected tree none: no base tree matches this SoC\n")
	} else {
		fmt.Fprintf(&builder, "selected tree %02d model=%q\n", result.Tree, result.Trees[result.Tree].Model)
	}
	for _, tie := range result.TreeTies {
		fmt.Fprintf(&builder, "tie tree %02d scores the same; ABL keeps the earlier tree\n", tie)
	}
	if result.dtboImage != nil {
		printCandidates(&builder, "entry", result.Entries, qcomdt.VariantMatch)
		if showRejected {
			for _, candidate := range result.Entries {
				if candidate.Score.MatchVal&(1<<qcomdt.VariantMatch) == 0 {
					reason := candidate.Score.Reason
					if reason == "" {
						reason = "no board-id platform type match"
					}
					fmt.Fprintf(&builder, "entry %02d rejected: %s model=%q\n", candidate.Index, reason, candidate.Model)
				}
			}
		}
		switch {
		case !result.DTBONeeded:
			builder.WriteString("selected entry none: the base tree matched every criterion, so ABL skips the DTBO search\n")
		case result.Entry < 0:
			builder.WriteString("selected entry none: no overlay matches this board (check --platform-type)\n")
		default:
			fmt.Fprintf(&builder, "selected entry %02d model=%q\n", result.Entry, result.Entries[result.Entry].Model)
		}
		for _, tie := range result.EntryTies {
			fmt.Fprintf(&builder, "tie entry %02d scores the same; stock ABL keeps the earlier entry, OEM bootloaders may use extra ids such as xiaomi,miboard-id (--miboard-id)\n", tie)
		}
		if result.miboardSkip > 0 {
			fmt.Fprintf(&builder, "miboard-id filter dropped %d entries\n", result.miboardSkip)
		}
	}
	_, err := io.WriteString(out, builder.String())
	return err
}

func newDTBMatchCommand() *cobra.Command {
	var flags boardFlags
	var dtboPath string
	var jsonOutput, showRejected bool
	cmd := &cobra.Command{Use: "match <image> --msm-id <id> --rev <rev>", Short: "Show which base tree and DTBO overlay the Qualcomm bootloader selects", Long: "Work out which base device tree and which DTBO overlay a Qualcomm bootloader (ABL) picks.\n\nProperties compared:\n  qcom,msm-id    SoC id, revision, foundry and package\n  qcom,board-id  platform type, version and subtype\n  qcom,pmic-id and qcom,oem-id\n\nA base tree needs a SoC match; an overlay also needs a platform type match.\nThe highest score wins. On equal scores ABL prefers, in order:\n  the higher SoC revision\n  the higher board major and minor version\n  the higher PMIC revisions\n  the lower platform subtype\n  the higher OEM variant\n  the lower soft SKU\nOnly candidates equal in all of these keep the earlier one.\n\nValues the board does not report count as 0.\nOn a phone, /sys/devices/soc0/soc_id and revision give --msm-id and --rev.\nVendor bootloaders may compare ids of their own, so equal candidates are listed.\nOn Xiaomi phones --miboard-id filters by xiaomi,miboard-id.\n\nWhen nothing matches, the result is still printed and the exit status is 1.", Example: "  artb dtb match vendor_boot.img --msm-id 519 --rev 2.0\n  artb dtb match vendor_boot.img --msm-id 0x207 --rev 2.0 --dtbo dtbo.img --platform-type MTP --platform-version 1.0 --miboard-id 2", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		board, err := flags.board()
		if err != nil {
			return err
		}
		path, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		if dtboPath != "" {
			if dtboPath, err = filepath.Abs(dtboPath); err != nil {
				return err
			}
		}
		result, err := matchBoard(path, dtboPath, board, flags.miboard)
		if err != nil {
			return err
		}
		if jsonOutput {
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetEscapeHTML(false)
			err = encoder.Encode(result)
		} else {
			err = printMatch(cmd.OutOrStdout(), result, showRejected)
		}
		switch {
		case err != nil:
			return err
		case result.Tree < 0:
			return errors.New("no base tree matches this board")
		case result.dtboImage != nil && result.DTBONeeded && result.Entry < 0:
			return errors.New("no DTBO overlay matches this board")
		}
		return nil
	}}
	flags.register(cmd)
	cmd.Flags().StringVar(&dtboPath, "dtbo", "", "Also pick the overlay from this DTBO image")
	cmd.Flags().BoolVar(&showRejected, "rejected", false, "Also list trees that cannot match and why")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Print JSON output")
	return cmd
}

func newDTBOApplyCommand() *cobra.Command {
	var flags boardFlags
	var output string
	var tree, entry int
	var quiet, force bool
	cmd := &cobra.Command{Use: "apply <base-image> <dtbo.img>", Short: "Merge the selected DTBO overlay into its base tree and write the effective DTS", Long: "Merge one DTBO overlay into a base device tree to get the tree the kernel actually boots with.\n\nThe merge follows libufdt, which Qualcomm's ABL uses:\n  overlay phandles are renumbered above the base tree;\n  __fixups__ and __local_fixups__ are resolved through the base __symbols__;\n  every fragment is merged into its target or target-path.\nAs with libufdt, properties on the overlay root (such as model and qcom,board-id) and overlay labels do not reach the result.\n\nThe base image is a dtb, boot or vendor_boot image.\nName the pair with --tree and --entry, or give the artb dtb match board options to let the ABL rules pick.\n\nThe output is DTS decompiled with dtc, or a binary when -o ends in .dtb.\nThe inputs are never modified; an existing output needs --force.", Example: "  artb dtbo apply vendor_boot.img dtbo.img --tree 2 --entry 3 -o fuxi.dts\n  artb dtbo apply vendor_boot.img dtbo.img --msm-id 519 --rev 2.0 --platform-type MTP --platform-version 1.0 --miboard-id 2", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		var paths [2]string
		for index, arg := range args {
			path, err := filepath.Abs(arg)
			if err != nil {
				return err
			}
			paths[index] = path
		}
		var base, overlay *deviceTree
		if tree >= 0 && entry >= 0 {
			baseImage, err := loadDeviceTreeImage(paths[0])
			if err != nil {
				return err
			}
			dtboImage, err := loadDeviceTreeImage(paths[1])
			if err != nil {
				return err
			}
			selected, err := baseImage.selectTrees([]int{tree})
			if err != nil {
				return err
			}
			overlays, err := dtboImage.selectTrees([]int{entry})
			if err != nil {
				return err
			}
			base, overlay = selected[0], overlays[0]
		} else {
			board, err := flags.board()
			if err != nil {
				return fmt.Errorf("pass --tree and --entry, or describe the board: %w", err)
			}
			result, err := matchBoard(paths[0], paths[1], board, flags.miboard)
			if err != nil {
				return err
			}
			if result.Tree < 0 || result.Entry < 0 {
				return errors.New("the board matches no base tree and overlay pair; run artb dtb match --rejected to see why")
			}
			base, overlay = result.baseImage.trees[result.Tree], result.dtboImage.trees[result.Entry]
			if len(result.EntryTies) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "entries %v score the same as entry %d; stock ABL keeps entry %d\n", result.EntryTies, result.Entry, result.Entry)
			}
		}
		merged, err := fdt.ApplyOverlay(base.Tree, overlay.Tree)
		if err != nil {
			return fmt.Errorf("apply entry %d to tree %d: %w", overlay.Index, base.Index, err)
		}
		blob := merged.Encode(fdt.MemReserve(base.Blob))
		if output == "" {
			output = fmt.Sprintf("%s_tree%02d_entry%02d.dts", strings.TrimSuffix(paths[0], filepath.Ext(paths[0])), base.Index, overlay.Index)
		}
		if output, err = filepath.Abs(output); err != nil {
			return err
		}
		if err = checkOutput(output, force, paths[:]...); err != nil {
			return err
		}
		data := blob
		if !strings.EqualFold(filepath.Ext(output), ".dtb") {
			executable, err := nativebin.New(buildinfo.Version).Ensure(cmd.Context(), "dtc")
			if err != nil {
				return err
			}
			if data, err = runDTC(cmd.Context(), executable, filepath.Dir(output), blob, "-I", "dtb", "-O", "dts", "-q"); err != nil {
				return err
			}
		}
		if err = os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
			return err
		}
		if err = os.WriteFile(output, data, 0o644); err != nil {
			return err
		}
		if quiet {
			return nil
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\nbase tree %02d model=%q\noverlay entry %02d model=%q\n", output, base.Index, base.Tree.Summarize().Model, overlay.Index, overlay.Tree.Summarize().Model)
		return err
	}}
	flags.register(cmd)
	cmd.Flags().IntVar(&tree, "tree", -1, "Base tree index (with --entry, skips board matching)")
	cmd.Flags().IntVar(&entry, "entry", -1, "DTBO entry index (with --tree, skips board matching)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file; .dtb writes a binary, anything else DTS (default: <base>_treeNN_entryNN.dts)")
	cmd.Flags().BoolVar(&force, "force", false, "Replace the output file if it already exists")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress success output")
	return cmd
}
