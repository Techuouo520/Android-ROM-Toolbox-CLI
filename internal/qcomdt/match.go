// Package qcomdt repeats how Qualcomm's ABL (QcomModulePkg LocateDeviceTree.c) scores device trees against a board.
package qcomdt

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"strings"

	"artb/internal/fdt"
)

// Bit positions of the ABL DTMATCH_PARAMS enum; a higher DtMatchVal wins.
const (
	noneMatch              = 0
	oemFlavorDefaultMatch  = 1
	oemFlavorExactMatch    = 2
	pmicBestRevIdx0        = 3
	pmicExactRevIdx0       = 4
	variantMinorBestMatch  = 11
	variantMinorExactMatch = 12
	variantMajorBestMatch  = 13
	variantMajorExactMatch = 14
	versionBestMatch       = 15
	versionExactMatch      = 16
	foundryDefaultMatch    = 17
	foundryExactMatch      = 18
	pmicDefaultModelIdx0   = 19
	pmicExactModelIdx0     = 20
	softSKUExactMatch      = 51
	hlosSubtypeExactMatch  = 52
	subtypeDefaultMatch    = 53
	subtypeExactMatch      = 54
	ddrMatch               = 55
	VariantMatch           = 56
	SocMatch               = 57
	packageDefaultMatch    = 58
	packageExactMatch      = 59
)

const (
	socMask            = 0xffff
	foundryMask        = 0x00ff0000
	packageMask        = 0x03000000
	softSKUMask        = 0x3c000000
	variantMask        = 0xff
	variantMinorMask   = 0xff00
	variantMajorMask   = 0xff0000
	subtypeMask        = 0xff
	ddrMask            = 0x700
	pmicModelMask      = 0xff
	pmicRevMask        = 0xffffff00
	maxPmic            = 15
	defaultPmicEntries = 4
)

var bitNames = map[int]string{oemFlavorDefaultMatch: "oem-default", oemFlavorExactMatch: "oem-exact", variantMinorBestMatch: "variant-minor-best", variantMinorExactMatch: "variant-minor-exact", variantMajorBestMatch: "variant-major-best", variantMajorExactMatch: "variant-major-exact", versionBestMatch: "soc-rev-best", versionExactMatch: "soc-rev-exact", foundryDefaultMatch: "foundry-default", foundryExactMatch: "foundry-exact", softSKUExactMatch: "softsku-exact", hlosSubtypeExactMatch: "hlos-subtype-exact", subtypeDefaultMatch: "subtype-default", subtypeExactMatch: "subtype-exact", ddrMatch: "ddr", VariantMatch: "variant", SocMatch: "soc", packageDefaultMatch: "package-default", packageExactMatch: "package-exact"}

// allBits is ABL's ALL_BITS_SET: a base tree scoring all of them makes the DTBO search unnecessary.
var allBits = func() uint64 {
	value := uint64(1)<<SocMatch | 1<<VariantMatch | 1<<subtypeExactMatch | 1<<foundryExactMatch | 1<<packageExactMatch | 1<<softSKUExactMatch
	for index := range 16 {
		value |= 1 << (pmicExactModelIdx0 + 2*index)
	}
	return value
}()

// Board is what ABL reads from SMEM; PMIC entries are model | revision as stored in qcom,pmic-id.
type Board struct {
	ChipID          uint32   `json:"chip_id"`
	SocRev          uint32   `json:"soc_rev"`
	FoundryID       uint32   `json:"foundry_id"`
	PackageID       uint32   `json:"package_id"`
	PlatformType    uint32   `json:"platform_type"`
	PlatformSubtype uint32   `json:"platform_subtype"`
	HlosSubtype     uint32   `json:"hlos_subtype"`
	TargetID        uint32   `json:"target_id"`
	SoftSKU         uint32   `json:"softsku_id"`
	OEMVariant      uint32   `json:"oem_variant_id"`
	Pmic            []uint32 `json:"pmic,omitempty"`
}

func (board Board) pmic(index int) uint32 {
	if index < len(board.Pmic) {
		return board.Pmic[index]
	}
	return 0
}

// Score is the ABL DtInfo of one tree.
type Score struct {
	MatchVal        uint64   `json:"match_value"`
	Bits            []string `json:"bits"`
	Reason          string   `json:"reason,omitempty"`
	PlatformID      uint32   `json:"platform_id"`
	SocRev          uint32   `json:"soc_rev"`
	VariantMajor    uint32   `json:"variant_major"`
	VariantMinor    uint32   `json:"variant_minor"`
	PlatformSubtype uint32   `json:"platform_subtype"`
	OEMVariant      uint32   `json:"oem_variant_id"`
	SoftSKU         uint32   `json:"softsku_id"`
	PmicRev         [maxPmic]uint32
}

func cells(node *fdt.Node, name string) ([]uint32, bool) {
	property := node.Property(name)
	if property == nil {
		return nil, false
	}
	return property.Cells(), true
}

// platform scores one qcom,msm-id pair as GetPlatformMatchDtb does.
func platform(score *Score, board Board, platformID, socRev uint32) bool {
	score.PlatformID, score.SocRev = platformID, socRev
	if board.ChipID&socMask != platformID&socMask {
		score.MatchVal, score.Reason = 1<<noneMatch, fmt.Sprintf("msm-id 0x%x is not chip 0x%x", platformID&socMask, board.ChipID&socMask)
		return false
	}
	score.MatchVal |= 1 << SocMatch
	switch {
	case socRev == board.SocRev:
		score.MatchVal |= 1 << versionExactMatch
	case socRev < board.SocRev:
		score.MatchVal |= 1 << versionBestMatch
	}
	switch foundry := platformID & foundryMask; foundry {
	case board.FoundryID << 16:
		score.MatchVal |= 1 << foundryExactMatch
	case 0:
		score.MatchVal |= 1 << foundryDefaultMatch
	default:
		score.MatchVal, score.Reason = 1<<noneMatch, fmt.Sprintf("foundry 0x%x differs", foundry>>16)
		return false
	}
	switch pkg := platformID & packageMask; pkg {
	case (board.PackageID & 1) << 24:
		score.MatchVal |= 1 << packageExactMatch
	case 0:
		score.MatchVal |= 1 << packageDefaultMatch
	default:
		score.MatchVal, score.Reason = 1<<noneMatch, fmt.Sprintf("package 0x%x differs", pkg>>24)
		return false
	}
	return true
}

func bestPmic(entries []uint32, size int, board Board) (uint64, [maxPmic]uint32, [maxPmic]uint32) {
	var bestVal uint64
	var bestModel, bestRev [maxPmic]uint32
	for start := 0; start+size <= len(entries); start += size {
		var value uint64
		var model, rev [maxPmic]uint32
		for index := range size {
			model[index], rev[index] = entries[start+index]&pmicModelMask, entries[start+index]&pmicRevMask
			switch {
			case model[index] == board.pmic(index)&pmicModelMask:
				value |= 1 << (pmicExactModelIdx0 + 2*index)
			case model[index] == 0:
				value |= 1 << (pmicDefaultModelIdx0 + 2*index)
			default:
				value = 1 << noneMatch
			}
			if value == 1<<noneMatch {
				break
			}
			if index < defaultPmicEntries {
				if rev[index] == board.pmic(index)&pmicRevMask {
					value |= 1 << (pmicExactRevIdx0 + 2*index)
				} else if rev[index] < board.pmic(index)&pmicRevMask {
					value |= 1 << (pmicBestRevIdx0 + 2*index)
				} else {
					break
				}
			}
		}
		if bestVal < value {
			bestVal, bestModel, bestRev = value, model, rev
		} else if bestVal == value {
			for index := range size {
				if bestRev[index] < rev[index] {
					bestModel, bestRev = model, rev
				}
			}
		}
	}
	return bestVal, bestModel, bestRev
}

// Evaluate scores one tree like ReadDtbFindMatch, without the best-tree bookkeeping.
func Evaluate(tree *fdt.Tree, board Board) Score {
	root := tree.Root
	score := Score{}
	msm, hasMSM := cells(root, "qcom,msm-id")
	if hasMSM && len(msm) > 0 && len(msm)%2 == 0 {
		best := Score{}
		for index := 0; index < len(msm); index += 2 {
			current := Score{}
			if platform(&current, board, msm[index], msm[index+1]) && current.MatchVal > best.MatchVal {
				best = current
			}
			if current.Reason != "" && best.Reason == "" && best.MatchVal == 0 {
				best.Reason = current.Reason
			}
		}
		score = best
		if score.MatchVal == noneMatch {
			return finish(score)
		}
		score.Reason = ""
	}
	if boardID, ok := cells(root, "qcom,board-id"); ok && len(boardID) > 0 && len(boardID)%2 == 0 {
		variant, subtype := boardID[0], boardID[1]
		if subtype == 0 {
			subtype = variant >> 24
		}
		score.PlatformSubtype = subtype
		score.VariantMajor, score.VariantMinor = variant&variantMajorMask, variant&variantMinorMask
		switch id := variant & variantMask; {
		case id == board.PlatformType:
			score.MatchVal |= 1 << VariantMatch
		case id != 0:
			score.MatchVal, score.Reason = 1<<noneMatch, fmt.Sprintf("board-id platform type %d is not %d", id, board.PlatformType)
			return finish(score)
		}
		switch target := board.TargetID & variantMajorMask; {
		case score.VariantMajor == target:
			score.MatchVal |= 1 << variantMajorExactMatch
		case score.VariantMajor < target:
			score.MatchVal |= 1 << variantMajorBestMatch
		}
		switch target := board.TargetID & variantMinorMask; {
		case score.VariantMinor == target:
			score.MatchVal |= 1 << variantMinorExactMatch
		case score.VariantMinor < target:
			score.MatchVal |= 1 << variantMinorBestMatch
		}
		if subtype == board.HlosSubtype {
			score.MatchVal |= 1 << hlosSubtypeExactMatch
		}
		switch subtype & subtypeMask {
		case board.PlatformSubtype:
			score.MatchVal |= 1 << subtypeExactMatch
		case 0:
			score.MatchVal |= 1 << subtypeDefaultMatch
		default:
			score.MatchVal, score.Reason = 1<<noneMatch, fmt.Sprintf("board-id subtype %d is not %d", subtype&subtypeMask, board.PlatformSubtype)
			return finish(score)
		}
		if subtype&ddrMask == board.HlosSubtype&ddrMask {
			score.MatchVal |= 1 << ddrMatch
		}
	}
	if sku, ok := cells(root, "qcom,softsku-id"); ok && len(sku) > 0 {
		score.SoftSKU = sku[0]
	} else if hasMSM && len(msm) > 0 {
		score.SoftSKU = (msm[0] & softSKUMask) >> 26
	}
	if score.SoftSKU == board.SoftSKU {
		score.MatchVal |= 1 << softSKUExactMatch
	}
	if pmic, ok := cells(root, "qcom,pmic-id"); ok && len(pmic) > 0 {
		size := defaultPmicEntries
		if sizes, ok := cells(root, "qcom,pmic-id-size"); ok && len(sizes) > 0 {
			size = int(min(sizes[0], maxPmic))
		}
		if size == 0 || len(pmic)%size != 0 {
			score.Reason = "qcom,pmic-id length is not a multiple of qcom,pmic-id-size"
			return finish(score)
		}
		value, _, rev := bestPmic(pmic, size, board)
		score.MatchVal |= value
		score.PmicRev = rev
	}
	if board.OEMVariant != 0 {
		if property := root.Property("qcom,oem-id"); property != nil && len(property.Value) >= 4 {
			score.OEMVariant = binary.BigEndian.Uint32(property.Value)
			if score.OEMVariant == board.OEMVariant {
				score.MatchVal |= 1 << oemFlavorExactMatch
			} else {
				score.MatchVal |= 1 << noneMatch
			}
		} else {
			score.MatchVal |= 1 << oemFlavorDefaultMatch
		}
	}
	return finish(score)
}

func finish(score Score) Score {
	for bit := 1; bit < 64; bit++ {
		if score.MatchVal&(1<<bit) == 0 {
			continue
		}
		if name, ok := bitNames[bit]; ok {
			score.Bits = append(score.Bits, name)
		} else if bit >= pmicDefaultModelIdx0 && bit < softSKUExactMatch {
			kind := "default"
			if (bit-pmicDefaultModelIdx0)%2 == 1 {
				kind = "exact"
			}
			score.Bits = append(score.Bits, fmt.Sprintf("pmic%d-model-%s", (bit-pmicDefaultModelIdx0)/2, kind))
		} else if bit >= pmicBestRevIdx0 && bit < variantMinorBestMatch {
			kind := "best"
			if (bit-pmicBestRevIdx0)%2 == 1 {
				kind = "exact"
			}
			score.Bits = append(score.Bits, fmt.Sprintf("pmic%d-rev-%s", (bit-pmicBestRevIdx0)/2, kind))
		}
	}
	return score
}

// AllBitsSet reports whether a base tree matched so completely that ABL skips the DTBO search.
func (score Score) AllBitsSet() bool { return score.MatchVal&allBits == allBits }

// better repeats the cleanup block of ReadDtbFindMatch: equal scores switch when any else-if condition holds, in order.
func better(best, current Score) bool {
	if best.MatchVal != current.MatchVal {
		return best.MatchVal < current.MatchVal
	}
	return best.SocRev < current.SocRev || best.VariantMajor < current.VariantMajor || best.VariantMinor < current.VariantMinor || best.PmicRev[0] < current.PmicRev[0] || best.PmicRev[1] < current.PmicRev[1] || best.PmicRev[2] < current.PmicRev[2] || best.PmicRev[3] < current.PmicRev[3] || best.PlatformSubtype > current.PlatformSubtype || best.OEMVariant < current.OEMVariant || best.SoftSKU > current.SoftSKU
}

func sameRank(a, b Score) bool {
	return a.MatchVal == b.MatchVal && a.SocRev == b.SocRev && a.VariantMajor == b.VariantMajor && a.VariantMinor == b.VariantMinor && a.PmicRev == b.PmicRev && a.PlatformSubtype == b.PlatformSubtype && a.OEMVariant == b.OEMVariant && a.SoftSKU == b.SoftSKU
}

// Select walks scores in image order like GetSocDtb (required SocMatch) or GetBoardDtb (VariantMatch); ties keep the first.
func Select(scores []Score, required int) (int, []int) {
	best := -1
	for index, score := range scores {
		if score.MatchVal&(1<<required) == 0 {
			continue
		}
		if best < 0 || better(scores[best], score) {
			best = index
		}
	}
	var ties []int
	for index, score := range scores {
		if best >= 0 && index != best && score.MatchVal&(1<<required) != 0 && sameRank(scores[best], score) {
			ties = append(ties, index)
		}
	}
	return best, ties
}

// BitCount is the number of matched criteria, handy for showing how close a tree came.
func (score Score) BitCount() int { return bits.OnesCount64(score.MatchVal) }

// Describe joins the matched bit names.
func (score Score) Describe() string {
	if len(score.Bits) == 0 {
		return "none"
	}
	return strings.Join(score.Bits, ",")
}
