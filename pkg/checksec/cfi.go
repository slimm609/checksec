package checksec

import (
	"debug/elf"
	"encoding/binary"
)

type x86CET struct {
	shstk bool
	ibt   bool
}

type armPACBTI struct {
	pac bool
	bti bool
}

type riscvCFI struct {
	lp bool // Zicfilp landing pads
	ss bool // Zicfiss shadow stack
}

const GnuPropertyArmFeature1Flag uint32 = 0xc0000000
const GnuPropertyX86Feature1Flag uint32 = 0xc0000002
const GnuPropertyRiscvFeature1Flag uint32 = 0xc0000000

const (
	GnuPropertyX86FeatureIBT uint32 = 1 << iota
	GnuPropertyX86FeatureSHSTK
)

const (
	GnuPropertyArmFeatureBTI uint32 = 1 << iota
	GnuPropertyArmFeaturePAC
)

const (
	GnuPropertyRiscvFeatureCFILP uint32 = 1 << iota // Zicfilp (unlabeled landing pads)
	GnuPropertyRiscvFeatureCFISS                    // Zicfiss (shadow stack)
)

// Cfi - Check for Control Flow Integrity features
func Cfi(file *elf.File) *Result {
	res := &Result{}
	var hwOutput string
	var hwColor Status
	notes := file.Section(".note.gnu.property")
	if notes == nil {
		resUnknown(res)
		return res
	}

	propertyData, err := notes.Data()
	if err != nil {
		resUnknown(res)
		return res
	}

	hwOutput, hwColor = hwCFIDispatch(file.Machine, file.Class, propertyData, file.ByteOrder)

	// Detect Clang CFI presence and classify Single-Module vs Multi-Module
	clangMode := "none"
	// Errors from reading symbols are treated as absence of Clang CFI
	var allSyms []elf.Symbol
	if syms, err := file.Symbols(); err == nil {
		allSyms = syms
	}
	var dynSyms []elf.Symbol
	if dsyms, err := file.DynamicSymbols(); err == nil {
		dynSyms = dsyms
	}
	clangMode = classifyClangCFIMode(allSyms, dynSyms)

	// Build output string
	if hwOutput == "" {
		// No known HW CFI parsed
		if clangMode == "none" {
			resUnknown(res)
			return res
		}
		// Only Clang CFI detected
		res.Status = StatusGood
		if clangMode == "multi" {
			res.Value = "Clang CFI: Multi-Module"
		} else {
			res.Value = "Clang CFI: Single-Module"
		}
		return res
	}

	// Combine HW and Clang CFI info
	res.Status = hwColor
	if clangMode == "none" {
		res.Value = hwOutput
	} else if clangMode == "multi" {
		res.Value = hwOutput + " | Clang CFI: Multi-Module"
	} else {
		res.Value = hwOutput + " | Clang CFI: Single-Module"
	}

	return res
}

// hwCFIDispatch selects the per-arch hardware-CFI parser. Returns ("", "") for
// architectures with no known .note.gnu.property CFI encoding — the caller
// then falls back to Clang-CFI symbol detection or Unknown.
func hwCFIDispatch(m elf.Machine, c elf.Class, data []byte, bo binary.ByteOrder) (string, Status) {
	align := propAlign(c)
	switch m {
	case elf.EM_X86_64, elf.EM_386:
		// x86 CET (Shadow Stack + IBT) — same property encoding for both
		// 32- and 64-bit x86, only the property-array alignment differs.
		// https://gitlab.com/x86-psABIs/x86-64-ABI
		return cetOutputString(parseX86CETFromNotes(data, bo, align))
	case elf.EM_AARCH64:
		// AArch64 PAC + BTI.
		return armOutputString(parseArmPACBTIFromNotes(data, bo, align))
	case elf.EM_RISCV:
		// RISC-V Zicfilp (landing pads) + Zicfiss (shadow stack).
		// binutils include/elf/common.h: GNU_PROPERTY_RISCV_FEATURE_1_AND.
		return riscvOutputString(parseRiscvCFIFromNotes(data, bo, align))
	default:
		return "", ""
	}
}

// propAlign returns the GNU property-array entry alignment for the ELF class:
// 8 bytes for ELFCLASS64, 4 bytes for ELFCLASS32.
func propAlign(c elf.Class) int {
	if c == elf.ELFCLASS32 {
		return 4
	}
	return 8
}

// walkGNUProperties walks a .note.gnu.property payload, calling fn for each
// 4-byte (datasz==4) property whose pr_type matches want. The payload is
// padded to align bytes per entry. Bounds-safe on truncated/malformed input.
func walkGNUProperties(data []byte, bo binary.ByteOrder, align int, want uint32, fn func(mask uint32)) {
	alignUp := func(n uint32) int { return int((uint64(n) + uint64(align-1)) &^ uint64(align-1)) }
	i := 0
	for i+8 <= len(data) {
		ptype := bo.Uint32(data[i : i+4])
		datasz := bo.Uint32(data[i+4 : i+8])
		i += 8
		payloadLen := alignUp(datasz)
		if i+int(datasz) > len(data) {
			break
		}
		if datasz == 4 && ptype == want {
			fn(bo.Uint32(data[i : i+4]))
		}
		i += payloadLen
	}
}

func parseX86CETFromNotes(data []byte, bo binary.ByteOrder, align int) x86CET {
	var parsed x86CET
	walkGNUProperties(data, bo, align, GnuPropertyX86Feature1Flag, func(m uint32) {
		parsed = parseBitmaskForx86CET(m)
	})
	return parsed
}

func parseArmPACBTIFromNotes(data []byte, bo binary.ByteOrder, align int) armPACBTI {
	var parsed armPACBTI
	walkGNUProperties(data, bo, align, GnuPropertyArmFeature1Flag, func(m uint32) {
		parsed = parseBitmaskForArmPACBTI(m)
	})
	return parsed
}

func parseRiscvCFIFromNotes(data []byte, bo binary.ByteOrder, align int) riscvCFI {
	var parsed riscvCFI
	walkGNUProperties(data, bo, align, GnuPropertyRiscvFeature1Flag, func(m uint32) {
		parsed.lp = m&GnuPropertyRiscvFeatureCFILP != 0
		parsed.ss = m&GnuPropertyRiscvFeatureCFISS != 0
	})
	return parsed
}

// riscvOutputString maps parsed RISC-V CFI features to display string + status.
func riscvOutputString(s riscvCFI) (string, Status) {
	switch {
	case s.lp && s.ss:
		return "Zicfilp & Zicfiss", StatusGood
	case s.lp:
		return "Zicfilp & NO Zicfiss", StatusWarn
	case s.ss:
		return "NO Zicfilp & Zicfiss", StatusWarn
	default:
		return "NO Zicfilp & NO Zicfiss", StatusBad
	}
}

// cetOutputString maps parsed x86 CET features to the display string and status.
func cetOutputString(s x86CET) (string, Status) {
	switch {
	case s.shstk && s.ibt:
		return "SHSTK & IBT", StatusGood
	case s.shstk:
		return "SHSTK & NO IBT", StatusWarn
	case s.ibt:
		return "NO SHSTK & IBT", StatusWarn
	default:
		return "NO SHSTK & NO IBT", StatusBad
	}
}

// armOutputString maps parsed AArch64 PAC/BTI features to the display string and status.
func armOutputString(s armPACBTI) (string, Status) {
	switch {
	case s.pac && s.bti:
		return "PAC & BTI", StatusGood
	case s.pac:
		return "PAC & NO BTI", StatusWarn
	case s.bti:
		return "NO PAC & BTI", StatusWarn
	default:
		return "NO PAC & NO BTI", StatusBad
	}
}

func parseBitmaskForx86CET(bitmask uint32) x86CET {
	result := x86CET{
		shstk: false,
		ibt:   false,
	}
	for bitmask > 0 {
		bit := bitmask & (-bitmask)
		bitmask &= ^bit

		switch bit {
		case GnuPropertyX86FeatureIBT:
			result.ibt = true
		case GnuPropertyX86FeatureSHSTK:
			result.shstk = true
		}
	}
	return result
}

func parseBitmaskForArmPACBTI(bitmask uint32) armPACBTI {
	result := armPACBTI{
		pac: false,
		bti: false,
	}
	for bitmask > 0 {
		bit := bitmask & (-bitmask)
		bitmask &= ^bit

		switch bit {
		case GnuPropertyArmFeaturePAC:
			result.pac = true
		case GnuPropertyArmFeatureBTI:
			result.bti = true
		}
	}
	return result
}

func resUnknown(emptyCfi *Result) {
	emptyCfi.Status = StatusWarn
	emptyCfi.Value = "Unknown"
}

// classifyClangCFIMode determines presence and scope of Clang CFI.
// Returns one of: "multi" (cross-DSO), "single" (intra-module only), "none".
// Heuristic based on symbol tables:
//   - Multi-module: a defined, exported (global/default visibility) __cfi_check in .dynsym
//   - Single-module: defined __cfi_check that is not exported, or presence of
//     local CFI helpers like __cfi_slowpath/__cfi_slowpath_diag/__cfi_fail
func classifyClangCFIMode(allSymbols []elf.Symbol, dynSymbols []elf.Symbol) string {
	// Check for exported __cfi_check in dynamic symbol table
	for _, s := range dynSymbols {
		if s.Name == "__cfi_check" {
			if s.Section != elf.SHN_UNDEF {
				bind := elf.ST_BIND(s.Info)
				vis := elf.ST_VISIBILITY(s.Other)
				if (bind == elf.STB_GLOBAL || bind == elf.STB_WEAK) && vis == elf.STV_DEFAULT {
					return "multi"
				}
			}
		}
	}

	hasLocalCFI := false
	for _, s := range allSymbols {
		if s.Section == elf.SHN_UNDEF {
			continue
		}
		switch s.Name {
		case "__cfi_check":
			// defined but not seen as exported in dynsym => treat as single-module
			hasLocalCFI = true
		case "__cfi_slowpath", "__cfi_slowpath_diag", "__cfi_fail", "__cfi_check_fail":
			hasLocalCFI = true
		}
		if hasLocalCFI {
			break
		}
	}
	if hasLocalCFI {
		return "single"
	}
	return "none"
}
