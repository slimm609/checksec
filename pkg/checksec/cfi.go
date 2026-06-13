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

const GnuPropertyArmFeature1Flag uint32 = 0xc0000000
const GnuPropertyX86Feature1Flag uint32 = 0xc0000002

const (
	GnuPropertyX86FeatureIBT uint32 = 1 << iota
	GnuPropertyX86FeatureSHSTK
)

const (
	GnuPropertyArmFeatureBTI uint32 = 1 << iota
	GnuPropertyArmFeaturePAC
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

	// Property data layout of the relevant sections in ELFCLASS64
	// |0                  |1
	// |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | type  |datasz | btmsk |  pad  |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	if file.Class == elf.ELFCLASS64 && file.Machine == elf.EM_X86_64 {
		// x86-64, check for Shadow Stack and IBT
		// https://docs.kernel.org/next/x86/shstk.html
		// https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html
		hwOutput, hwColor = cetOutputString(parseX86CETFromNotes(propertyData, file.ByteOrder))
	} else if file.Class == elf.ELFCLASS64 && file.Machine == elf.EM_AARCH64 {
		// AARCH64, check for PAC and BTI
		// https://docs.kernel.org/arch/arm64/pointer-authentication.html
		// https://community.arm.com/arm-community-blogs/b/architectures-and-processors-blog/posts/armv8-1-m-pointer-authentication-and-branch-target-identification-extension
		hwOutput, hwColor = armOutputString(parseArmPACBTIFromNotes(propertyData, file.ByteOrder))
	} else {
		// Leave hwOutput empty; fallback to Unknown unless Clang CFI is detected
	}

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

// parseX86CETFromNotes walks a .note.gnu.property payload and returns the x86
// CET (SHSTK/IBT) features advertised. It is bounds-safe on truncated or
// malformed input: out-of-range reads stop the scan rather than panicking.
func parseX86CETFromNotes(data []byte, bo binary.ByteOrder) x86CET {
	var parsed x86CET
	i := 0
	for i+8 <= len(data) {
		notetype := bo.Uint32(data[i : i+4])
		datasz := bo.Uint32(data[i+4 : i+8])
		i += 8

		// The payload is datasz bytes, padded to 8-byte (ELFCLASS64) alignment.
		// Advance by the full padded length so non-feature properties (datasz != 4)
		// don't desync the scan and hide a following feature property.
		payloadLen := align8(datasz)
		if i+int(datasz) > len(data) {
			break
		}
		if datasz == 4 && notetype == GnuPropertyX86Feature1Flag {
			parsed = parseBitmaskForx86CET(bo.Uint32(data[i : i+4]))
		}
		i += payloadLen
	}
	return parsed
}

// align8 rounds n up to the next multiple of 8 (the GNU property note alignment
// for ELFCLASS64), returned as an int for use as a slice offset.
func align8(n uint32) int {
	return int((uint64(n) + 7) &^ 7)
}

// parseArmPACBTIFromNotes walks a .note.gnu.property payload and returns the
// AArch64 PAC/BTI features advertised. It is bounds-safe on truncated input.
func parseArmPACBTIFromNotes(data []byte, bo binary.ByteOrder) armPACBTI {
	var parsed armPACBTI
	i := 0
	for i+8 <= len(data) {
		notetype := bo.Uint32(data[i : i+4])
		datasz := bo.Uint32(data[i+4 : i+8])
		i += 8

		// Advance by the full padded payload so non-feature properties don't
		// desync the scan (see parseX86CETFromNotes).
		payloadLen := align8(datasz)
		if i+int(datasz) > len(data) {
			break
		}
		if datasz == 4 && notetype == GnuPropertyArmFeature1Flag {
			parsed = parseBitmaskForArmPACBTI(bo.Uint32(data[i : i+4]))
		}
		i += payloadLen
	}
	return parsed
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
