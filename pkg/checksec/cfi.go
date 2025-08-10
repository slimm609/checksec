package checksec

import (
	"context"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type CfiResult struct {
	Output string
	Color  string
}

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
func Cfi(name string) (*CfiResult, error) {
	// Input validation
	if name == "" {
		return nil, fmt.Errorf("filename cannot be empty")
	}

	// Clean the file path to prevent directory traversal
	cleanPath := filepath.Clean(name)

	// Check file exists and is accessible
	if _, err := os.Stat(cleanPath); err != nil {
		return nil, fmt.Errorf("cannot access file: %w", err)
	}

	// Open with timeout context to prevent hanging operations
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use context for file operations
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("operation timed out")
	default:
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	file, err := elf.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("invalid ELF file: %w", err)
	}

	res := &CfiResult{}
	var hwOutput string
	var hwColor string
	notes := file.Section(".note.gnu.property")
	if notes == nil {
		resUnknown(res)
		return res, nil
	}

	propertyData, err := notes.Data()
	if err != nil {
		resUnknown(res)
		return res, nil
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
		var parsedSupport x86CET
		i := 0
		for i < len(propertyData) {
			// Bounds checking for note type and data size
			if i+8 > len(propertyData) {
				break
			}

			notetype := file.ByteOrder.Uint32(propertyData[i : i+4])
			datasz := file.ByteOrder.Uint32(propertyData[i+4 : i+8])
			i += 8

			if datasz != 4 {
				continue
			}

			// Bounds checking for bitmask
			if i+4 > len(propertyData) {
				break
			}

			bitmask := file.ByteOrder.Uint32(propertyData[i : i+4])
			if notetype == GnuPropertyX86Feature1Flag {
				parsedSupport = parseBitmaskForx86CET(bitmask)
			}
			i += 8
		}

		if parsedSupport.shstk && parsedSupport.ibt {
			hwColor = "green"
			hwOutput = "SHSTK & IBT"
		} else if parsedSupport.shstk {
			hwColor = "yellow"
			hwOutput = "SHSTK & NO IBT"
		} else if parsedSupport.ibt {
			hwColor = "yellow"
			hwOutput = "NO SHSTK & IBT"
		} else {
			hwColor = "red"
			hwOutput = "NO SHSTK & NO IBT"
		}
	} else if file.Class == elf.ELFCLASS64 && file.Machine == elf.EM_AARCH64 {
		// AARCH64, check for PAC and BTI
		// https://docs.kernel.org/arch/arm64/pointer-authentication.html
		// https://community.arm.com/arm-community-blogs/b/architectures-and-processors-blog/posts/armv8-1-m-pointer-authentication-and-branch-target-identification-extension
		var parsedSupport armPACBTI
		i := 0
		for i < len(propertyData) {
			// Bounds checking for note type and data size
			if i+8 > len(propertyData) {
				break
			}

			notetype := file.ByteOrder.Uint32(propertyData[i : i+4])
			datasz := file.ByteOrder.Uint32(propertyData[i+4 : i+8])
			i += 8

			if datasz != 4 {
				continue
			}

			// Bounds checking for bitmask
			if i+4 > len(propertyData) {
				break
			}

			bitmask := file.ByteOrder.Uint32(propertyData[i : i+4])
			if notetype == GnuPropertyArmFeature1Flag {
				parsedSupport = parseBitmaskForArmPACBTI(bitmask)
			}
			i += 8
		}

		if parsedSupport.pac && parsedSupport.bti {
			hwColor = "green"
			hwOutput = "PAC & BTI"
		} else if parsedSupport.pac {
			hwColor = "yellow"
			hwOutput = "PAC & NO BTI"
		} else if parsedSupport.bti {
			hwColor = "yellow"
			hwOutput = "NO PAC & BTI"
		} else {
			hwColor = "red"
			hwOutput = "NO PAC & NO BTI"
		}
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
			return res, nil
		}
		// Only Clang CFI detected
		res.Color = "green"
		if clangMode == "multi" {
			res.Output = "Clang CFI: Multi-Module"
		} else {
			res.Output = "Clang CFI: Single-Module"
		}
		return res, nil
	}

	// Combine HW and Clang CFI info
	res.Color = hwColor
	if clangMode == "none" {
		res.Output = hwOutput
	} else if clangMode == "multi" {
		res.Output = hwOutput + " | Clang CFI: Multi-Module"
	} else {
		res.Output = hwOutput + " | Clang CFI: Single-Module"
	}

	return res, nil
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

func resUnknown(emptyCfi *CfiResult) {
	emptyCfi.Color = "yellow"
	emptyCfi.Output = "Unknown"
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
