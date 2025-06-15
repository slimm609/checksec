package checksec

import (
	"debug/elf"
	"fmt"
	"os"
)

type cfi struct {
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

func Cfi(name string) *cfi {
	f, err := os.Open(name)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer f.Close()
	file, err := elf.NewFile(f)
	if err != nil {
		fmt.Println("Error parsing ELF file:", err)
		os.Exit(1)
	}
	res := cfi{}
	notes := file.Section(".note.gnu.property")
	if notes == nil {
		resUnknown(&res)
		return &res
	}

	propertyData, err := notes.Data()
	if err != nil {
		resUnknown(&res)
		return &res
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
			notetype := file.ByteOrder.Uint32(propertyData[i : i+4])
			datasz := file.ByteOrder.Uint32(propertyData[i+4 : i+8])
			i += 8
			if datasz != 4 {
				continue
			}
			bitmask := file.ByteOrder.Uint32(propertyData[i : i+4])
			if notetype == GnuPropertyX86Feature1Flag {
				parsedSupport = parseBitmaskForx86CET(bitmask)
			}
			i += 8
		}

		if parsedSupport.shstk && parsedSupport.ibt {
			res.Color = "green"
			res.Output = "SHSTK & IBT"
		} else if parsedSupport.shstk {
			res.Color = "yellow"
			res.Output = "SHSTK & NO IBT"
		} else if parsedSupport.ibt {
			res.Color = "yellow"
			res.Output = " NO SHSTK & IBT"
		} else {
			res.Color = "red"
			res.Output = "NO SHSTK & NO IBT"
		}
	} else if file.Class == elf.ELFCLASS64 && file.Machine == elf.EM_AARCH64 {
		// AARCH64, check for PAC and BTI
		// https://docs.kernel.org/arch/arm64/pointer-authentication.html
		// https://community.arm.com/arm-community-blogs/b/architectures-and-processors-blog/posts/armv8-1-m-pointer-authentication-and-branch-target-identification-extension
		var parsedSupport armPACBTI
		i := 0
		for i < len(propertyData) {
			notetype := file.ByteOrder.Uint32(propertyData[i : i+4])
			datasz := file.ByteOrder.Uint32(propertyData[i+4 : i+8])
			i += 8
			if datasz != 4 {
				continue
			}
			bitmask := file.ByteOrder.Uint32(propertyData[i : i+4])
			if notetype == GnuPropertyArmFeature1Flag {
				parsedSupport = parseBitmaskForArmPACBTI(bitmask)
			}
			i += 8
		}

		if parsedSupport.pac && parsedSupport.bti {
			res.Color = "green"
			res.Output = "PAC & BTI"
		} else if parsedSupport.pac {
			res.Color = "yellow"
			res.Output = "PAC & NO BTI"
		} else if parsedSupport.bti {
			res.Color = "yellow"
			res.Output = "NO PAC & BTI"
		} else {
			res.Color = "red"
			res.Output = "NO PAC & NO BTI"
		}
	} else {
		resUnknown(&res)
	}

	return &res
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

func resUnknown(emptyCfi *cfi) {
	emptyCfi.Color = "yellow"
	emptyCfi.Output = "Unknown"
}
