package checksec

import (
	"debug/elf"
)

// classifyPIE maps the ELF type plus DF_1_PIE / PT_INTERP signals to the PIE
// classification. ET_DYN alone does not mean "PIE Enabled" — a shared library
// is also ET_DYN. A PIE executable is distinguished by either the DF_1_PIE
// flag (modern toolchains) or the presence of a program interpreter (it's run
// directly, not dlopen'd).
func classifyPIE(t elf.Type, hasInterp bool, flags1 []uint64) (string, Status) {
	switch t {
	case elf.ET_DYN:
		hasPIEFlag := len(flags1) > 0 && flags1[0]&uint64(elf.DF_1_PIE) != 0
		switch {
		case hasPIEFlag && !hasInterp:
			// Static-PIE (gcc/clang --static-pie, musl): self-relocating PIE
			// with no dynamic linker.
			return "Static PIE", StatusGood
		case hasPIEFlag, hasInterp:
			return "PIE Enabled", StatusGood
		default:
			return "DSO", StatusInfo
		}
	case elf.ET_REL:
		return "REL", StatusWarn
	default:
		return "PIE Disabled", StatusBad
	}
}

func PIE(file *elf.File) *Result {
	hasInterp := false
	for _, p := range file.Progs {
		if p.Type == elf.PT_INTERP {
			hasInterp = true
			break
		}
	}
	flags1, _ := file.DynValue(elf.DT_FLAGS_1)
	if len(flags1) == 0 {
		flags1, _ = DynValueFromPTDynamic(file, elf.DT_FLAGS_1)
	}
	v, s := classifyPIE(file.Type, hasInterp, flags1)
	return &Result{Value: v, Status: s}
}
