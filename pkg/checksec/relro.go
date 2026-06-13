package checksec

import (
	"debug/elf"
)

func RELRO(file *elf.File) *Result {
	if len(file.Progs) == 0 {
		return &Result{Value: "N/A", Status: StatusNA}
	}

	// check bind and flags and flags1.
	// if DT_BIND_NOW == 0, then it is set
	// if (DT_FLAGS & 0x8) > 0, then DF_BIND_NOW is set
	// if (DT_FLAGS_1 & 0x1) > 1, then DF_1_NOW is set
	// this is depending on the compiler version used.
	bind, _ := file.DynValue(elf.DT_BIND_NOW)
	if len(bind) == 0 {
		bind, _ = DynValueFromPTDynamic(file, elf.DT_BIND_NOW)
	}
	flags, _ := file.DynValue(elf.DT_FLAGS)
	if len(flags) == 0 {
		flags, _ = DynValueFromPTDynamic(file, elf.DT_FLAGS)
	}

	flags1, _ := file.DynValue(elf.DT_FLAGS_1)
	if len(flags1) == 0 {
		flags1, _ = DynValueFromPTDynamic(file, elf.DT_FLAGS_1)
	}

	bindNow := relroBindNow(bind, flags, flags1)

	relroHeader := false
	for _, prog := range file.Progs {
		if prog.Type == elf.PT_GNU_RELRO {
			relroHeader = true
		}
	}

	if bindNow {
		return &Result{Value: "Full RELRO", Status: StatusGood}
	} else if relroHeader {
		return &Result{Value: "Partial RELRO", Status: StatusWarn}
	}
	return &Result{Value: "No RELRO", Status: StatusBad}
}

// relroBindNow reports whether the dynamic-section flags indicate bind-now (the
// "Full RELRO" condition): a present DT_BIND_NOW entry, the DF_BIND_NOW bit in
// DT_FLAGS, or the DF_1_NOW bit in DT_FLAGS_1.
func relroBindNow(bind, flags, flags1 []uint64) bool {
	// A present DT_BIND_NOW entry means bind-now regardless of its d_val (which
	// the ELF spec leaves unused), so presence — not value == 0 — is the test.
	return len(bind) > 0 ||
		(len(flags) > 0 && (flags[0]&uint64(elf.DF_BIND_NOW)) != 0) ||
		(len(flags1) > 0 && (flags1[0]&uint64(elf.DF_1_NOW)) != 0)
}
