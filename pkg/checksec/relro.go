package checksec

import (
	"debug/elf"

	"github.com/slimm609/checksec/v3/pkg/output"
)

type relro struct {
	Output string
	Color  string
}

func RELRO(name string) *relro {
	res := relro{}
	relroHeader := false
	bindNow := false

	// To get the dynamic values
	// Open the ELF binary file
	file, err := elf.Open(name)
	if err != nil {
		output.Fatalf("Error opening ELF file: %v", err)
	}
	defer file.Close()

	if len(file.Progs) == 0 {
		res.Color = "italic"
		res.Output = "N/A"
		return &res
	}

	// check both bind and flags.
	// if DT_BIND_NOW == 0, then it is set
	// if (DT_FLAGS & 0x8) > 0, then DF_BIND_NOW is set
	// this is depending on the compiler version used.
	bind, _ := file.DynValue(elf.DT_BIND_NOW)
	if len(bind) == 0 {
		bind, _ = DynValueFromPTDynamic(file, elf.DT_BIND_NOW)
	}
	flags, _ := file.DynValue(elf.DT_FLAGS)
	if len(flags) == 0 {
		flags, _ = DynValueFromPTDynamic(file, elf.DT_FLAGS)
	}

	const DF_BIND_NOW = 0x8
	if (len(bind) > 0 && bind[0] == 0) || (len(flags) > 0 && (flags[0]&DF_BIND_NOW) > 0) {
		bindNow = true
	}

	for _, prog := range file.Progs {
		if prog.Type == elf.PT_GNU_RELRO {
			relroHeader = true
		}
	}

	if bindNow == true {
		res.Color = "green"
		res.Output = "Full RELRO"
		return &res
	} else if relroHeader == true {
		res.Color = "yellow"
		res.Output = "Partial RELRO"
		return &res
	} else {
		res.Color = "red"
		res.Output = "No RELRO"
		return &res
	}
}
