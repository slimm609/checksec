package checksec

import (
	"debug/elf"
	"fmt"
	"os"
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
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer file.Close()

	if len(file.Progs) == 0 {
		res.Color = "italic"
		res.Output = "N/A"
		return &res
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

	if (len(bind) > 0 && bind[0] == 0) ||
		(len(flags) > 0 && (flags[0]&uint64(elf.DF_BIND_NOW)) != 0) ||
		(len(flags1) > 0 && (flags1[0]&uint64(elf.DF_1_NOW)) != 0) {
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
