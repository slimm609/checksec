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

	// check both bind and bind_flag.
	// if DT_BIND_NOW == 0, then it is set
	// if DT_FLAGS == 8, then DF_BIND_NOW is set
	// this is depending on the compiler version used.
	bind, _ := file.DynValue(elf.DT_BIND_NOW)
	if (len(bind) == 0) {
		bind, _ = DynValueFromPTDynamic(file, elf.DT_BIND_NOW)
	}
	bind_flag, _ := file.DynValue(elf.DT_FLAGS)
	if (len(bind_flag) == 0) {
		bind_flag, _ = DynValueFromPTDynamic(file, elf.DT_FLAGS)
	}

	if (len(bind) > 0 && bind[0] == 0) || (len(bind_flag) > 0 && bind_flag[0] == 8) {
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
