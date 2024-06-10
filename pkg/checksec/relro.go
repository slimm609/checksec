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

	bind, _ := file.DynValue(24)
	if len(bind) > 0 && bind[0] == 0 {
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
