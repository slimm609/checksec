package checksec

import (
	"debug/elf"
	"fmt"
	"os"
)

type runpath struct {
	Output string
	Color  string
}

// Detect runpath in binary
func RUNPATH(name string) *runpath {
	res := runpath{}
	file, err := elf.Open(name)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer file.Close()

	runpath, _ := file.DynValue(29)
	if len(runpath) == 0 {
		res.Output = "No RUNPATH"
		res.Color = "green"
	} else {
		res.Output = "RUNPATH"
		res.Color = "red"
	}
	return &res
}
