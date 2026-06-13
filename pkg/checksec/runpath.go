package checksec

import (
	"debug/elf"
	"fmt"
)

// Detect runpath in binary
func RUNPATH(name string) (*Result, error) {
	file, err := elf.Open(name)
	if err != nil {
		return nil, fmt.Errorf("error opening ELF file: %w", err)
	}
	defer file.Close()

	runpath, _ := file.DynValue(29)
	if len(runpath) == 0 {
		return &Result{Value: "No RUNPATH", Status: StatusGood}, nil
	}
	return &Result{Value: "RUNPATH", Status: StatusBad}, nil
}
