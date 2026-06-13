package checksec

import (
	"debug/elf"
	"fmt"
)

func RPATH(name string) (*Result, error) {
	file, err := elf.Open(name)
	if err != nil {
		return nil, fmt.Errorf("error opening ELF file: %w", err)
	}
	defer file.Close()

	rpath, _ := file.DynValue(15)
	if len(rpath) == 0 {
		return &Result{Value: "No RPATH", Status: StatusGood}, nil
	}
	return &Result{Value: "RPATH", Status: StatusBad}, nil
}
