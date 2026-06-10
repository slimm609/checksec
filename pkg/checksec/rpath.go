package checksec

import (
	"debug/elf"
	"fmt"
)

type rpath struct {
	Output string
	Color  string
}

func RPATH(name string) (*rpath, error) {
	res := rpath{}
	file, err := elf.Open(name)
	if err != nil {
		return nil, fmt.Errorf("error opening ELF file: %w", err)
	}
	defer file.Close()

	rpath, _ := file.DynValue(15)
	if len(rpath) == 0 {
		res.Output = "No RPATH"
		res.Color = "green"
	} else {
		res.Output = "RPATH"
		res.Color = "red"
	}
	return &res, nil
}
