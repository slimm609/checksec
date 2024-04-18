package checksec

import (
	"debug/elf"
	"fmt"
	"os"
)

type rpath struct {
	Output string
	Color  string
}

func RPATH(name string) *rpath {
	res := rpath{}
	file, err := elf.Open(name)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
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
	return &res
}
