package checksec

import (
	"debug/elf"
	"fmt"
	"os"
)

type symbols struct {
	Output string
	Color  string
}

// SYMBOLS detects usage of elf symbols
func SYMBOLS(name string) *symbols {
	res := symbols{}
	file, err := elf.Open(name)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer file.Close()

	symbols, _ := file.Symbols()
	if len(symbols) == 0 {
		res.Output = "No Symbols"
		res.Color = "green"
	} else {
		res.Output = fmt.Sprintf("%d symbols", len(symbols))
		res.Color = "red"
	}
	return &res
}
