package checksec

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
)

// canary struct
type canary struct {
	Output string
	Color  string
}

// StackChk to check for stack_chk_fail value
const StackChk = "__stack_chk_fail"

// Canary - Check for canary bits
func Canary(name string) *canary {
	// To get the dynamic values
	// Open the ELF binary file
	file, err := elf.Open(name)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer file.Close()
	res := canary{}
	if symbols, err := file.Symbols(); err == nil {
		for _, symbol := range symbols {
			if bytes.HasPrefix([]byte(symbol.Name), []byte(StackChk)) {
				res.Output = "Canary Found"
				res.Color = "green"
				return &res
			}
		}
	}

	if importedSymbols, err := file.ImportedSymbols(); err == nil {
		for _, imp := range importedSymbols {
			if bytes.HasPrefix([]byte(imp.Name), []byte(StackChk)) {
				res.Output = "Canary Found"
				res.Color = "green"
				return &res
			}
		}
	}

	res.Output = "No Canary Found"
	res.Color = "red"
	return &res
}
