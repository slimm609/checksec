package checksec

import (
	"bytes"
	"debug/elf"
	"os"
)

// SafeStackInit symbol used by SafeStack-enabled binaries.
const SafeStackInit = "__safestack_init"

func hasSafeStackSymbol(name string) bool {
	return bytes.HasPrefix([]byte(name), []byte(SafeStackInit))
}

// SafeStack checks for SafeStack support by searching for __safestack_init.
// raw may be nil; when present it enables the stripped-binary fallback.
func SafeStack(file *elf.File, raw *os.File) *Result {
	found := &Result{Value: "SafeStack Found", Status: StatusGood}

	if symbols, err := file.Symbols(); err == nil {
		for _, symbol := range symbols {
			if hasSafeStackSymbol(symbol.Name) {
				return found
			}
		}
	}

	if importedSymbols, err := file.ImportedSymbols(); err == nil {
		for _, symbol := range importedSymbols {
			if hasSafeStackSymbol(symbol.Name) {
				return found
			}
		}
	}

	if raw != nil {
		if dynamicFunctions, err := FunctionsFromSymbolTable(raw); err == nil {
			for _, symbol := range dynamicFunctions {
				if hasSafeStackSymbol(symbol.Name) {
					return found
				}
			}
		}
	}

	return &Result{Value: "No SafeStack Found", Status: StatusBad}
}
