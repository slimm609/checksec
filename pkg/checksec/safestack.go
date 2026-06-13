package checksec

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
)

// SafeStackInit symbol used by SafeStack-enabled binaries.
const SafeStackInit = "__safestack_init"

func hasSafeStackSymbol(name string) bool {
	return bytes.HasPrefix([]byte(name), []byte(SafeStackInit))
}

// SafeStack checks for SafeStack support by searching for __safestack_init.
func SafeStack(name string) (*Result, error) {
	if name == "" {
		return nil, fmt.Errorf("filename cannot be empty")
	}

	cleanPath := filepath.Clean(name)
	if _, err := os.Stat(cleanPath); err != nil {
		return nil, fmt.Errorf("cannot access file: %w", err)
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	file, err := elf.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("invalid ELF file: %w", err)
	}

	found := &Result{Value: "SafeStack Found", Status: StatusGood}

	if symbols, err := file.Symbols(); err == nil {
		for _, symbol := range symbols {
			if hasSafeStackSymbol(symbol.Name) {
				return found, nil
			}
		}
	}

	if importedSymbols, err := file.ImportedSymbols(); err == nil {
		for _, symbol := range importedSymbols {
			if hasSafeStackSymbol(symbol.Name) {
				return found, nil
			}
		}
	}

	if dynamicFunctions, err := FunctionsFromSymbolTable(f); err == nil {
		for _, symbol := range dynamicFunctions {
			if hasSafeStackSymbol(symbol.Name) {
				return found, nil
			}
		}
	}

	return &Result{Value: "No SafeStack Found", Status: StatusBad}, nil
}
