package checksec

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SafeStackInit symbol used by SafeStack-enabled binaries.
const SafeStackInit = "__safestack_init"

// SafeStackResult is the result of SafeStack detection.
type SafeStackResult struct {
	Output string
	Color  string
}

func hasSafeStackSymbol(name string) bool {
	return bytes.HasPrefix([]byte(name), []byte(SafeStackInit))
}

// SafeStack checks for SafeStack support by searching for __safestack_init.
func SafeStack(name string) (*SafeStackResult, error) {
	if name == "" {
		return nil, fmt.Errorf("filename cannot be empty")
	}

	cleanPath := filepath.Clean(name)
	if _, err := os.Stat(cleanPath); err != nil {
		return nil, fmt.Errorf("cannot access file: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("operation timed out")
	default:
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

	res := &SafeStackResult{}

	if symbols, err := file.Symbols(); err == nil {
		for _, symbol := range symbols {
			if hasSafeStackSymbol(symbol.Name) {
				res.Output = "SafeStack Found"
				res.Color = "green"
				return res, nil
			}
		}
	}

	if importedSymbols, err := file.ImportedSymbols(); err == nil {
		for _, symbol := range importedSymbols {
			if hasSafeStackSymbol(symbol.Name) {
				res.Output = "SafeStack Found"
				res.Color = "green"
				return res, nil
			}
		}
	}

	if dynamicFunctions, err := FunctionsFromSymbolTable(f); err == nil {
		for _, symbol := range dynamicFunctions {
			if hasSafeStackSymbol(symbol.Name) {
				res.Output = "SafeStack Found"
				res.Color = "green"
				return res, nil
			}
		}
	}

	res.Output = "No SafeStack Found"
	res.Color = "red"
	return res, nil
}
