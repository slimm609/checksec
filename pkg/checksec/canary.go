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

// CanaryResult struct
type CanaryResult struct {
	Output string
	Color  string
}

// StackChk to check for stack_chk_fail value
const StackChk = "__stack_chk_fail"

// Canary - Check for canary bits
func Canary(name string) (*CanaryResult, error) {
	// Input validation
	if name == "" {
		return nil, fmt.Errorf("filename cannot be empty")
	}

	// Clean the file path to prevent directory traversal
	cleanPath := filepath.Clean(name)

	// Check file exists and is accessible
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

	res := &CanaryResult{}

	// Check symbols with proper error handling
	if symbols, err := file.Symbols(); err == nil {
		for _, symbol := range symbols {
			if bytes.HasPrefix([]byte(symbol.Name), []byte(StackChk)) {
				res.Output = "Canary Found"
				res.Color = "green"
				return res, nil
			}
		}
	}

	// Check imported symbols
	if importedSymbols, err := file.ImportedSymbols(); err == nil {
		for _, imp := range importedSymbols {
			if bytes.HasPrefix([]byte(imp.Name), []byte(StackChk)) {
				res.Output = "Canary Found"
				res.Color = "green"
				return res, nil
			}
		}
	}

	// Check dynamic functions
	if dynamicFunctions, err := FunctionsFromSymbolTable(f); err == nil {
		for _, symbol := range dynamicFunctions {
			if bytes.HasPrefix([]byte(symbol.Name), []byte(StackChk)) {
				res.Output = "Canary Found"
				res.Color = "green"
				return res, nil
			}
		}
	}

	res.Output = "No Canary Found"
	res.Color = "red"
	return res, nil
}
