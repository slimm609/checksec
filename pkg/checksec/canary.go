package checksec

import (
	"context"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// StackChk to check for stack_chk_fail value
const StackChk = "__stack_chk_fail"

// canarySymbolPrefixes are symbol-name prefixes whose presence indicates the
// binary was built with stack-smashing protection. Mirrors checksec.bash:
// __stack_chk_fail (glibc handler), __stack_chk_guard (the guard slot itself,
// seen in static/freestanding builds), and __intel_security_cookie (Intel ICC).
var canarySymbolPrefixes = []string{
	"__stack_chk_fail",
	"__stack_chk_guard",
	"__intel_security_cookie",
	"__intel_security_check_cookie",
}

func isCanarySymbol(name string) bool {
	for _, p := range canarySymbolPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Canary - Check for canary bits
func Canary(name string) (*Result, error) {
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

	found := &Result{Value: "Canary Found", Status: StatusGood}

	// Check symbols with proper error handling
	if symbols, err := file.Symbols(); err == nil {
		for _, symbol := range symbols {
			if isCanarySymbol(symbol.Name) {
				return found, nil
			}
		}
	}

	// Check imported symbols
	if importedSymbols, err := file.ImportedSymbols(); err == nil {
		for _, imp := range importedSymbols {
			if isCanarySymbol(imp.Name) {
				return found, nil
			}
		}
	}

	// Check dynamic functions
	if dynamicFunctions, err := FunctionsFromSymbolTable(f); err == nil {
		for _, symbol := range dynamicFunctions {
			if isCanarySymbol(symbol.Name) {
				return found, nil
			}
		}
	}

	return &Result{Value: "No Canary Found", Status: StatusBad}, nil
}
