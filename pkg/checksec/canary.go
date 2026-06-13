package checksec

import (
	"debug/elf"
	"os"
	"strings"
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

// Canary - Check for canary bits. raw may be nil; when present it enables the
// stripped-binary fallback via FunctionsFromSymbolTable.
func Canary(file *elf.File, raw *os.File) *Result {
	found := &Result{Value: "Canary Found", Status: StatusGood}

	// Check symbols with proper error handling
	if symbols, err := file.Symbols(); err == nil {
		for _, symbol := range symbols {
			if isCanarySymbol(symbol.Name) {
				return found
			}
		}
	}

	// Check imported symbols
	if importedSymbols, err := file.ImportedSymbols(); err == nil {
		for _, imp := range importedSymbols {
			if isCanarySymbol(imp.Name) {
				return found
			}
		}
	}

	// Check dynamic functions (stripped-binary fallback)
	if raw != nil {
		if dynamicFunctions, err := FunctionsFromSymbolTable(raw); err == nil {
			for _, symbol := range dynamicFunctions {
				if isCanarySymbol(symbol.Name) {
					return found
				}
			}
		}
	}

	return &Result{Value: "No Canary Found", Status: StatusBad}
}
