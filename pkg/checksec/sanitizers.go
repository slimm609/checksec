package checksec

import (
	"debug/elf"
	"strings"
)

// sanitizerSig maps a display label to the symbol-name prefixes that indicate
// the corresponding compiler-rt sanitizer runtime is linked in.
type sanitizerSig struct {
	label    string
	prefixes []string
}

// Order here is the display order ("ASAN+UBSAN+...").
var sanitizerSigs = []sanitizerSig{
	{"ASAN", []string{"__asan_"}},
	{"UBSAN", []string{"__ubsan_handle_"}},
	{"MSAN", []string{"__msan_"}},
	{"TSAN", []string{"__tsan_"}},
	{"LSAN", []string{"__lsan_"}},
}

// classifySanitizers returns the "+"-joined set of sanitizers whose runtime
// symbols appear in the given symbol-name list, or "None".
func classifySanitizers(symbols []string) string {
	found := make(map[string]bool, len(sanitizerSigs))
	for _, name := range symbols {
		for _, sig := range sanitizerSigs {
			if found[sig.label] {
				continue
			}
			for _, p := range sig.prefixes {
				if strings.HasPrefix(name, p) {
					found[sig.label] = true
					break
				}
			}
		}
	}
	if len(found) == 0 {
		return "None"
	}
	var parts []string
	for _, sig := range sanitizerSigs {
		if found[sig.label] {
			parts = append(parts, sig.label)
		}
	}
	return strings.Join(parts, "+")
}

func sanitizerResult(value string) Result {
	if value == "None" {
		return Result{Value: value, Status: StatusInfo}
	}
	return Result{Value: value, Status: StatusGood}
}

// Sanitizers reports which compiler-rt sanitizer runtimes (ASAN/UBSAN/MSAN/
// TSAN/LSAN) are linked into the binary, by symbol-prefix scan across .symtab,
// .dynsym, and imported symbols.
func Sanitizers(file *elf.File) *Result {
	var names []string
	if syms, err := file.Symbols(); err == nil {
		for _, s := range syms {
			names = append(names, s.Name)
		}
	}
	if dyn, err := file.DynamicSymbols(); err == nil {
		for _, s := range dyn {
			names = append(names, s.Name)
		}
	}
	if imp, err := file.ImportedSymbols(); err == nil {
		for _, s := range imp {
			names = append(names, s.Name)
		}
	}
	r := sanitizerResult(classifySanitizers(names))
	return &r
}
