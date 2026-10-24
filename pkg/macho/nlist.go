package macho

import dm "debug/macho"

// nlist n_type bits, from <mach-o/nlist.h>.
const (
	nStab uint8 = 0xe0
	nType uint8 = 0x0e
	nExt  uint8 = 0x01
	nUndf uint8 = 0x0
	nPbud uint8 = 0xc

	// nDescReferencedDynamically is the n_desc REFERENCED_DYNAMICALLY bit. The
	// linker sets it on synthesized symbols such as __mh_execute_header, which
	// strip keeps by design.
	nDescReferencedDynamically uint16 = 0x10
)

func isUndefined(s dm.Symbol) bool {
	t := s.Type & nType
	return t == nUndf || t == nPbud
}

// definedSymbolCount counts symtab entries that name something inside this
// image: not undefined (imports), not debugger stabs, and not marked
// REFERENCED_DYNAMICALLY. A stripped binary keeps its imports and the
// linker-synthesized __mh_execute_header, so counting those would never reach zero.
func definedSymbolCount(f *dm.File) int {
	if f.Symtab == nil {
		return 0
	}
	n := 0
	for _, s := range f.Symtab.Syms {
		if s.Type&nStab != 0 || isUndefined(s) || s.Desc&nDescReferencedDynamically != 0 {
			continue
		}
		n++
	}
	return n
}

// importedNames returns the names of undefined external symbols, computed from
// the symtab directly so it works without LC_DYSYMTAB.
func importedNames(f *dm.File) []string {
	if f.Symtab == nil {
		return nil
	}
	var out []string
	for _, s := range f.Symtab.Syms {
		if s.Type&nStab == 0 && isUndefined(s) && s.Type&nExt != 0 {
			out = append(out, s.Name)
		}
	}
	return out
}

// allSymbolNames returns every non-stab symbol name, defined or imported.
func allSymbolNames(f *dm.File) []string {
	if f.Symtab == nil {
		return nil
	}
	out := make([]string, 0, len(f.Symtab.Syms))
	for _, s := range f.Symtab.Syms {
		if s.Type&nStab == 0 {
			out = append(out, s.Name)
		}
	}
	return out
}
