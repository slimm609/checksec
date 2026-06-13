package checksec

import (
	"debug/elf"
)

// SeparateCode reports whether the binary's loadable segments respect W^X — no
// PT_LOAD segment is both writable and executable. This is the property that
// `ld -z separate-code` (and lld --rosegment) guarantees by splitting code and
// data into distinct, non-overlapping page-aligned segments.
func SeparateCode(file *elf.File) *Result {
	loads := 0
	for _, p := range file.Progs {
		if p == nil || p.Type != elf.PT_LOAD {
			continue
		}
		loads++
		if p.Flags&elf.PF_W != 0 && p.Flags&elf.PF_X != 0 {
			return &Result{Value: "WX Segment", Status: StatusBad}
		}
	}
	if loads == 0 {
		return &Result{Value: "N/A", Status: StatusNA}
	}
	return &Result{Value: "Enabled", Status: StatusGood}
}
