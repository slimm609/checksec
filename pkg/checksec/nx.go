package checksec

import (
	"debug/elf"
)

// NX analyzes the NX (No eXecute) bit status of an ELF binary
// It checks for the presence of PT_GNU_STACK segment and whether it has execute permissions.
// If a (malformed or crafted) binary carries more than one PT_GNU_STACK header,
// the last one decides, because that is what the Linux kernel does: the
// PT_GNU_STACK case in the program-header loop of load_elf_binary()
// (fs/binfmt_elf.c) overwrites executable_stack for every such header, without
// a break.
func NX(binary *elf.File) *Result {
	// Input validation - follow security rule: "ALWAYS validate input before processing"
	if binary == nil {
		return &Result{Value: "Error: Invalid binary", Status: StatusBad}
	}

	// Check if binary has program headers
	if len(binary.Progs) == 0 {
		return &Result{Value: "N/A", Status: StatusNA}
	}

	// Iterate through program headers to find GNU_STACK. Keep scanning after the
	// first match: the last PT_GNU_STACK wins (see above).
	// Follow security rule: "ALWAYS validate array/slice bounds before access"
	var gnuStack *elf.Prog
	for i, p := range binary.Progs {
		// Bounds checking - ensure we don't exceed reasonable limits
		// Follow security rule: "ALWAYS implement resource limits to prevent DoS"
		if i > 10000 { // Reasonable limit on program headers to prevent DoS
			return &Result{Value: "Error: Too many program headers", Status: StatusBad}
		}
		if p == nil {
			continue
		}
		if p.Type == elf.PT_GNU_STACK {
			gnuStack = p
		}
	}

	// Missing PT_GNU_STACK ≠ executable stack: the kernel applies its own
	// default (non-exec on x86-64/arm64, exec on some legacy arches). Report
	// it distinctly so it isn't conflated with an explicit RWX stack.
	if gnuStack == nil {
		return &Result{Value: "No GNU_STACK", Status: StatusWarn}
	}
	if gnuStack.Flags&elf.PF_X == 0 {
		return &Result{Value: "NX enabled", Status: StatusGood}
	}
	return &Result{Value: "NX disabled", Status: StatusBad}
}
