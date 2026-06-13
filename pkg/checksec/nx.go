package checksec

import (
	"debug/elf"
)

// NX analyzes the NX (No eXecute) bit status of an ELF binary
// It checks for the presence of PT_GNU_STACK segment and whether it has execute permissions
func NX(binary *elf.File) *Result {
	// Input validation - follow security rule: "ALWAYS validate input before processing"
	if binary == nil {
		return &Result{Value: "Error: Invalid binary", Status: StatusBad}
	}

	// Check if binary has program headers
	if len(binary.Progs) == 0 {
		return &Result{Value: "N/A", Status: StatusNA}
	}

	// Iterate through program headers to find GNU_STACK
	// Follow security rule: "ALWAYS validate array/slice bounds before access"
	for i, p := range binary.Progs {
		// Bounds checking - ensure we don't exceed reasonable limits
		// Follow security rule: "ALWAYS implement resource limits to prevent DoS"
		if i > 10000 { // Reasonable limit on program headers to prevent DoS
			return &Result{Value: "Error: Too many program headers", Status: StatusBad}
		}

		// Additional validation - ensure program header is not nil
		if p == nil {
			continue // Skip nil program headers gracefully
		}

		// Check for GNU_STACK segment without execute permission
		if p.Type == elf.PT_GNU_STACK && p.Flags&elf.PF_X == 0 {
			return &Result{Value: "NX enabled", Status: StatusGood}
		}
	}

	// If we reach here, either no GNU_STACK was found or it has execute permission
	return &Result{Value: "NX disabled", Status: StatusBad}
}
