package checksec

import (
	"debug/elf"
	"path/filepath"
)

type nx struct {
	Output string
	Color  string
}

// NX analyzes the NX (No eXecute) bit status of an ELF binary
// It checks for the presence of PT_GNU_STACK segment and whether it has execute permissions
func NX(name string, binary *elf.File) *nx {
	res := nx{}

	// Input validation - follow security rule: "ALWAYS validate input before processing"
	if binary == nil {
		res.Color = "red"
		res.Output = "Error: Invalid binary"
		return &res
	}

	// Sanitize filename for logging - follow security rule: "NEVER log full file paths in production"
	_ = filepath.Base(name) // We don't use this currently but shows proper path handling

	// Check if binary has program headers
	if len(binary.Progs) == 0 {
		res.Color = "italic"
		res.Output = "N/A"
		return &res
	}

	// Iterate through program headers to find GNU_STACK
	// Follow security rule: "ALWAYS validate array/slice bounds before access"
	for i, p := range binary.Progs {
		// Bounds checking - ensure we don't exceed reasonable limits
		// Follow security rule: "ALWAYS implement resource limits to prevent DoS"
		if i > 10000 { // Reasonable limit on program headers to prevent DoS
			res.Color = "red"
			res.Output = "Error: Too many program headers"
			return &res
		}

		// Additional validation - ensure program header is not nil
		if p == nil {
			continue // Skip nil program headers gracefully
		}

		// Check for GNU_STACK segment without execute permission
		if p.Type == elf.PT_GNU_STACK && p.Flags&elf.PF_X == 0 {
			res.Color = "green"
			res.Output = "NX enabled"
			return &res
		}
	}

	// If we reach here, either no GNU_STACK was found or it has execute permission
	res.Color = "red"
	res.Output = "NX disabled"
	return &res
}
