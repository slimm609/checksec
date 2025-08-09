package checksec

import (
	"debug/elf"
	"fmt"
	"testing"
)

// mockElfFile creates a mock ELF file with specified program headers
type mockElfFile struct {
	progs []mockProgHeader
}

// mockProgHeader represents a mock program header for testing
type mockProgHeader struct {
	progType elf.ProgType
	flags    elf.ProgFlag
}

// createMockElfFile creates a mock ELF file with the specified program headers
func createMockElfFile(progs []mockProgHeader) *elf.File {
	// Create a minimal mock structure that satisfies the interface
	// In production, this would be a real *elf.File, but for testing we create
	// a structure that has the required Progs field
	mockFile := &elf.File{
		Progs: make([]*elf.Prog, len(progs)),
	}

	for i, prog := range progs {
		mockFile.Progs[i] = &elf.Prog{
			ProgHeader: elf.ProgHeader{
				Type:  prog.progType,
				Flags: prog.flags,
			},
		}
	}

	return mockFile
}

func TestNX(t *testing.T) {
	tests := []struct {
		name           string
		filename       string
		mockProgs      []mockProgHeader
		expectedOutput string
		expectedColor  string
		description    string
	}{
		{
			name:     "NX enabled - GNU_STACK without execute flag",
			filename: "/test/binary_nx_enabled",
			mockProgs: []mockProgHeader{
				{progType: elf.PT_GNU_STACK, flags: elf.PF_R | elf.PF_W}, // Read+Write, no Execute
			},
			expectedOutput: "NX enabled",
			expectedColor:  "green",
			description:    "Binary with GNU_STACK segment without execute permission should show NX enabled",
		},
		{
			name:     "NX disabled - GNU_STACK with execute flag",
			filename: "/test/binary_nx_disabled",
			mockProgs: []mockProgHeader{
				{progType: elf.PT_GNU_STACK, flags: elf.PF_R | elf.PF_W | elf.PF_X}, // Read+Write+Execute
			},
			expectedOutput: "NX disabled",
			expectedColor:  "red",
			description:    "Binary with GNU_STACK segment with execute permission should show NX disabled",
		},
		{
			name:     "NX disabled - no GNU_STACK segment",
			filename: "/test/binary_no_stack",
			mockProgs: []mockProgHeader{
				{progType: elf.PT_LOAD, flags: elf.PF_R | elf.PF_X}, // Different segment type
			},
			expectedOutput: "NX disabled",
			expectedColor:  "red",
			description:    "Binary without GNU_STACK segment should show NX disabled",
		},
		{
			name:           "N/A - no program headers",
			filename:       "/test/binary_empty",
			mockProgs:      []mockProgHeader{}, // Empty program headers
			expectedOutput: "N/A",
			expectedColor:  "italic",
			description:    "Binary with no program headers should show N/A",
		},
		{
			name:     "NX enabled - multiple segments with GNU_STACK non-executable",
			filename: "/test/binary_multiple_segs",
			mockProgs: []mockProgHeader{
				{progType: elf.PT_LOAD, flags: elf.PF_R | elf.PF_X},
				{progType: elf.PT_GNU_STACK, flags: elf.PF_R | elf.PF_W}, // Non-executable stack
				{progType: elf.PT_DYNAMIC, flags: elf.PF_R},
			},
			expectedOutput: "NX enabled",
			expectedColor:  "green",
			description:    "Binary with multiple segments including non-executable GNU_STACK should show NX enabled",
		},
		{
			name:     "NX disabled - multiple segments with GNU_STACK executable",
			filename: "/test/binary_multiple_exec_stack",
			mockProgs: []mockProgHeader{
				{progType: elf.PT_LOAD, flags: elf.PF_R | elf.PF_X},
				{progType: elf.PT_GNU_STACK, flags: elf.PF_R | elf.PF_W | elf.PF_X}, // Executable stack
				{progType: elf.PT_DYNAMIC, flags: elf.PF_R},
			},
			expectedOutput: "NX disabled",
			expectedColor:  "red",
			description:    "Binary with multiple segments including executable GNU_STACK should show NX disabled",
		},
		{
			name:     "NX enabled - GNU_STACK with only read permission",
			filename: "/test/binary_read_only_stack",
			mockProgs: []mockProgHeader{
				{progType: elf.PT_GNU_STACK, flags: elf.PF_R}, // Read-only stack
			},
			expectedOutput: "NX enabled",
			expectedColor:  "green",
			description:    "Binary with read-only GNU_STACK should show NX enabled",
		},
		{
			name:     "NX enabled - GNU_STACK with no flags",
			filename: "/test/binary_no_flags_stack",
			mockProgs: []mockProgHeader{
				{progType: elf.PT_GNU_STACK, flags: 0}, // No flags set
			},
			expectedOutput: "NX enabled",
			expectedColor:  "green",
			description:    "Binary with GNU_STACK having no flags should show NX enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock ELF file with specified program headers
			mockBinary := createMockElfFile(tt.mockProgs)

			// Call the NX function
			result := NX(tt.filename, mockBinary)

			// Validate results
			if result == nil {
				t.Fatalf("NX() returned nil result")
			}

			if result.Output != tt.expectedOutput {
				t.Errorf("NX() Output = %q, expected %q", result.Output, tt.expectedOutput)
			}

			if result.Color != tt.expectedColor {
				t.Errorf("NX() Color = %q, expected %q", result.Color, tt.expectedColor)
			}

			// Log test description for documentation
			t.Logf("Test case: %s", tt.description)
		})
	}
}

// TestNX_SecurityValidation tests security-specific edge cases
func TestNX_SecurityValidation(t *testing.T) {
	t.Run("nil binary handling", func(t *testing.T) {
		// Test defensive programming - secure implementation should handle nil binary gracefully
		// This validates the security fix per our security rules: "ALWAYS validate input before processing"

		result := NX("test", nil)

		if result == nil {
			t.Fatal("NX() returned nil result for nil binary")
		}

		// Should return error state, not panic
		if result.Output != "Error: Invalid binary" {
			t.Errorf("Expected 'Error: Invalid binary' output for nil binary, got: %q", result.Output)
		}

		if result.Color != "red" {
			t.Errorf("Expected 'red' color for nil binary error, got: %q", result.Color)
		}

		t.Logf("SECURITY FIX VALIDATED: NX() handles nil input gracefully")
	})

	t.Run("DoS protection - excessive program headers", func(t *testing.T) {
		// Test DoS protection per security rule: "ALWAYS implement resource limits to prevent DoS"

		// Create a mock with excessive program headers
		excessiveProgs := make([]mockProgHeader, 15000) // Above the 10,000 limit
		for i := range excessiveProgs {
			excessiveProgs[i] = mockProgHeader{progType: elf.PT_LOAD, flags: elf.PF_R}
		}

		mockBinary := createMockElfFile(excessiveProgs)
		result := NX("/test/dos_test", mockBinary)

		if result == nil {
			t.Fatal("NX() returned nil result for excessive program headers")
		}

		// Should return error state for DoS protection
		if result.Output != "Error: Too many program headers" {
			t.Errorf("Expected DoS protection error, got: %q", result.Output)
		}

		if result.Color != "red" {
			t.Errorf("Expected 'red' color for DoS protection error, got: %q", result.Color)
		}

		t.Logf("DoS PROTECTION VALIDATED: NX() limits program header processing")
	})
}

// TestNX_EdgeCases tests additional edge cases for robustness
func TestNX_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		mockProgs   []mockProgHeader
		description string
	}{
		{
			name:     "very large number of program headers",
			filename: "/test/large_progs",
			mockProgs: func() []mockProgHeader {
				// Create a large number of program headers to test performance
				progs := make([]mockProgHeader, 1000)
				for i := range progs {
					if i == 500 { // Put GNU_STACK in the middle
						progs[i] = mockProgHeader{progType: elf.PT_GNU_STACK, flags: elf.PF_R | elf.PF_W}
					} else {
						progs[i] = mockProgHeader{progType: elf.PT_LOAD, flags: elf.PF_R}
					}
				}
				return progs
			}(),
			description: "Should handle large number of program headers efficiently",
		},
		{
			name:     "mixed flag combinations",
			filename: "/test/mixed_flags",
			mockProgs: []mockProgHeader{
				{progType: elf.PT_GNU_STACK, flags: elf.PF_R | elf.PF_W | elf.PF_X | 0x100}, // Extra flags
			},
			description: "Should handle non-standard flag combinations",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBinary := createMockElfFile(tt.mockProgs)
			result := NX(tt.filename, mockBinary)

			// Should not panic or crash
			if result == nil {
				t.Errorf("NX() returned nil for edge case: %s", tt.description)
			}

			// Should return valid output and color
			if result.Output == "" {
				t.Errorf("NX() returned empty output for: %s", tt.description)
			}

			if result.Color == "" {
				t.Errorf("NX() returned empty color for: %s", tt.description)
			}

			t.Logf("Edge case: %s - Result: %s (%s)", tt.description, result.Output, result.Color)
		})
	}
}

// BenchmarkNX benchmarks the NX function performance
func BenchmarkNX(b *testing.B) {
	// Create a representative mock binary
	mockBinary := createMockElfFile([]mockProgHeader{
		{progType: elf.PT_LOAD, flags: elf.PF_R | elf.PF_X},
		{progType: elf.PT_GNU_STACK, flags: elf.PF_R | elf.PF_W},
		{progType: elf.PT_DYNAMIC, flags: elf.PF_R},
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		result := NX("/test/benchmark", mockBinary)
		if result == nil {
			b.Fatal("NX() returned nil")
		}
	}
}

// TestNX_ReturnValueValidation ensures return values are always valid
func TestNX_ReturnValueValidation(t *testing.T) {
	testCases := [][]mockProgHeader{
		{}, // Empty
		{{progType: elf.PT_GNU_STACK, flags: elf.PF_R | elf.PF_W}},            // NX enabled
		{{progType: elf.PT_GNU_STACK, flags: elf.PF_R | elf.PF_W | elf.PF_X}}, // NX disabled
		{{progType: elf.PT_LOAD, flags: elf.PF_R | elf.PF_X}},                 // No GNU_STACK
	}

	validOutputs := map[string]bool{
		"NX enabled":  true,
		"NX disabled": true,
		"N/A":         true,
	}

	validColors := map[string]bool{
		"green":  true,
		"red":    true,
		"italic": true,
	}

	for i, progs := range testCases {
		t.Run(fmt.Sprintf("validation_case_%d", i), func(t *testing.T) {
			mockBinary := createMockElfFile(progs)
			result := NX("test", mockBinary)

			if result == nil {
				t.Fatal("NX() returned nil")
			}

			if !validOutputs[result.Output] {
				t.Errorf("Invalid output value: %q", result.Output)
			}

			if !validColors[result.Color] {
				t.Errorf("Invalid color value: %q", result.Color)
			}
		})
	}
}
