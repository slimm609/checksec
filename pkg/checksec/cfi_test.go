package checksec

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"
)

func TestX86CFI(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected x86CET
	}{
		{"no shstk & no ibt", 0, x86CET{shstk: false, ibt: false}},
		{"no shstk & ibt", 1, x86CET{shstk: false, ibt: true}},
		{"shstk & no ibt", 2, x86CET{shstk: true, ibt: false}},
		{"shstk & ibt", 3, x86CET{shstk: true, ibt: true}},
		{"additional bits set", 0xFFFFFFFF, x86CET{shstk: true, ibt: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := parseBitmaskForx86CET(tt.input)
			if res != tt.expected {
				t.Errorf("got %v, want %v", res, tt.expected)
			}
		})
	}
}

func TestArmPACBTI(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected armPACBTI
	}{
		{"no pac & no bti", 0, armPACBTI{pac: false, bti: false}},
		{"no pac & bti", 1, armPACBTI{pac: false, bti: true}},
		{"pac & no bti", 2, armPACBTI{pac: true, bti: false}},
		{"pac & bti", 3, armPACBTI{pac: true, bti: true}},
		{"additional bits set", 0xFFFFFFFF, armPACBTI{pac: true, bti: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := parseBitmaskForArmPACBTI(tt.input)
			if res != tt.expected {
				t.Errorf("got %v, want %v", res, tt.expected)
			}
		})
	}
}

func TestCfi_InputValidation(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty filename",
			filename:    "",
			expectError: true,
			errorMsg:    "filename cannot be empty",
		},
		{
			name:        "non-existent file",
			filename:    "/path/to/nonexistent/file",
			expectError: true,
			errorMsg:    "cannot access file",
		},
		{
			name:        "directory traversal attempt",
			filename:    "../../../etc/passwd",
			expectError: true,
			errorMsg:    "cannot access file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Cfi(tt.filename)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if result == nil {
					t.Errorf("Expected result but got nil")
				}
			}
		})
	}
}

func TestCfi_InvalidELF(t *testing.T) {
	// Create a temporary file that's not an ELF
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write some non-ELF content
	_, err = tmpFile.WriteString("This is not an ELF file")
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	result, err := Cfi(tmpFile.Name())

	if err == nil {
		t.Errorf("Expected error for non-ELF file, but got none")
		return
	}
	if !contains(err.Error(), "invalid ELF file") {
		t.Errorf("Expected 'invalid ELF file' error, got: %s", err.Error())
	}
	if result != nil {
		t.Errorf("Expected nil result for error case, got: %v", result)
	}
}

func TestCfi_PathTraversal(t *testing.T) {
	// Test various path traversal attempts
	maliciousPaths := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"....//....//....//etc/passwd",
		"/tmp/../../../etc/passwd",
	}

	for _, path := range maliciousPaths {
		t.Run("path_traversal_"+filepath.Base(path), func(t *testing.T) {
			result, err := Cfi(path)

			// Should either fail with access error or be cleaned by filepath.Clean
			if err == nil {
				// If it doesn't error, the path should have been cleaned
				cleanPath := filepath.Clean(path)
				if cleanPath == path {
					t.Errorf("Path traversal attempt should have been cleaned or failed: %s", path)
				}
			} else {
				// Should fail with access error or invalid ELF file error
				if !contains(err.Error(), "cannot access file") && !contains(err.Error(), "invalid ELF file") {
					t.Errorf("Expected access error or invalid ELF file error for path traversal, got: %s", err.Error())
				}
			}

			if result != nil {
				t.Errorf("Expected nil result for malicious path, got: %v", result)
			}
		})
	}
}

func TestParseBitmaskForx86CET_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected x86CET
	}{
		{"zero", 0, x86CET{shstk: false, ibt: false}},
		{"max uint32", 0xFFFFFFFF, x86CET{shstk: true, ibt: true}},
		{"only shstk", GnuPropertyX86FeatureSHSTK, x86CET{shstk: true, ibt: false}},
		{"only ibt", GnuPropertyX86FeatureIBT, x86CET{shstk: false, ibt: true}},
		{"both flags", GnuPropertyX86FeatureSHSTK | GnuPropertyX86FeatureIBT, x86CET{shstk: true, ibt: true}},
		{"other bits set", 0xFFFFFFFC, x86CET{shstk: false, ibt: false}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := parseBitmaskForx86CET(tt.input)
			if res != tt.expected {
				t.Errorf("got %v, want %v", res, tt.expected)
			}
		})
	}
}

func TestParseBitmaskForArmPACBTI_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected armPACBTI
	}{
		{"zero", 0, armPACBTI{pac: false, bti: false}},
		{"max uint32", 0xFFFFFFFF, armPACBTI{pac: true, bti: true}},
		{"only pac", GnuPropertyArmFeaturePAC, armPACBTI{pac: true, bti: false}},
		{"only bti", GnuPropertyArmFeatureBTI, armPACBTI{pac: false, bti: true}},
		{"both flags", GnuPropertyArmFeaturePAC | GnuPropertyArmFeatureBTI, armPACBTI{pac: true, bti: true}},
		{"other bits set", 0xFFFFFFFC, armPACBTI{pac: false, bti: false}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := parseBitmaskForArmPACBTI(tt.input)
			if res != tt.expected {
				t.Errorf("got %v, want %v", res, tt.expected)
			}
		})
	}
}

func TestResUnknown(t *testing.T) {
	cfi := &CfiResult{}
	resUnknown(cfi)

	if cfi.Color != "yellow" {
		t.Errorf("Expected color 'yellow', got '%s'", cfi.Color)
	}

	if cfi.Output != "Unknown" {
		t.Errorf("Expected output 'Unknown', got '%s'", cfi.Output)
	}
}

// Test constants to ensure they're correctly defined
func TestConstants(t *testing.T) {
	// Test x86 constants
	if GnuPropertyX86FeatureIBT != 1 {
		t.Errorf("Expected GnuPropertyX86FeatureIBT to be 1, got %d", GnuPropertyX86FeatureIBT)
	}
	if GnuPropertyX86FeatureSHSTK != 2 {
		t.Errorf("Expected GnuPropertyX86FeatureSHSTK to be 2, got %d", GnuPropertyX86FeatureSHSTK)
	}

	// Test ARM constants
	if GnuPropertyArmFeatureBTI != 1 {
		t.Errorf("Expected GnuPropertyArmFeatureBTI to be 1, got %d", GnuPropertyArmFeatureBTI)
	}
	if GnuPropertyArmFeaturePAC != 2 {
		t.Errorf("Expected GnuPropertyArmFeaturePAC to be 2, got %d", GnuPropertyArmFeaturePAC)
	}

	// Test flag constants
	if GnuPropertyArmFeature1Flag != 0xc0000000 {
		t.Errorf("Expected GnuPropertyArmFeature1Flag to be 0xc0000000, got 0x%x", GnuPropertyArmFeature1Flag)
	}
	if GnuPropertyX86Feature1Flag != 0xc0000002 {
		t.Errorf("Expected GnuPropertyX86Feature1Flag to be 0xc0000002, got 0x%x", GnuPropertyX86Feature1Flag)
	}
}

func TestClassifyClangCFIMode_None(t *testing.T) {
	if got := classifyClangCFIMode(nil, nil); got != "none" {
		t.Fatalf("expected none, got %s", got)
	}
}

func TestClassifyClangCFIMode_SingleModule(t *testing.T) {
	all := []elf.Symbol{
		{Name: "__cfi_slowpath", Section: 1},
		{Name: "__cfi_check", Section: 1}, // defined locally
	}
	dyn := []elf.Symbol{}
	if got := classifyClangCFIMode(all, dyn); got != "single" {
		t.Fatalf("expected single, got %s", got)
	}
}

func TestClassifyClangCFIMode_MultiModule(t *testing.T) {
	// dynamic symbol table contains exported __cfi_check
	dyn := []elf.Symbol{{
		Name:    "__cfi_check",
		Section: 1, // not SHN_UNDEF
		Info:    byte(elf.STB_GLOBAL<<4) | byte(elf.STT_FUNC&0x0f),
		Other:   byte(elf.STV_DEFAULT),
	}}
	if got := classifyClangCFIMode(nil, dyn); got != "multi" {
		t.Fatalf("expected multi, got %s", got)
	}
}

// Benchmark tests for performance
func BenchmarkParseBitmaskForx86CET(b *testing.B) {
	for i := 0; i < b.N; i++ {
		parseBitmaskForx86CET(0xFFFFFFFF)
	}
}

func BenchmarkParseBitmaskForArmPACBTI(b *testing.B) {
	for i := 0; i < b.N; i++ {
		parseBitmaskForArmPACBTI(0xFFFFFFFF)
	}
}
