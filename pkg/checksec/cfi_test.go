package checksec

import (
	"debug/elf"
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

func TestCfi_LinuxELFNoNotes(t *testing.T) {
	// A pure-Go binary has no .note.gnu.property → Unknown.
	ef, _ := openELF(t, buildLinuxELF(t))
	res := Cfi(ef)
	if res.Value != "Unknown" || res.Status != StatusWarn {
		t.Fatalf("expected Unknown/StatusWarn, got %+v", res)
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
	cfi := &Result{}
	resUnknown(cfi)

	if cfi.Status != StatusWarn {
		t.Errorf("Expected status %q, got %q", StatusWarn, cfi.Status)
	}

	if cfi.Value != "Unknown" {
		t.Errorf("Expected value 'Unknown', got %q", cfi.Value)
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
