package checksec

import (
	"debug/elf"
	"testing"
)

func TestPIE(t *testing.T) {
	tests := []struct {
		name           string
		elfType        elf.Type
		expectedOutput string
		expectedColor  string
	}{
		{"ET_DYN is PIE enabled", elf.ET_DYN, "PIE Enabled", "green"},
		{"ET_REL is REL", elf.ET_REL, "REL", "yellow"},
		{"ET_EXEC is PIE disabled", elf.ET_EXEC, "PIE Disabled", "red"},
		{"ET_NONE is PIE disabled", elf.ET_NONE, "PIE Disabled", "red"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binary := &elf.File{FileHeader: elf.FileHeader{Type: tt.elfType}}
			result := PIE("test", binary)
			if result == nil {
				t.Fatal("PIE() returned nil")
			}
			if result.Output != tt.expectedOutput {
				t.Errorf("Output = %q, want %q", result.Output, tt.expectedOutput)
			}
			if result.Color != tt.expectedColor {
				t.Errorf("Color = %q, want %q", result.Color, tt.expectedColor)
			}
		})
	}
}
