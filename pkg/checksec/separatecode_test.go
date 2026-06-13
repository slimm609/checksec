package checksec

import (
	"debug/elf"
	"testing"
)

// mkProgs builds an *elf.File with PT_LOAD segments carrying the given flag
// sets (plus an unrelated PT_NOTE to ensure non-LOAD segments are ignored).
func mkProgs(loads ...elf.ProgFlag) *elf.File {
	f := &elf.File{}
	for _, fl := range loads {
		f.Progs = append(f.Progs, &elf.Prog{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: fl}})
	}
	f.Progs = append(f.Progs, &elf.Prog{ProgHeader: elf.ProgHeader{Type: elf.PT_NOTE, Flags: elf.PF_R | elf.PF_W | elf.PF_X}})
	return f
}

// TestSeparateCode verifies the W^X-at-segment-level check (-z separate-code /
// --rosegment): no PT_LOAD segment may be both writable and executable.
func TestSeparateCode(t *testing.T) {
	tests := []struct {
		name       string
		file       *elf.File
		wantValue  string
		wantStatus Status
	}{
		{"typical -z separate-code layout (R, RX, RW)",
			mkProgs(elf.PF_R, elf.PF_R|elf.PF_X, elf.PF_R|elf.PF_W),
			"Enabled", StatusGood},
		{"legacy layout (RX, RW) — still W^X",
			mkProgs(elf.PF_R|elf.PF_X, elf.PF_R|elf.PF_W),
			"Enabled", StatusGood},
		{"single RWX segment",
			mkProgs(elf.PF_R | elf.PF_W | elf.PF_X),
			"WX Segment", StatusBad},
		{"WX segment among clean ones",
			mkProgs(elf.PF_R|elf.PF_X, elf.PF_W|elf.PF_X, elf.PF_R|elf.PF_W),
			"WX Segment", StatusBad},
		{"no PT_LOAD",
			&elf.File{},
			"N/A", StatusNA},
		{"exec-only and write-only",
			mkProgs(elf.PF_X, elf.PF_W),
			"Enabled", StatusGood},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := SeparateCode(tt.file)
			if r.Value != tt.wantValue || r.Status != tt.wantStatus {
				t.Errorf("SeparateCode() = %+v, want {%q, %q}", r, tt.wantValue, tt.wantStatus)
			}
		})
	}
}

func TestSeparateCode_RealELF(t *testing.T) {
	ef, _ := openELF(t, buildLinuxELF(t))
	res := SeparateCode(ef)
	// Go's linker emits clean R/RX/RW segments — must be Enabled.
	if res.Value != "Enabled" || res.Status != StatusGood {
		t.Errorf("SeparateCode(go elf) = %+v, want {Enabled, StatusGood}", res)
	}
}
