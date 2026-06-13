package checksec

import (
	"debug/elf"
	"testing"
)

// TestClassifyPIE drives the pure classifier. The DSO/PIE distinction is the
// regression guard: an ET_DYN with neither DF_1_PIE nor PT_INTERP is a shared
// library, not a position-independent executable.
func TestClassifyPIE(t *testing.T) {
	tests := []struct {
		name       string
		elfType    elf.Type
		hasInterp  bool
		flags1     []uint64
		wantValue  string
		wantStatus Status
	}{
		{"ET_EXEC → disabled", elf.ET_EXEC, true, nil, "PIE Disabled", StatusBad},
		{"ET_NONE → disabled", elf.ET_NONE, false, nil, "PIE Disabled", StatusBad},
		{"ET_REL → REL", elf.ET_REL, false, nil, "REL", StatusWarn},
		{"ET_DYN + DF_1_PIE + no interp → Static PIE", elf.ET_DYN, false, []uint64{uint64(elf.DF_1_PIE)}, "Static PIE", StatusGood},
		{"ET_DYN + DF_1_PIE + interp → PIE", elf.ET_DYN, true, []uint64{uint64(elf.DF_1_PIE)}, "PIE Enabled", StatusGood},
		{"ET_DYN + DF_1_PIE among others → PIE", elf.ET_DYN, true, []uint64{uint64(elf.DF_1_NOW | elf.DF_1_PIE)}, "PIE Enabled", StatusGood},
		{"ET_DYN + PT_INTERP, no DF_1_PIE → PIE (older toolchain)", elf.ET_DYN, true, nil, "PIE Enabled", StatusGood},
		{"ET_DYN + PT_INTERP, flags1 without PIE bit → PIE", elf.ET_DYN, true, []uint64{uint64(elf.DF_1_NOW)}, "PIE Enabled", StatusGood},
		{"ET_DYN, no interp, no DF_1_PIE → DSO", elf.ET_DYN, false, nil, "DSO", StatusInfo},
		{"ET_DYN, no interp, flags1 without PIE bit → DSO", elf.ET_DYN, false, []uint64{uint64(elf.DF_1_NOW)}, "DSO", StatusInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, s := classifyPIE(tt.elfType, tt.hasInterp, tt.flags1)
			if v != tt.wantValue || s != tt.wantStatus {
				t.Errorf("classifyPIE(%v, interp=%v, flags1=%v) = (%q, %q), want (%q, %q)",
					tt.elfType, tt.hasInterp, tt.flags1, v, s, tt.wantValue, tt.wantStatus)
			}
		})
	}
}

func TestPIE_RealELF(t *testing.T) {
	// A static Go linux/amd64 binary is ET_EXEC → PIE Disabled.
	ef, _ := openELF(t, buildLinuxELF(t))
	res := PIE(ef)
	if res.Value != "PIE Disabled" || res.Status != StatusBad {
		t.Errorf("PIE(static go elf) = %+v, want {PIE Disabled, StatusBad}", res)
	}
}

func TestPIE_DSOFixture(t *testing.T) {
	// dso.so is a shared library (ET_DYN, no PT_INTERP, no DF_1_PIE).
	ef, _ := openELF(t, requireFixture(t, "dso.so"))
	res := PIE(ef)
	if res.Value != "DSO" {
		t.Errorf("PIE(dso.so) = %+v, want DSO", res)
	}
}
