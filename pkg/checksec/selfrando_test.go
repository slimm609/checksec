package checksec

import (
	"debug/elf"
	"testing"
)

// TestHasSelfrandoSection drives the section-name predicate. checksec.bash:759
// matches any section name containing "txtrp" (selfrando emits ".txtrp").
func TestHasSelfrandoSection(t *testing.T) {
	mk := func(names ...string) *elf.File {
		f := &elf.File{}
		for _, n := range names {
			f.Sections = append(f.Sections, &elf.Section{SectionHeader: elf.SectionHeader{Name: n}})
		}
		return f
	}
	tests := []struct {
		name string
		file *elf.File
		want bool
	}{
		{"no sections", mk(), false},
		{"standard sections only", mk(".text", ".data", ".rodata"), false},
		{".txtrp present", mk(".text", ".txtrp", ".data"), true},
		{"suffixed .txtrp.hot", mk(".txtrp.hot"), true},
		{"substring match (bash parity)", mk(".foo.txtrp.bar"), true},
		{"near-miss", mk(".txt", ".trp"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasSelfrandoSection(tt.file); got != tt.want {
				t.Errorf("hasSelfrandoSection(%v) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestSelfrando_Result(t *testing.T) {
	mk := func(names ...string) *elf.File {
		f := &elf.File{}
		for _, n := range names {
			f.Sections = append(f.Sections, &elf.Section{SectionHeader: elf.SectionHeader{Name: n}})
		}
		return f
	}
	if r := Selfrando(mk(".txtrp")); r.Value != "Enabled" || r.Status != StatusGood {
		t.Errorf("Selfrando(.txtrp) = %+v, want {Enabled, StatusGood}", r)
	}
	if r := Selfrando(mk(".text")); r.Value != "No Selfrando" || r.Status != StatusInfo {
		t.Errorf("Selfrando(.text) = %+v, want {No Selfrando, StatusInfo}", r)
	}
}

func TestSelfrando_RealELF(t *testing.T) {
	ef, _ := openELF(t, buildLinuxELF(t))
	res := Selfrando(ef)
	if res.Value != "No Selfrando" {
		t.Errorf("expected No Selfrando for plain Go ELF, got %+v", res)
	}
}
