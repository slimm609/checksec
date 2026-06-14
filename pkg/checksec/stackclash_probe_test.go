package checksec

import (
	"debug/elf"
	"testing"
)

func TestStackClashProbePattern(t *testing.T) {
	tests := []struct {
		arch elf.Machine
		want []byte
	}{
		{elf.EM_X86_64, []byte{0x48, 0x83, 0x0c, 0x24, 0x00}}, // orq $0,(%rsp)
		{elf.EM_386, []byte{0x83, 0x0c, 0x24, 0x00}},          // orl $0,(%esp)
		{elf.EM_AARCH64, []byte{0xff, 0x03, 0x00, 0xf9}},      // str xzr,[sp]
		{elf.EM_RISCV, nil},
		{elf.EM_PPC64, nil},
	}
	for _, tt := range tests {
		got := stackClashProbePattern(tt.arch)
		if string(got) != string(tt.want) {
			t.Errorf("stackClashProbePattern(%v) = %x, want %x", tt.arch, got, tt.want)
		}
	}
}

// TestProbeScanResult drives the pure scan core.
func TestProbeScanResult(t *testing.T) {
	pat := stackClashProbePattern(elf.EM_X86_64)
	tests := []struct {
		name     string
		sections [][]byte
		cap      int
		want     string
	}{
		{"probe in first section", [][]byte{append([]byte{0x90}, pat...)}, 1 << 20, "Likely Enabled"},
		{"probe in second section", [][]byte{{0x90, 0xc3}, pat}, 1 << 20, "Likely Enabled"},
		{"no probe", [][]byte{{0x90, 0xc3}}, 1 << 20, "No Probes"},
		{"no sections", nil, 1 << 20, "No Probes"},
		{"probe beyond cap not found", [][]byte{append(make([]byte, 100), pat...)}, 50, "No Probes"},
		{"probe at cap boundary found", [][]byte{append(make([]byte, 45), pat...)}, 50, "Likely Enabled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := probeScanResult(tt.sections, pat, tt.cap)
			if r.Value != tt.want {
				t.Errorf("probeScanResult() = %q, want %q", r.Value, tt.want)
			}
		})
	}
}

func TestStackClashProbeScan_UnsupportedArch(t *testing.T) {
	f := &elf.File{FileHeader: elf.FileHeader{Machine: elf.EM_MIPS}}
	if r := stackClashProbeScan(f); r != nil {
		t.Errorf("expected nil for unsupported arch, got %+v", r)
	}
}

// TestStackClash_AnnobinOverridesProbeScan asserts annobin verdict (when
// present) takes precedence over the heuristic.
func TestStackClash_AnnobinOverridesProbeScan(t *testing.T) {
	if scDisabled.merge(scEnabled) != scDisabled {
		t.Error("annobin Disabled must override")
	}
	if scEnabled.merge(scUnknown) != scEnabled {
		t.Error("annobin Enabled must override Unknown")
	}
}

func TestStackClashProbeScan_RealELF(t *testing.T) {
	// Go binary on x86-64: supported arch, no probes expected.
	ef, _ := openELF(t, buildLinuxELF(t))
	r := stackClashProbeScan(ef)
	if r == nil {
		t.Fatal("expected result for x86-64 ELF")
	}
	if r.Value != "No Probes" {
		t.Errorf("expected No Probes for Go binary, got %+v", r)
	}
}
