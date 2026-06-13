package checksec

import (
	"debug/elf"
	"encoding/binary"
	"testing"
)

// TestParseRiscvCFIFromNotes verifies the RISC-V Zicfilp/Zicfiss property
// parser. Per binutils include/elf/common.h:
//
//	GNU_PROPERTY_RISCV_FEATURE_1_AND            = 0xc0000000
//	GNU_PROPERTY_RISCV_FEATURE_1_CFI_LP_UNLABELED = 1<<0
//	GNU_PROPERTY_RISCV_FEATURE_1_CFI_SS           = 1<<1
func TestParseRiscvCFIFromNotes(t *testing.T) {
	le := binary.LittleEndian
	tests := []struct {
		name string
		mask uint32
		want riscvCFI
	}{
		{"none", 0, riscvCFI{}},
		{"LP only", GnuPropertyRiscvFeatureCFILP, riscvCFI{lp: true}},
		{"SS only", GnuPropertyRiscvFeatureCFISS, riscvCFI{ss: true}},
		{"both", GnuPropertyRiscvFeatureCFILP | GnuPropertyRiscvFeatureCFISS, riscvCFI{lp: true, ss: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			note := buildPropertyNote(le, GnuPropertyRiscvFeature1Flag, tt.mask)
			got := parseRiscvCFIFromNotes(note, le, 8)
			if got != tt.want {
				t.Errorf("parseRiscvCFIFromNotes(mask=%#x) = %+v, want %+v", tt.mask, got, tt.want)
			}
		})
	}
}

func TestRiscvOutputString(t *testing.T) {
	tests := []struct {
		in         riscvCFI
		wantOut    string
		wantStatus Status
	}{
		{riscvCFI{lp: true, ss: true}, "Zicfilp & Zicfiss", StatusGood},
		{riscvCFI{lp: true}, "Zicfilp & NO Zicfiss", StatusWarn},
		{riscvCFI{ss: true}, "NO Zicfilp & Zicfiss", StatusWarn},
		{riscvCFI{}, "NO Zicfilp & NO Zicfiss", StatusBad},
	}
	for _, tt := range tests {
		out, st := riscvOutputString(tt.in)
		if out != tt.wantOut || st != tt.wantStatus {
			t.Errorf("riscvOutputString(%+v) = (%q, %q), want (%q, %q)", tt.in, out, st, tt.wantOut, tt.wantStatus)
		}
	}
}

// TestParseX86CETFromNotes_ELFCLASS32 asserts the x86 CET parser handles the
// 4-byte property alignment used for i386 (ELFCLASS32) binaries.
func TestParseX86CETFromNotes_ELFCLASS32(t *testing.T) {
	le := binary.LittleEndian
	// ELFCLASS32 properties are 4-byte aligned: type(4)|datasz(4)|mask(4) — no
	// trailing pad. Two consecutive 12-byte records.
	mk := func(mask uint32) []byte {
		b := make([]byte, 12)
		le.PutUint32(b[0:4], GnuPropertyX86Feature1Flag)
		le.PutUint32(b[4:8], 4)
		le.PutUint32(b[8:12], mask)
		return b
	}
	data := append(mk(GnuPropertyX86FeatureIBT), mk(GnuPropertyX86FeatureSHSTK)...)
	got := parseX86CETFromNotes(data, le, 4)
	// Last record wins (parser semantics) → SHSTK only.
	if !got.shstk || got.ibt {
		t.Errorf("ELFCLASS32 parse: got %+v, want {shstk:true, ibt:false}", got)
	}
}

// TestHwCFIDispatch asserts the per-arch dispatch covers i386 and RISC-V.
func TestHwCFIDispatch(t *testing.T) {
	tests := []struct {
		machine elf.Machine
		class   elf.Class
		want    bool // should produce a non-empty hwOutput (vs falling through to Unknown)
	}{
		{elf.EM_X86_64, elf.ELFCLASS64, true},
		{elf.EM_386, elf.ELFCLASS32, true},
		{elf.EM_AARCH64, elf.ELFCLASS64, true},
		{elf.EM_RISCV, elf.ELFCLASS64, true},
		{elf.EM_RISCV, elf.ELFCLASS32, true},
		{elf.EM_MIPS, elf.ELFCLASS64, false},
	}
	for _, tt := range tests {
		out, _ := hwCFIDispatch(tt.machine, tt.class, nil, binary.LittleEndian)
		if (out != "") != tt.want {
			t.Errorf("hwCFIDispatch(%v, %v) out=%q, want non-empty=%v", tt.machine, tt.class, out, tt.want)
		}
	}
}
