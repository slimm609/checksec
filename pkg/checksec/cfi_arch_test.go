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

// TestGNUPropertyPayload verifies the ELF note wrapper (namesz/descsz/type/
// "GNU\0") is stripped before walking the property array. Section.Data()
// returns the FULL section bytes — see Go stdlib testdata/libtiffxx.so_:
//
//	04 00 00 00 10 00 00 00 05 00 00 00 47 4e 55 00  ← note header + name
//	02 00 00 c0 04 00 00 00 03 00 00 00 00 00 00 00  ← property array (desc)
//
// PR #345 review: walking from offset 0 misreads namesz as pr_type and yields
// "NO SHSTK & NO IBT" for a binary that has both.
func TestGNUPropertyPayload(t *testing.T) {
	le := binary.LittleEndian
	// Exact bytes from Go stdlib debug/elf/testdata/libtiffxx.so_ section.
	raw := []byte{
		0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x05, 0x00, 0x00, 0x00, 'G', 'N', 'U', 0x00,
		0x02, 0x00, 0x00, 0xc0, 0x04, 0x00, 0x00, 0x00,
		0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	desc := gnuPropertyPayload(raw, le)
	if len(desc) != 16 || desc[0] != 0x02 {
		t.Fatalf("gnuPropertyPayload returned wrong slice: len=%d %x", len(desc), desc)
	}
	got := parseX86CETFromNotes(desc, le, 8)
	if !got.ibt || !got.shstk {
		t.Errorf("parseX86CETFromNotes after header strip = %+v, want {shstk:true ibt:true}", got)
	}
}

func TestGNUPropertyPayload_Malformed(t *testing.T) {
	le := binary.LittleEndian
	tests := []struct {
		name string
		raw  []byte
	}{
		{"too short", []byte{0x04, 0x00}},
		{"wrong name", append([]byte{4, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0}, []byte("XXX\x00abcd")...)},
		{"wrong type", append([]byte{4, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0}, []byte("GNU\x00abcd")...)},
		{"descsz overruns", append([]byte{4, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 5, 0, 0, 0}, []byte("GNU\x00")...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gnuPropertyPayload(tt.raw, le); got != nil {
				t.Errorf("expected nil for %s, got %x", tt.name, got)
			}
		})
	}
}

// TestGNUPropertyPayloadAArch64FwdPAC exercises the full section-level path
// (note wrapper strip → property walk) for an AArch64 binary carrying both
// FEATURE_1 (pac-ret + BTI) and FEATURE_PAUTH (-fptrauth-calls) properties,
// as LLVM 19+ emits them.
func TestGNUPropertyPayloadAArch64FwdPAC(t *testing.T) {
	le := binary.LittleEndian

	feat := buildPropertyNote(le, GnuPropertyArmFeature1Flag, GnuPropertyArmFeaturePAC|GnuPropertyArmFeatureBTI)
	pauth := buildPauthNote(le, 1, 1)
	desc := append(feat, pauth...)

	raw := make([]byte, 16, 16+len(desc))
	le.PutUint32(raw[0:4], 4)                 // namesz
	le.PutUint32(raw[4:8], uint32(len(desc))) // descsz
	le.PutUint32(raw[8:12], 5)                // NT_GNU_PROPERTY_TYPE_0
	copy(raw[12:16], "GNU\x00")
	raw = append(raw, desc...)

	payload := gnuPropertyPayload(raw, le)
	if payload == nil {
		t.Fatalf("gnuPropertyPayload rejected well-formed AArch64 note section")
	}
	got := parseArmPACBTIFromNotes(payload, le, 8)
	if !got.pac || !got.fwd || !got.bti {
		t.Fatalf("AArch64 fwd+backward PAC parse = %+v, want {pac,fwd,bti} all true", got)
	}
}

// TestCfi_RealELFWithCET uses the Go stdlib's own ELF test fixture (always
// present) which carries .note.gnu.property with IBT+SHSTK. End-to-end
// regression guard for the note-header-offset bug.
func TestCfi_RealELFWithCET(t *testing.T) {
	path := goStdlibELFFixture(t, "libtiffxx.so_")
	ef, _ := openELF(t, path)
	res := Cfi(ef)
	if res.Value != "SHSTK & IBT" {
		t.Errorf("Cfi(%s) = %+v, want SHSTK & IBT", path, res)
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
