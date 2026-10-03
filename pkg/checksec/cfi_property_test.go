package checksec

import (
	"debug/elf"
	"encoding/binary"
	"testing"

	"pgregory.net/rapid"
)

func TestCetOutputString(t *testing.T) {
	cases := []struct {
		in         x86CET
		wantOut    string
		wantStatus Status
	}{
		{x86CET{shstk: true, ibt: true}, "SHSTK & IBT", StatusGood},
		{x86CET{shstk: true, ibt: false}, "SHSTK & NO IBT", StatusWarn},
		{x86CET{shstk: false, ibt: true}, "NO SHSTK & IBT", StatusWarn},
		{x86CET{shstk: false, ibt: false}, "NO SHSTK & NO IBT", StatusBad},
	}
	for _, c := range cases {
		gotOut, gotStatus := cetOutputString(c.in)
		if gotOut != c.wantOut || gotStatus != c.wantStatus {
			t.Errorf("cetOutputString(%+v) = %q/%q, want %q/%q", c.in, gotOut, gotStatus, c.wantOut, c.wantStatus)
		}
	}
}

func TestArmOutputString(t *testing.T) {
	cases := []struct {
		in         armPACBTI
		wantOut    string
		wantStatus Status
	}{
		// great: fine-grained forward (FwdPAC) + backward (PAC)
		{armPACBTI{pac: true, fwd: true, bti: true}, "PAC & FwdPAC & BTI", StatusGreat},
		{armPACBTI{pac: true, fwd: true, bti: false}, "PAC & FwdPAC & NO BTI", StatusGreat},
		// good: coarse-grained forward (BTI) + backward (PAC)
		{armPACBTI{pac: true, bti: true}, "PAC & BTI", StatusGood},
		// warn: only one of forward/backward enabled
		{armPACBTI{pac: true, bti: false}, "PAC & NO BTI", StatusWarn},
		{armPACBTI{pac: false, bti: true}, "NO PAC & BTI", StatusWarn},
		{armPACBTI{fwd: true, bti: true}, "FwdPAC & BTI", StatusWarn},
		{armPACBTI{fwd: true, bti: false}, "FwdPAC & NO BTI", StatusWarn},
		// bad: neither
		{armPACBTI{pac: false, bti: false}, "NO PAC & NO BTI", StatusBad},
	}
	for _, c := range cases {
		gotOut, gotStatus := armOutputString(c.in)
		if gotOut != c.wantOut || gotStatus != c.wantStatus {
			t.Errorf("armOutputString(%+v) = %q/%q, want %q/%q", c.in, gotOut, gotStatus, c.wantOut, c.wantStatus)
		}
	}
}

// parseBitmaskForx86CET must set exactly the IBT/SHSTK flags corresponding to
// the GNU property feature bits, independent of any other bits in the mask.
func TestProp_X86Bitmask_Oracle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := rapid.Uint32().Draw(t, "mask")
		got := parseBitmaskForx86CET(m)
		wantIBT := m&GnuPropertyX86FeatureIBT != 0
		wantSHSTK := m&GnuPropertyX86FeatureSHSTK != 0
		if got.ibt != wantIBT || got.shstk != wantSHSTK {
			t.Fatalf("mask=%#x got=%+v want ibt=%v shstk=%v", m, got, wantIBT, wantSHSTK)
		}
	})
}

// parseBitmaskForArmPACBTI must set exactly the PAC/BTI flags corresponding to
// the GNU property feature bits.
func TestProp_ArmBitmask_Oracle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := rapid.Uint32().Draw(t, "mask")
		got := parseBitmaskForArmPACBTI(m)
		wantBTI := m&GnuPropertyArmFeatureBTI != 0
		wantPAC := m&GnuPropertyArmFeaturePAC != 0
		if got.bti != wantBTI || got.pac != wantPAC {
			t.Fatalf("mask=%#x got=%+v want bti=%v pac=%v", m, got, wantBTI, wantPAC)
		}
	})
}

// buildPropertyNote assembles one .note.gnu.property record for a 4-byte feature
// bitmask: type(4) | datasz(4)=4 | bitmask(4) | pad(4), matching the layout the
// parser expects for ELFCLASS64.
func buildPropertyNote(bo binary.ByteOrder, noteType, bitmask uint32) []byte {
	b := make([]byte, 16)
	bo.PutUint32(b[0:4], noteType)
	bo.PutUint32(b[4:8], 4)
	bo.PutUint32(b[8:12], bitmask)
	return b
}

// buildPropertyNoteRaw builds a property record with an explicit datasz and
// payload, padded to 8-byte (ELFCLASS64) alignment: type(4) | datasz(4) |
// payload(datasz) | pad. Used to test records the parser must skip over.
func buildPropertyNoteRaw(bo binary.ByteOrder, noteType, datasz uint32, payload []byte) []byte {
	padded := (int(datasz) + 7) &^ 7
	b := make([]byte, 8+padded)
	bo.PutUint32(b[0:4], noteType)
	bo.PutUint32(b[4:8], datasz)
	copy(b[8:], payload)
	return b
}

// A non-feature property whose datasz is not 4 (e.g. GNU_PROPERTY_STACK_SIZE,
// datasz=8) must be skipped by its full padded length so a following x86 feature
// property is still found, rather than desyncing the scan.
func TestX86Notes_SkipsNon4ByteProperty(t *testing.T) {
	bo := binary.LittleEndian
	// Payload whose second word encodes datasz=4 (LE): if the parser mis-walks
	// into the payload it will treat this as a header and desync the scan.
	lead := buildPropertyNoteRaw(bo, 0x0001, 8, []byte{0, 0, 0, 0, 4, 0, 0, 0})
	feat := buildPropertyNote(bo, GnuPropertyX86Feature1Flag, GnuPropertyX86FeatureIBT|GnuPropertyX86FeatureSHSTK)
	data := append(lead, feat...)

	got := parseX86CETFromNotes(data, bo, 8)
	if !got.ibt || !got.shstk {
		t.Fatalf("feature property after an 8-byte property was missed: %+v", got)
	}
}

// Same requirement for the AArch64 PAC/BTI parser.
func TestArmNotes_SkipsNon4ByteProperty(t *testing.T) {
	bo := binary.LittleEndian
	// Payload whose second word encodes datasz=4 (LE): if the parser mis-walks
	// into the payload it will treat this as a header and desync the scan.
	lead := buildPropertyNoteRaw(bo, 0x0001, 8, []byte{0, 0, 0, 0, 4, 0, 0, 0})
	feat := buildPropertyNote(bo, GnuPropertyArmFeature1Flag, GnuPropertyArmFeaturePAC|GnuPropertyArmFeatureBTI)
	data := append(lead, feat...)

	got := parseArmPACBTIFromNotes(data, bo, 8)
	if !got.pac || !got.bti {
		t.Fatalf("feature property after an 8-byte property was missed: %+v", got)
	}
}

// buildPauthNote assembles a GNU_PROPERTY_AARCH64_FEATURE_PAUTH record:
// type(4) | datasz(4)=16 | platform identifier(8) | version number(8),
// matching pauthabielf64 for ELFCLASS64.
func buildPauthNote(bo binary.ByteOrder, platform, version uint64) []byte {
	b := make([]byte, 24)
	bo.PutUint32(b[0:4], GnuPropertyArmFeaturePAuth)
	bo.PutUint32(b[4:8], 16)
	bo.PutUint64(b[8:16], platform)
	bo.PutUint64(b[16:24], version)
	return b
}

// A FEATURE_PAUTH record with a non-zero platform identifier (LLVM 19+
// -fptrauth-calls) enables the forward-PAC token; the reserved (0, 0)
// "incompatible" tuple must not.
func TestArmNotes_FwdPACProperty(t *testing.T) {
	bo := binary.LittleEndian
	cases := []struct {
		name     string
		platform uint64
		version  uint64
		wantFwd  bool
	}{
		{"baremetal platform 1", 1, 1, true},
		{"nonzero platform zero version", 0x1000, 0, true},
		{"reserved incompatible tuple", 0, 0, false},
		{"invalid platform zero", 0, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseArmPACBTIFromNotes(buildPauthNote(bo, c.platform, c.version), bo, 8)
			if got.fwd != c.wantFwd {
				t.Fatalf("platform=%#x version=%#x got fwd=%v, want %v", c.platform, c.version, got.fwd, c.wantFwd)
			}
		})
	}
}

// FEATURE_1 (backward PAC/BTI) and FEATURE_PAUTH (forward PAC) records can
// coexist in one property array, in either order.
func TestArmNotes_FeatureAndPAuthCombined(t *testing.T) {
	bo := binary.LittleEndian
	feat := buildPropertyNote(bo, GnuPropertyArmFeature1Flag, GnuPropertyArmFeaturePAC|GnuPropertyArmFeatureBTI)
	pauth := buildPauthNote(bo, 1, 1)

	for _, data := range [][]byte{append(feat, pauth...), append(pauth, feat...)} {
		got := parseArmPACBTIFromNotes(data, bo, 8)
		if !got.pac || !got.fwd || !got.bti {
			t.Fatalf("combined notes not fully parsed: %+v", got)
		}
	}

	out, st := armOutputString(parseArmPACBTIFromNotes(append(feat, pauth...), bo, 8))
	if out != "PAC & FwdPAC & BTI" || st != StatusGreat {
		t.Fatalf("combined notes output = %q/%q, want %q/%q", out, st, "PAC & FwdPAC & BTI", StatusGreat)
	}
}

// A FEATURE_PAUTH record whose declared datasz overruns the buffer must be
// dropped without panicking and without setting forward PAC.
func TestArmNotes_TruncatedPAuthIgnored(t *testing.T) {
	bo := binary.LittleEndian
	full := buildPauthNote(bo, 1, 1)
	truncated := full[:20] // header + only half the payload
	if got := parseArmPACBTIFromNotes(truncated, bo, 8); got.fwd {
		t.Fatalf("truncated FEATURE_PAUTH set fwd: %+v", got)
	}
}

// A well-formed single x86 feature note must yield the same result as parsing
// its bitmask directly.
func TestProp_X86Notes_SingleRecordOracle(t *testing.T) {
	for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		rapid.Check(t, func(t *rapid.T) {
			mask := rapid.Uint32().Draw(t, "mask")
			note := buildPropertyNote(bo, GnuPropertyX86Feature1Flag, mask)
			if got, want := parseX86CETFromNotes(note, bo, 8), parseBitmaskForx86CET(mask); got != want {
				t.Fatalf("mask=%#x got=%+v want=%+v", mask, got, want)
			}
		})
	}
}

// A well-formed single AArch64 feature note must yield the same result as
// parsing its bitmask directly.
func TestProp_ArmNotes_SingleRecordOracle(t *testing.T) {
	for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		rapid.Check(t, func(t *rapid.T) {
			mask := rapid.Uint32().Draw(t, "mask")
			note := buildPropertyNote(bo, GnuPropertyArmFeature1Flag, mask)
			if got, want := parseArmPACBTIFromNotes(note, bo, 8), parseBitmaskForArmPACBTI(mask); got != want {
				t.Fatalf("mask=%#x got=%+v want=%+v", mask, got, want)
			}
		})
	}
}

// When two feature records are concatenated, the later one wins (the parser
// overwrites on each match), and record alignment must be handled correctly.
func TestProp_X86Notes_LastRecordWins(t *testing.T) {
	bo := binary.LittleEndian
	rapid.Check(t, func(t *rapid.T) {
		m1 := rapid.Uint32().Draw(t, "mask1")
		m2 := rapid.Uint32().Draw(t, "mask2")
		data := append(buildPropertyNote(bo, GnuPropertyX86Feature1Flag, m1),
			buildPropertyNote(bo, GnuPropertyX86Feature1Flag, m2)...)
		if got, want := parseX86CETFromNotes(data, bo, 8), parseBitmaskForx86CET(m2); got != want {
			t.Fatalf("m1=%#x m2=%#x got=%+v want=%+v", m1, m2, got, want)
		}
	})
}

// The note parsers must never panic on arbitrary or truncated input.
func TestProp_NoteParsers_NeverPanic(t *testing.T) {
	for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		rapid.Check(t, func(t *rapid.T) {
			data := rapid.SliceOfN(rapid.Byte(), 0, 256).Draw(t, "data")
			_ = parseX86CETFromNotes(data, bo, 8)
			_ = parseArmPACBTIFromNotes(data, bo, 8)
		})
	}
}

// classifyClangCFIMode must always return one of the three legal classifications
// for any combination of symbol names, sections, bindings, and visibilities.
func TestProp_ClassifyClangCFIMode_LegalResult(t *testing.T) {
	names := []string{"__cfi_check", "__cfi_slowpath", "__cfi_slowpath_diag", "__cfi_fail", "__cfi_check_fail", "main", "printf"}
	sections := []elf.SectionIndex{elf.SHN_UNDEF, 1, 2}
	binds := []byte{byte(elf.STB_LOCAL), byte(elf.STB_GLOBAL), byte(elf.STB_WEAK)}
	vis := []byte{byte(elf.STV_DEFAULT), byte(elf.STV_HIDDEN), byte(elf.STV_PROTECTED)}

	genSym := func(t *rapid.T, label string) elf.Symbol {
		b := rapid.SampledFrom(binds).Draw(t, label+"_bind")
		return elf.Symbol{
			Name:    rapid.SampledFrom(names).Draw(t, label+"_name"),
			Section: rapid.SampledFrom(sections).Draw(t, label+"_sect"),
			Info:    b << 4,
			Other:   rapid.SampledFrom(vis).Draw(t, label+"_vis"),
		}
	}

	rapid.Check(t, func(t *rapid.T) {
		nAll := rapid.IntRange(0, 4).Draw(t, "nAll")
		nDyn := rapid.IntRange(0, 4).Draw(t, "nDyn")
		all := make([]elf.Symbol, nAll)
		for i := range all {
			all[i] = genSym(t, "all")
		}
		dyn := make([]elf.Symbol, nDyn)
		for i := range dyn {
			dyn[i] = genSym(t, "dyn")
		}
		mode := classifyClangCFIMode(all, dyn)
		if mode != "none" && mode != "single" && mode != "multi" {
			t.Fatalf("illegal classification %q", mode)
		}
	})
}

// An exported, defined __cfi_check in the dynamic symbol table is always
// multi-module, regardless of other symbols present.
func TestProp_ClassifyClangCFIMode_ExportedIsMulti(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bind := rapid.SampledFrom([]elf.SymBind{elf.STB_GLOBAL, elf.STB_WEAK}).Draw(t, "bind")
		dyn := []elf.Symbol{{
			Name:    "__cfi_check",
			Section: 1, // defined
			Info:    byte(bind) << 4,
			Other:   byte(elf.STV_DEFAULT),
		}}
		if mode := classifyClangCFIMode(nil, dyn); mode != "multi" {
			t.Fatalf("exported __cfi_check must be multi, got %q", mode)
		}
	})
}
