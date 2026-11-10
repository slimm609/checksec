package checksec

import "testing"

// The probe fires only when BOTH the save (prologue) and restore (epilogue)
// instruction encodings appear in the scanned bytes; a single pattern or
// unrelated code must not report a shadow call stack.
func TestScsPairPresent(t *testing.T) {
	pair := append(append([]byte{0xd5, 0x03, 0x00, 0xaa}, scsProloguePattern...), scsEpiloguePattern...) // nop + pair
	cases := []struct {
		name     string
		sections [][]byte
		want     bool
	}{
		{"both patterns in one section", [][]byte{pair}, true},
		{"patterns split across sections", [][]byte{scsProloguePattern, scsEpiloguePattern}, true},
		{"reversed order in one section", [][]byte{append(append([]byte{}, scsEpiloguePattern...), scsProloguePattern...)}, true},
		{"only prologue", [][]byte{scsProloguePattern}, false},
		{"only epilogue", [][]byte{scsEpiloguePattern}, false},
		{"unrelated code", [][]byte{{0xd5, 0x03, 0x00, 0xaa, 0xff, 0xff, 0xff, 0xff}}, false},
		{"no sections", nil, false},
		{"empty section", [][]byte{{}}, false},
		{"pair beyond scan cap", [][]byte{append(make([]byte, 32), pair...)}, false},
		{"pair crossing section boundary only", [][]byte{
			// Two-byte halves of each pattern: no full pattern present. Build
			// with a composite literal — append into a shared pattern's backing
			// array would corrupt the globals.
			{scsProloguePattern[0], scsProloguePattern[1], scsEpiloguePattern[0], scsEpiloguePattern[1]},
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := scsPairPresent(c.sections, 16); got != c.want {
				t.Errorf("scsPairPresent(%d sections) = %v, want %v", len(c.sections), got, c.want)
			}
		})
	}
}

// A cap large enough to include the pair must report it even with a leading
// filler, while a zero cap never does.
func TestScsPairPresent_CapBoundary(t *testing.T) {
	filler := make([]byte, 100)
	section := append(filler, scsProloguePattern...)
	section = append(section, scsEpiloguePattern...)
	if !scsPairPresent([][]byte{section}, len(section)) {
		t.Error("pair within cap was not detected")
	}
	if scsPairPresent([][]byte{section}, 0) {
		t.Error("zero cap must not detect")
	}
}
