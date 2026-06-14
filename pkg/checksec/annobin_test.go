package checksec

import (
	"encoding/binary"
	"testing"
)

// buildAnnobinNumericNote constructs a GA*<attr>\0<value-bytes>\0 note name as
// annobin emits it (annobin.cc:1463-1466).
func buildAnnobinNumericNote(attr string, value byte) []byte {
	name := append([]byte("GA*"), []byte(attr)...)
	name = append(name, 0, value, 0)
	// namesz is len(name); buildAnnobinNote will add the trailing pad.
	return name
}

// TestParseAnnobinName drives the unified annobin note-name parser. It must
// extract (kind, attr, value-bytes) from names of all four kinds.
func TestParseAnnobinName(t *testing.T) {
	tests := []struct {
		name     string
		raw      []byte
		wantKind byte
		wantAttr string
		wantVal  []byte
	}{
		{"bool true stack_clash", []byte("GA+stack_clash\x00"), '+', "stack_clash", nil},
		{"bool false stack_clash", []byte("GA!stack_clash\x00"), '!', "stack_clash", nil},
		{"numeric FORTIFY=2", buildAnnobinNumericNote("FORTIFY", 2), '*', "FORTIFY", []byte{2}},
		{"numeric FORTIFY=3", buildAnnobinNumericNote("FORTIFY", 3), '*', "FORTIFY", []byte{3}},
		{"numeric FORTIFY=0xfe (level 254 → 'unset' sentinel)", buildAnnobinNumericNote("FORTIFY", 0xfe), '*', "FORTIFY", []byte{0xfe}},
		{"bool GLIBCXX_ASSERTIONS true", []byte("GA+GLIBCXX_ASSERTIONS\x00"), '+', "GLIBCXX_ASSERTIONS", nil},
		{"string tool", []byte("GA$\x05gcc 13.2\x00"), '$', "\x05", []byte("gcc 13.2")},
		{"non-GA prefix", []byte("XX+foo\x00"), 0, "", nil},
		{"too short", []byte("GA"), 0, "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, attr, val := parseAnnobinName(tt.raw)
			if kind != tt.wantKind || attr != tt.wantAttr || string(val) != string(tt.wantVal) {
				t.Errorf("parseAnnobinName(%q) = (%c, %q, %v), want (%c, %q, %v)",
					tt.raw, kind, attr, val, tt.wantKind, tt.wantAttr, tt.wantVal)
			}
		})
	}
}

// TestClassifyFortifyLevel maps annobin payloads to the FORTIFY level Result.
func TestClassifyFortifyLevel(t *testing.T) {
	le := binary.LittleEndian
	mkNote := func(name []byte) []byte {
		return buildAnnobinNote(le, ntGnuBuildAttributeOpen, string(name[:len(name)-1]), nil)
	}
	tests := []struct {
		name       string
		payload    []byte
		wantValue  string
		wantStatus Status
	}{
		{"no annobin section", nil, "Unknown", StatusWarn},
		{"level 0", mkNote(buildAnnobinNumericNote("FORTIFY", 0)), "Level 0", StatusBad},
		{"level 1", mkNote(buildAnnobinNumericNote("FORTIFY", 1)), "Level 1", StatusWarn},
		{"level 2", mkNote(buildAnnobinNumericNote("FORTIFY", 2)), "Level 2", StatusGood},
		{"level 3", mkNote(buildAnnobinNumericNote("FORTIFY", 3)), "Level 3", StatusGood},
		{"sentinel 0xfe (unset)", mkNote(buildAnnobinNumericNote("FORTIFY", 0xfe)), "Unknown", StatusWarn},
		{"mixed levels → lowest wins",
			append(mkNote(buildAnnobinNumericNote("FORTIFY", 3)), mkNote(buildAnnobinNumericNote("FORTIFY", 1))...),
			"Level 1", StatusWarn},
		{"unrelated note only", mkNote([]byte("GA+stack_clash\x00")), "Unknown", StatusWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := classifyFortifyLevel(tt.payload, le)
			if r.Value != tt.wantValue || r.Status != tt.wantStatus {
				t.Errorf("classifyFortifyLevel() = %+v, want {%q, %q}", r, tt.wantValue, tt.wantStatus)
			}
		})
	}
}

// TestClassifyGlibcxxAssertions maps annobin payloads to the assertion Result.
func TestClassifyGlibcxxAssertions(t *testing.T) {
	le := binary.LittleEndian
	mk := func(kind byte) []byte {
		return buildAnnobinNote(le, ntGnuBuildAttributeOpen, "GA"+string(kind)+"GLIBCXX_ASSERTIONS", nil)
	}
	tests := []struct {
		name       string
		payload    []byte
		wantValue  string
		wantStatus Status
	}{
		{"enabled", mk('+'), "Enabled", StatusGood},
		{"disabled", mk('!'), "Disabled", StatusBad},
		{"absent", nil, "Unknown", StatusWarn},
		{"mixed → disabled wins", append(mk('+'), mk('!')...), "Disabled", StatusBad},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := classifyGlibcxxAssertions(tt.payload, le)
			if r.Value != tt.wantValue || r.Status != tt.wantStatus {
				t.Errorf("classifyGlibcxxAssertions() = %+v, want {%q, %q}", r, tt.wantValue, tt.wantStatus)
			}
		})
	}
}

func TestFortifyLevel_ELFWithoutAnnobin(t *testing.T) {
	ef, _ := openELF(t, buildLinuxELF(t))
	if r := FortifyLevel(ef); r.Value != "Unknown" {
		t.Errorf("FortifyLevel = %+v, want Unknown", r)
	}
	if r := GlibcxxAssertions(ef); r.Value != "Unknown" {
		t.Errorf("GlibcxxAssertions = %+v, want Unknown", r)
	}
}
