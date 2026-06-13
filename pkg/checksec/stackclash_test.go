package checksec

import (
	"encoding/binary"
	"testing"
)

// buildAnnobinNote constructs one ELF note record as it appears in
// .gnu.build.attributes: namesz(4) | descsz(4) | type(4) | name (NUL-terminated,
// padded to 4) | desc (padded to 4).
func buildAnnobinNote(bo binary.ByteOrder, noteType uint32, name string, desc []byte) []byte {
	nameBytes := append([]byte(name), 0)
	pad4 := func(n int) int { return (n + 3) &^ 3 }
	out := make([]byte, 12)
	bo.PutUint32(out[0:4], uint32(len(nameBytes)))
	bo.PutUint32(out[4:8], uint32(len(desc)))
	bo.PutUint32(out[8:12], noteType)
	out = append(out, nameBytes...)
	out = append(out, make([]byte, pad4(len(nameBytes))-len(nameBytes))...)
	out = append(out, desc...)
	out = append(out, make([]byte, pad4(len(desc))-len(desc))...)
	return out
}

// TestClassifyAnnobinStackClash drives the pure note-payload classifier with
// synthetic .gnu.build.attributes contents. This is the regression guard for
// issue #300.
func TestClassifyAnnobinStackClash(t *testing.T) {
	le := binary.LittleEndian
	const ntOpen = 0x100
	const ntFunc = 0x101

	tests := []struct {
		name    string
		payload []byte
		want    stackClashState
	}{
		{"empty payload", nil, scUnknown},
		{"single enabled (OPEN)",
			buildAnnobinNote(le, ntOpen, "GA+stack_clash", nil),
			scEnabled},
		{"single disabled (OPEN)",
			buildAnnobinNote(le, ntOpen, "GA!stack_clash", nil),
			scDisabled},
		{"single enabled (FUNC, with desc range)",
			buildAnnobinNote(le, ntFunc, "GA+stack_clash", make([]byte, 16)),
			scEnabled},
		{"mixed: one TU enabled, one disabled → disabled wins",
			append(
				buildAnnobinNote(le, ntOpen, "GA+stack_clash", nil),
				buildAnnobinNote(le, ntFunc, "GA!stack_clash", make([]byte, 16))...),
			scDisabled},
		{"unrelated annobin notes only → unknown",
			append(
				buildAnnobinNote(le, ntOpen, "GA*\x02\x01", nil), // stack-protector, not stack-clash
				buildAnnobinNote(le, ntOpen, "GA$\x05gcc 13.2", nil)...),
			scUnknown},
		{"stack_clash after unrelated note",
			append(
				buildAnnobinNote(le, ntOpen, "GA$\x05gcc 13.2", nil),
				buildAnnobinNote(le, ntOpen, "GA+stack_clash", nil)...),
			scEnabled},
		{"non-annobin note type ignored",
			buildAnnobinNote(le, 0x1, "GA+stack_clash", nil),
			scUnknown},
		{"non-GA name prefix ignored",
			buildAnnobinNote(le, ntOpen, "XX+stack_clash", nil),
			scUnknown},
		{"truncated header is safe",
			[]byte{0x04, 0x00, 0x00},
			scUnknown},
		{"namesz overruns buffer is safe",
			[]byte{0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0, 0, 1, 0, 0, 'G', 'A'},
			scUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyAnnobinStackClash(tt.payload, le)
			if got != tt.want {
				t.Errorf("classifyAnnobinStackClash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClassifyAnnobinStackClash_BigEndian(t *testing.T) {
	be := binary.BigEndian
	payload := buildAnnobinNote(be, 0x100, "GA+stack_clash", nil)
	if got := classifyAnnobinStackClash(payload, be); got != scEnabled {
		t.Errorf("big-endian: got %v, want scEnabled", got)
	}
}

func TestStackClashStateResult(t *testing.T) {
	tests := []struct {
		state      stackClashState
		wantValue  string
		wantStatus Status
	}{
		{scEnabled, "Enabled", StatusGood},
		{scDisabled, "Disabled", StatusBad},
		{scUnknown, "Unknown", StatusWarn},
	}
	for _, tt := range tests {
		r := tt.state.result()
		if r.Value != tt.wantValue || r.Status != tt.wantStatus {
			t.Errorf("%v.result() = %+v, want {%q %q}", tt.state, r, tt.wantValue, tt.wantStatus)
		}
	}
}

func TestStackClash_ELFWithoutAnnobin(t *testing.T) {
	// A pure-Go ELF has no .gnu.build.attributes and no stack-clash probes —
	// the heuristic fallback runs and reports "No Probes".
	ef, _ := openELF(t, buildLinuxELF(t))
	res := StackClash(ef)
	if res.Value != "No Probes" || res.Status != StatusWarn {
		t.Errorf("StackClash() = %+v, want {No Probes, StatusWarn}", res)
	}
}
