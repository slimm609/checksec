package checksec

import (
	"encoding/binary"
	"math"
	"testing"
)

// Note sizes near the uint32 limit overflow int on 32-bit platforms.
func TestWalkAnnobinNotesOversizedNotes(t *testing.T) {
	sizes := []struct {
		name           string
		namesz, descsz uint32
	}{
		{"max name size", math.MaxUint32, 0},
		{"name size above int32", math.MaxInt32 + 1, 0},
		{"max description size", 0, math.MaxUint32},
		{"sum above int32", math.MaxInt32 - 7, 16},
	}

	for _, tt := range sizes {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, 32)
			binary.LittleEndian.PutUint32(data[0:4], tt.namesz)
			binary.LittleEndian.PutUint32(data[4:8], tt.descsz)
			binary.LittleEndian.PutUint32(data[8:12], ntGnuBuildAttributeOpen)

			walkAnnobinNotes(data, binary.LittleEndian, func(byte, string, []byte) {
				t.Fatal("callback called for a truncated note")
			})
		})
	}
}
