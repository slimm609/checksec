package checksec

import (
	"debug/elf"
	"encoding/binary"
	"testing"

	"pgregory.net/rapid"
)

// scanDynamicEntries must never panic and never read out of bounds, regardless
// of how truncated or malformed the dynamic-section payload is.
func TestProp_ScanDynamicEntries_NeverPanic(t *testing.T) {
	classes := []elf.Class{elf.ELFCLASS32, elf.ELFCLASS64}
	orders := []binary.ByteOrder{binary.LittleEndian, binary.BigEndian}
	rapid.Check(t, func(t *rapid.T) {
		data := rapid.SliceOfN(rapid.Byte(), 0, 256).Draw(t, "data")
		class := rapid.SampledFrom(classes).Draw(t, "class")
		bo := rapid.SampledFrom(orders).Draw(t, "bo")
		tag := elf.DynTag(rapid.Int64().Draw(t, "tag"))
		_, _ = scanDynamicEntries(data, class, bo, tag)
	})
}

// build64DynEntry encodes one 64-bit ELF dynamic entry: d_tag(8) | d_val(8).
func build64DynEntry(bo binary.ByteOrder, tag elf.DynTag, val uint64) []byte {
	b := make([]byte, 16)
	bo.PutUint64(b[0:8], uint64(tag))
	bo.PutUint64(b[8:16], val)
	return b
}

// A 64-bit entry whose tag matches must be found and its d_val returned exactly.
func TestProp_ScanDynamicEntries_Finds64(t *testing.T) {
	bo := binary.LittleEndian
	rapid.Check(t, func(t *rapid.T) {
		tag := elf.DynTag(rapid.Int64Range(0, 0x7fffffff).Draw(t, "tag"))
		val := rapid.Uint64().Draw(t, "val")
		// Prefix with a non-matching entry to exercise iteration.
		other := build64DynEntry(bo, elf.DynTag(int64(tag)+1), val^0xdead)
		data := append(other, build64DynEntry(bo, tag, val)...)

		got, ok := scanDynamicEntries(data, elf.ELFCLASS64, bo, tag)
		if !ok {
			t.Fatalf("tag %d not found", tag)
		}
		if got != val {
			t.Fatalf("tag %d: got d_val %d, want %d", tag, got, val)
		}
	})
}

// A truncated final entry (fewer than 16 bytes) must be ignored, not read.
func TestProp_ScanDynamicEntries_TruncatedTailIgnored(t *testing.T) {
	bo := binary.LittleEndian
	rapid.Check(t, func(t *rapid.T) {
		tag := elf.DynTag(rapid.Int64Range(1, 0x7fffffff).Draw(t, "tag"))
		// A single entry for a *different* tag, then a truncated fragment.
		data := build64DynEntry(bo, elf.DynTag(int64(tag)+7), 1)
		frag := rapid.SliceOfN(rapid.Byte(), 1, 15).Draw(t, "frag")
		data = append(data, frag...)
		if _, ok := scanDynamicEntries(data, elf.ELFCLASS64, bo, tag); ok {
			t.Fatalf("absent tag %d should not be found in truncated data", tag)
		}
	})
}
