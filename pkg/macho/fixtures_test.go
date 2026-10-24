package macho

import (
	"bytes"
	dm "debug/macho"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

const fixtureDir = "../../tests/binaries/output/macho"

// allFixtures is the committed fixture set; TestFixturesPresent fails if any
// is missing so a stale checkout is caught early rather than as silent skips.
var allFixtures = []string{
	"exec_arm64", "exec_x86_64", "nopie_x86_64", "nocanary_arm64", "fat",
	"dylib.dylib", "obj.o", "rpath_arm64", "lazy_arm64", "dyldenv_arm64",
	"restrict_arm64", "adhoc_arm64", "hardened_arm64", "debuggable_arm64",
	"unsigned_arm64", "stripped_arm64", "arc_arm64", "noarc_arm64",
	"minos13_arm64", "asan_arm64",
}

func fixturePath(name string) string { return filepath.Join(fixtureDir, name) }

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(fixturePath(name))
	if err != nil {
		t.Skipf("fixture %q missing: %v (run tests/binaries/build_macho_fixtures.sh on macOS)", name, err)
	}
	return b
}

func fromBytes(t *testing.T, b []byte) *dm.File {
	t.Helper()
	f, err := dm.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("parse Mach-O: %v", err)
	}
	return f
}

func loadFixture(t *testing.T, name string) *dm.File {
	t.Helper()
	return fromBytes(t, fixtureBytes(t, name))
}

// withHeaderFlags returns the fixture with extra mach_header flags OR-ed in.
// flags sit at byte 24 in both the 32- and 64-bit headers.
func withHeaderFlags(t *testing.T, name string, set uint32) *dm.File {
	t.Helper()
	b := append([]byte(nil), fixtureBytes(t, name)...)
	bo := byteOrderOf(b)
	bo.PutUint32(b[24:28], bo.Uint32(b[24:28])|set)
	return fromBytes(t, b)
}

func byteOrderOf(b []byte) binary.ByteOrder {
	if binary.LittleEndian.Uint32(b[:4]) == dm.Magic64 || binary.LittleEndian.Uint32(b[:4]) == dm.Magic32 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// lc builds one little-endian load command: cmd, cmdsize, payload, padded to 8.
func lc(cmd uint32, payload []byte) []byte {
	size := 8 + len(payload)
	for size%8 != 0 {
		payload = append(payload, 0)
		size++
	}
	out := make([]byte, 8, size)
	binary.LittleEndian.PutUint32(out[0:], cmd)
	binary.LittleEndian.PutUint32(out[4:], uint32(size))
	return append(out, payload...)
}

// syntheticMachO assembles a minimal 64-bit little-endian arm64 image from
// load commands only (no segments). Enough for header- and load-command-level
// checks; symbol- and segment-level checks need real fixtures.
func syntheticMachO(t *testing.T, filetype uint32, flags uint32, loads ...[]byte) *dm.File {
	t.Helper()
	var cmds []byte
	for _, l := range loads {
		cmds = append(cmds, l...)
	}
	hdr := make([]byte, 32)
	binary.LittleEndian.PutUint32(hdr[0:], dm.Magic64)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(dm.CpuArm64))
	binary.LittleEndian.PutUint32(hdr[8:], 0)
	binary.LittleEndian.PutUint32(hdr[12:], filetype)
	binary.LittleEndian.PutUint32(hdr[16:], uint32(len(loads)))
	binary.LittleEndian.PutUint32(hdr[20:], uint32(len(cmds)))
	binary.LittleEndian.PutUint32(hdr[24:], flags)
	return fromBytes(t, append(hdr, cmds...))
}

func TestFixturesPresent(t *testing.T) {
	for _, name := range allFixtures {
		if _, err := os.Stat(fixturePath(name)); err != nil {
			t.Errorf("fixture %q missing: %v", name, err)
		}
	}
}

func TestFixturesParse(t *testing.T) {
	for _, name := range allFixtures {
		if name == "fat" {
			continue // fat is parsed per slice by pkg/target
		}
		t.Run(name, func(t *testing.T) { _ = loadFixture(t, name) })
	}
}

func TestSyntheticMachOParses(t *testing.T) {
	f := syntheticMachO(t, uint32(dm.TypeExec), dm.FlagPIE, lc(0x32, make([]byte, 16)))
	if f.Type != dm.TypeExec || f.Flags&dm.FlagPIE == 0 || len(f.Loads) != 1 {
		t.Fatalf("synthetic image mis-assembled: %+v", f.FileHeader)
	}
}
