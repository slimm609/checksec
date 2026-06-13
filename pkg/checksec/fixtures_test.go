package checksec

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"
)

// fixtureDir is the path (relative to this package) to the committed ELF test
// binaries. These are real binaries checked into the repo so tests can exercise
// the hard branches without requiring a C toolchain at test time.
const fixtureDir = "../../tests/binaries/output"

// fixturePath returns the on-disk path to a committed fixture binary.
func fixturePath(name string) string {
	return filepath.Join(fixtureDir, name)
}

// loadFixture opens a committed fixture as an *elf.File, skipping the test if the
// fixture is missing and closing the file automatically when the test ends.
func loadFixture(t *testing.T, name string) *elf.File {
	t.Helper()
	p := fixturePath(name)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture %q not found: %v", name, err)
	}
	f, err := elf.Open(p)
	if err != nil {
		t.Fatalf("open fixture %q: %v", name, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// requireFixture returns the path to a fixture, skipping the test if it is absent.
func requireFixture(t *testing.T, name string) string {
	t.Helper()
	p := fixturePath(name)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture %q not found: %v", name, err)
	}
	return p
}

// openELF opens path as both a raw *os.File and a parsed *elf.File, registering
// cleanup. Use for checks that need either or both handles.
func openELF(t *testing.T, path string) (*elf.File, *os.File) {
	t.Helper()
	raw, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %q: %v", path, err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	ef, err := elf.NewFile(raw)
	if err != nil {
		t.Fatalf("parse ELF %q: %v", path, err)
	}
	return ef, raw
}
