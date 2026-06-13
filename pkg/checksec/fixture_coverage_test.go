package checksec

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"
)

// These tests drive the I/O check functions against the committed ELF fixtures
// (tests/binaries/output/*), covering branches that previously required a C
// toolchain or a real /lib libc to reach.

func TestCanary_FixtureFound(t *testing.T) {
	// "dso.so" imports the real __stack_chk_fail@GLIBC in its .dynsym, so the
	// imported-symbol scan must report a canary.
	bin := requireFixture(t, "dso.so")

	res, err := Canary(bin)
	if err != nil {
		t.Fatalf("Canary() error = %v", err)
	}
	if res.Value != "Canary Found" {
		t.Errorf("Value = %q, want %q", res.Value, "Canary Found")
	}
	if res.Status != StatusGood {
		t.Errorf("Status = %q, want %q", res.Status, StatusGood)
	}
}

func TestCanary_FixtureNoCanary(t *testing.T) {
	// "none" is the negative fixture: its only stack_chk symbol is deliberately
	// renamed "false__stack_chk_fail", so none of the three symbol sources match.
	bin := requireFixture(t, "none")

	res, err := Canary(bin)
	if err != nil {
		t.Fatalf("Canary() error = %v", err)
	}
	if res.Value != "No Canary Found" {
		t.Errorf("Value = %q, want %q", res.Value, "No Canary Found")
	}
	if res.Status != StatusBad {
		t.Errorf("Status = %q, want %q", res.Status, StatusBad)
	}
}

func TestSafeStack_FixtureStripped(t *testing.T) {
	// Drives the stripped-binary path; no fixture defines __safestack_init, so
	// the expected result is "No SafeStack Found".
	bin := requireFixture(t, "dso.so")

	res, err := SafeStack(bin)
	if err != nil {
		t.Fatalf("SafeStack() error = %v", err)
	}
	if res.Value != "No SafeStack Found" {
		t.Errorf("Value = %q, want %q", res.Value, "No SafeStack Found")
	}
	if res.Status != StatusBad {
		t.Errorf("Status = %q, want %q", res.Status, StatusBad)
	}
}

func TestCfi_FixtureArm64(t *testing.T) {
	bin := requireFixture(t, "none")

	res, err := Cfi(bin)
	if err != nil {
		t.Fatalf("Cfi() error = %v", err)
	}
	if res.Value == "" {
		t.Error("Cfi() Value is empty")
	}
	validStatus := map[Status]bool{StatusGood: true, StatusWarn: true, StatusBad: true}
	if !validStatus[res.Status] {
		t.Errorf("unexpected Status = %q", res.Status)
	}
}

func TestCfi_FixtureX86(t *testing.T) {
	bin := requireFixture(t, "zdump-x86")

	res, err := Cfi(bin)
	if err != nil {
		t.Fatalf("Cfi() error = %v", err)
	}
	if res.Value == "" {
		t.Error("Cfi() Value is empty")
	}
	validStatus := map[Status]bool{StatusGood: true, StatusWarn: true, StatusBad: true}
	if !validStatus[res.Status] {
		t.Errorf("unexpected Status = %q", res.Status)
	}
}

func TestDynValueFromPTDynamic_Fixture(t *testing.T) {
	file := loadFixture(t, "none")

	// A dynamic executable must carry DT_STRTAB in its PT_DYNAMIC segment.
	got, err := DynValueFromPTDynamic(file, elf.DT_STRTAB, "none")
	if err != nil {
		t.Fatalf("DynValueFromPTDynamic(DT_STRTAB) error = %v", err)
	}
	if len(got) == 0 {
		t.Error("expected DT_STRTAB to be present, got none")
	}

	// A tag that does not exist should return an empty slice without error.
	absent, err := DynValueFromPTDynamic(file, elf.DynTag(0x6fff9123), "none")
	if err != nil {
		t.Fatalf("DynValueFromPTDynamic(absent) error = %v", err)
	}
	if len(absent) != 0 {
		t.Errorf("expected absent tag to yield no values, got %v", absent)
	}
}

func TestFunctionsFromSymbolTable_Fixture(t *testing.T) {
	// dso.so is a stripped shared object; its functions come from .dynsym via
	// the manual symbol-table walk.
	path := requireFixture(t, "dso.so")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	funcs, err := FunctionsFromSymbolTable(f)
	if err != nil {
		t.Fatalf("FunctionsFromSymbolTable() error = %v", err)
	}
	if len(funcs) == 0 {
		t.Error("expected at least one function symbol from dso.so")
	}
}

func TestFortify_TargetNotElfReturnsError(t *testing.T) {
	// With a valid libc but a non-ELF target, Fortify must return an error
	// rather than calling os.Exit (the bug fixed for the (*fortify, error) API).
	libc := requireFixture(t, "dso.so")
	dir := t.TempDir()
	bad := filepath.Join(dir, "not-elf")
	if err := os.WriteFile(bad, []byte("plain text, not an ELF"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := Fortify(bad, nil, libc)
	if err == nil {
		t.Fatalf("expected error for non-ELF target, got result %+v", res)
	}
}

func TestFortify_FixtureAutoLdd(t *testing.T) {
	// Passing ldd="" exercises the automatic getLdd resolution path. On a host
	// without a matching libc for the fixture's architecture this resolves to
	// "none"/"unk" and yields an N/A result — either way getLdd runs.
	target := requireFixture(t, "none")

	res, err := Fortify(target, nil, "")
	if err != nil {
		t.Fatalf("Fortify() error = %v", err)
	}
	if res == nil {
		t.Fatal("Fortify() returned nil")
	}
	validOutputs := map[string]bool{"Yes": true, "No": true, "N/A": true}
	if !validOutputs[res.Output] {
		t.Errorf("unexpected Output = %q", res.Output)
	}
}

func TestFortify_FixtureLibcSupported(t *testing.T) {
	// Use a fixture that exports __*_chk functions as a stand-in libc so the
	// LibcSupport=Yes branch and the fortified-count comparison are exercised
	// without depending on the host's real /lib libc.
	libc := requireFixture(t, "dso.so")
	target := requireFixture(t, "all")

	res, err := Fortify(target, nil, libc)
	if err != nil {
		t.Fatalf("Fortify() error = %v", err)
	}
	if res == nil {
		t.Fatal("Fortify() returned nil")
	}
	if res.LibcSupport != "Yes" {
		t.Errorf("LibcSupport = %q, want %q", res.LibcSupport, "Yes")
	}
	validOutputs := map[string]bool{"Yes": true, "No": true}
	if !validOutputs[res.Output] {
		t.Errorf("unexpected Output = %q", res.Output)
	}
}
