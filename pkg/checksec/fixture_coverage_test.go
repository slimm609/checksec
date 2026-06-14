package checksec

import (
	"debug/elf"
	"os"
	"testing"
)

// These tests drive the I/O check functions against the committed ELF fixtures
// (tests/binaries/output/*), covering branches that previously required a C
// toolchain or a real /lib libc to reach.

func TestCanary_FixtureFound(t *testing.T) {
	// "dso.so" imports the real __stack_chk_fail@GLIBC in its .dynsym, so the
	// imported-symbol scan must report a canary.
	ef, raw := openELF(t, requireFixture(t, "dso.so"))

	res := Canary(ef, raw)
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
	ef, raw := openELF(t, requireFixture(t, "none"))

	res := Canary(ef, raw)
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
	ef, raw := openELF(t, requireFixture(t, "dso.so"))

	res := SafeStack(ef, raw)
	if res.Value != "No SafeStack Found" {
		t.Errorf("Value = %q, want %q", res.Value, "No SafeStack Found")
	}
	if res.Status != StatusBad {
		t.Errorf("Status = %q, want %q", res.Status, StatusBad)
	}
}

func TestCfi_FixtureArm64(t *testing.T) {
	ef, _ := openELF(t, requireFixture(t, "none"))

	res := Cfi(ef)
	if res.Value == "" {
		t.Error("Cfi() Value is empty")
	}
	validStatus := map[Status]bool{StatusGood: true, StatusWarn: true, StatusBad: true}
	if !validStatus[res.Status] {
		t.Errorf("unexpected Status = %q", res.Status)
	}
}

func TestCfi_FixtureX86(t *testing.T) {
	ef, _ := openELF(t, requireFixture(t, "zdump-x86"))

	res := Cfi(ef)
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
	got, err := DynValueFromPTDynamic(file, elf.DT_STRTAB)
	if err != nil {
		t.Fatalf("DynValueFromPTDynamic(DT_STRTAB) error = %v", err)
	}
	if len(got) == 0 {
		t.Error("expected DT_STRTAB to be present, got none")
	}

	// A tag that does not exist should return an empty slice without error.
	absent, err := DynValueFromPTDynamic(file, elf.DynTag(0x6fff9123))
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

func TestFortify_FixtureAutoLdd(t *testing.T) {
	// Passing ldd="" exercises the automatic getLdd resolution path. On a host
	// without a matching libc for the fixture's architecture this resolves to
	// "none"/"unk" and yields an N/A result — either way getLdd runs.
	target := requireFixture(t, "none")
	ef, _ := openELF(t, target)

	res, err := Fortify(target, ef, "")
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
	ef, _ := openELF(t, target)

	res, err := Fortify(target, ef, libc)
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
