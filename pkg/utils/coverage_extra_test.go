package utils

import (
	"os"
	"path/filepath"
	"testing"
)

const fixtureELF = "../../tests/binaries/output/none"

func requireFixtureBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(fixtureELF)
	if err != nil {
		t.Skipf("fixture %q missing: %v", fixtureELF, err)
	}
	return data
}

func TestCheckIfElf_RealAndNonElf(t *testing.T) {
	requireFixtureBytes(t) // skip if no fixtures present
	if !CheckIfElf(fixtureELF) {
		t.Errorf("CheckIfElf(%q) = false, want true", fixtureELF)
	}

	dir := t.TempDir()
	nonElf := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(nonElf, []byte("not an elf"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if CheckIfElf(nonElf) {
		t.Errorf("CheckIfElf(non-elf) = true, want false")
	}
}

func TestCheckFileExists_Positive(t *testing.T) {
	requireFixtureBytes(t)
	if !CheckFileExists(fixtureELF) {
		t.Errorf("CheckFileExists(%q) = false, want true", fixtureELF)
	}
}

func TestCheckDirExists_Positive(t *testing.T) {
	if _, err := os.Stat("../../tests/binaries/output"); err != nil {
		t.Skipf("fixture dir missing: %v", err)
	}
	if !CheckDirExists("../../tests/binaries/output") {
		t.Errorf("CheckDirExists(fixture dir) = false, want true")
	}
}

func TestGetBinary_Positive(t *testing.T) {
	requireFixtureBytes(t)
	b := GetBinary(fixtureELF)
	if b == nil {
		t.Fatal("GetBinary returned nil")
	}
	defer b.Close()
	if len(b.Sections) == 0 && len(b.Progs) == 0 {
		t.Error("expected a parsed ELF with sections or program headers")
	}
}

func TestGetAllFilesFromDir_Recursive(t *testing.T) {
	data := requireFixtureBytes(t)
	dir := t.TempDir()
	sub := filepath.Join(dir, "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bin := filepath.Join(sub, "app")
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := GetAllFilesFromDir(dir, true)
	found := false
	for _, p := range got {
		if filepath.Base(p) == "app" {
			found = true
		}
	}
	if !found {
		t.Fatalf("recursive walk did not find nested ELF, got %#v", got)
	}
}

// TestRunFileChecks_RealFixture exercises the real check pipeline end-to-end
// against a committed fixture.
func TestRunFileChecks_RealFixture(t *testing.T) {
	requireFixtureBytes(t)

	report := RunFileChecks(fixtureELF, "")
	if report.Name != fixtureELF {
		t.Errorf("Name = %q, want %q", report.Name, fixtureELF)
	}
	for _, key := range []string{"relro", "canary", "nx", "pie", "rpath", "runpath", "symbols"} {
		if _, ok := report.Checks[key]; !ok {
			t.Errorf("checks missing %q", key)
		}
	}
}
