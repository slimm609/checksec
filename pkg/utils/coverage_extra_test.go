package utils

import (
	"encoding/json"
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

// TestRunFileChecks_RealFixture exercises the real check wrappers (relroFn,
// canaryFn, ... fortifyFn) end-to-end against a committed fixture, rather than
// the stubbed hooks used by TestRunFileChecks_UsesHooksAndAggregates.
func TestRunFileChecks_RealFixture(t *testing.T) {
	requireFixtureBytes(t)

	data, color := RunFileChecks(fixtureELF, "")
	if len(data) == 0 || len(color) == 0 {
		t.Fatal("RunFileChecks returned empty results")
	}

	// The aggregated data must be valid JSON-serialisable and contain checks.
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal data: %v", err)
	}
	var decoded []map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected 1 result entry, got %d", len(decoded))
	}
	checks, ok := decoded[0]["checks"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing checks map in %#v", decoded[0])
	}
	for _, key := range []string{"relro", "canary", "nx", "pie", "rpath", "runpath", "symbols"} {
		if _, present := checks[key]; !present {
			t.Errorf("checks map missing %q", key)
		}
	}
}
