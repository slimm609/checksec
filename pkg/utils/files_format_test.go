package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsSupportedBinary(t *testing.T) {
	if _, err := os.Stat(fixtureELF); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	if !IsSupportedBinary(fixtureELF) {
		t.Error("ELF fixture must be supported")
	}
	if p := requireMachoFixture(t, "exec_arm64"); !IsSupportedBinary(p) {
		t.Error("Mach-O fixture must be supported")
	}
	if p := requireMachoFixture(t, "fat"); !IsSupportedBinary(p) {
		t.Error("fat Mach-O must be supported")
	}
	txt := filepath.Join(t.TempDir(), "x.txt")
	_ = os.WriteFile(txt, []byte("nope"), 0o644)
	if IsSupportedBinary(txt) {
		t.Error("text must not be supported")
	}
	if IsSupportedBinary(filepath.Join(t.TempDir(), "missing")) {
		t.Error("missing file must not be supported")
	}
}

func TestGetAllFilesFromDir_PicksUpMachO(t *testing.T) {
	src := requireMachoFixture(t, "exec_arm64")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "app"), data, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "readme"), []byte("text"), 0o644)
	got := GetAllFilesFromDir(dir, false)
	if len(got) != 1 || filepath.Base(got[0]) != "app" {
		t.Fatalf("expected only the Mach-O, got %v", got)
	}
}
