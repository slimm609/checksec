package macho

import (
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func TestCanary(t *testing.T) {
	if r := Canary(loadFixture(t, "exec_arm64")); r.Value != "Canary Found" || r.Status != checksec.StatusGood {
		t.Errorf("default: %+v", r)
	}
	if r := Canary(loadFixture(t, "nocanary_arm64")); r.Value != "No Canary Found" || r.Status != checksec.StatusBad {
		t.Errorf("nocanary: %+v", r)
	}
	// Stripped keeps undefined imports, so the canary import still shows.
	if r := Canary(loadFixture(t, "stripped_arm64")); r.Value != "Canary Found" {
		t.Errorf("stripped: %+v", r)
	}
}

func TestImportedNames_ExcludesDefined(t *testing.T) {
	names := importedNames(loadFixture(t, "exec_arm64"))
	for _, n := range names {
		if n == "_main" || n == "_false__stack_chk_fail" {
			t.Errorf("defined symbol %q reported as import", n)
		}
	}
	found := false
	for _, n := range names {
		if n == "___stack_chk_fail" {
			found = true
		}
	}
	if !found {
		t.Errorf("___stack_chk_fail missing from imports: %v", names)
	}
}
