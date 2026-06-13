package checksec

import (
	"testing"
)

func TestRPATH_NoRpath(t *testing.T) {
	ef, _ := openELF(t, buildLinuxELF(t))
	result := RPATH(ef)
	if result.Value != "No RPATH" {
		t.Errorf("Value = %q, want %q", result.Value, "No RPATH")
	}
	if result.Status != StatusGood {
		t.Errorf("Status = %q, want %q", result.Status, StatusGood)
	}
}

func TestRPATH_WithRpath(t *testing.T) {
	// The committed "rpath" fixture is a real ELF carrying DT_RPATH ([./]).
	ef, _ := openELF(t, requireFixture(t, "rpath"))
	result := RPATH(ef)
	if result.Value != "RPATH" {
		t.Errorf("Value = %q, want %q", result.Value, "RPATH")
	}
	if result.Status != StatusBad {
		t.Errorf("Status = %q, want %q", result.Status, StatusBad)
	}
}
