package checksec

import (
	"strings"
	"testing"
)

func TestRUNPATH_NoRunpath(t *testing.T) {
	ef, _ := openELF(t, buildLinuxELF(t))
	result := RUNPATH(ef)
	if result.Value != "No RUNPATH" {
		t.Errorf("Value = %q, want %q", result.Value, "No RUNPATH")
	}
	if result.Status != StatusGood {
		t.Errorf("Status = %q, want %q", result.Status, StatusGood)
	}
}

func TestRUNPATH_WithRunpath(t *testing.T) {
	// The committed "runpath" fixture is a real ELF carrying DT_RUNPATH (./).
	ef, _ := openELF(t, requireFixture(t, "runpath"))
	result := RUNPATH(ef)
	if !strings.HasPrefix(result.Value, "RUNPATH [") {
		t.Errorf("Value = %q, want prefix %q", result.Value, "RUNPATH [")
	}
	if result.Status != StatusBad {
		t.Errorf("Status = %q, want %q", result.Status, StatusBad)
	}
}
