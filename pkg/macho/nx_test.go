package macho

import (
	dm "debug/macho"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func TestNX(t *testing.T) {
	if r := NX(loadFixture(t, "exec_arm64")); r.Value != "NX enabled" || r.Status != checksec.StatusGood {
		t.Errorf("default: %+v", r)
	}
	// Apple's linker rejects -allow_stack_execute, so flip the header bit.
	f := withHeaderFlags(t, "exec_arm64", dm.FlagAllowStackExecution)
	if r := NX(f); r.Value != "NX disabled" || r.Status != checksec.StatusBad {
		t.Errorf("flag set: %+v", r)
	}
}
