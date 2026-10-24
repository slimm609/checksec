// pkg/macho/cfi_test.go
package macho

import (
	dm "debug/macho"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func TestCFI(t *testing.T) {
	if r := CFI(loadFixture(t, "exec_arm64")); r.Value != "NO PAC" || r.Status != checksec.StatusWarn {
		t.Errorf("arm64: %+v", r)
	}
	if r := CFI(loadFixture(t, "exec_x86_64")); r.Value != "N/A" || r.Status != checksec.StatusNA {
		t.Errorf("x86_64: %+v", r)
	}
	if v, s := classifyPAC(dm.CpuArm64, 0x80000002); v != "PAC" || s != checksec.StatusGood {
		t.Errorf("arm64e: %q/%q", v, s)
	}
}
