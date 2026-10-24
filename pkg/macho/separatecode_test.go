// pkg/macho/separatecode_test.go
package macho

import (
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func TestSeparateCode(t *testing.T) {
	if r := SeparateCode(loadFixture(t, "exec_arm64")); r.Value != "Enabled" || r.Status != checksec.StatusGood {
		t.Errorf("default: %+v", r)
	}
	if r := SeparateCode(loadFixture(t, "obj.o")); r.Value != "N/A" || r.Status != checksec.StatusNA {
		t.Errorf("object: %+v", r)
	}
	f := syntheticMachO(t, 2, 0)
	if r := SeparateCode(f); r.Value != "N/A" {
		t.Errorf("no segments: %+v", r)
	}
}

func TestClassifySegments_WX(t *testing.T) {
	if v, s := classifySegments([]uint32{7}); v != "WX Segment" || s != checksec.StatusBad {
		t.Errorf("rwx: %q/%q", v, s)
	}
	if v, s := classifySegments([]uint32{5, 3}); v != "Enabled" || s != checksec.StatusGood {
		t.Errorf("rx+rw: %q/%q", v, s)
	}
}
