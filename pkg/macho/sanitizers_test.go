// pkg/macho/sanitizers_test.go
package macho

import (
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func TestSanitizers(t *testing.T) {
	if r := Sanitizers(loadFixture(t, "exec_arm64")); r.Value != "None" || r.Status != checksec.StatusInfo {
		t.Errorf("default: %+v", r)
	}
	if r := Sanitizers(loadFixture(t, "asan_arm64")); r.Value != "ASAN" || r.Status != checksec.StatusGood {
		t.Errorf("asan: %+v", r)
	}
}
