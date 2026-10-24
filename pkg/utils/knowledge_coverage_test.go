package utils

import (
	"testing"

	"github.com/slimm609/checksec/v3/pkg/knowledge"
)

// TestEveryCheckHasKnowledge guards the invariant documented in
// pkg/knowledge/knowledge.go: the registry must cover every id in every
// format registry, plus "seccomp" (process-derived, only in ProcFields).
func TestEveryCheckHasKnowledge(t *testing.T) {
	all := AllFields()
	ids := make([]string, 0, len(all)+1)
	for _, f := range all {
		ids = append(ids, f.Key)
	}
	ids = append(ids, "seccomp")

	for _, id := range ids {
		if _, ok := knowledge.Lookup(id); !ok {
			t.Errorf("knowledge registry missing entry for check id %q", id)
		}
	}
}
