package utils

import (
	"testing"

	"github.com/slimm609/checksec/v3/pkg/knowledge"
)

// TestEveryCheckHasKnowledge guards the invariant documented in
// pkg/knowledge/knowledge.go: the registry must cover every id in
// FileFields, plus "seccomp" (only added via ProcFields, since it is
// process-derived rather than ELF-derived). Adding a Field without a
// matching knowledge.Check entry must fail this test.
func TestEveryCheckHasKnowledge(t *testing.T) {
	ids := make([]string, 0, len(FileFields)+1)
	for _, f := range FileFields {
		ids = append(ids, f.Key)
	}
	ids = append(ids, "seccomp")

	for _, id := range ids {
		if _, ok := knowledge.Lookup(id); !ok {
			t.Errorf("knowledge registry missing entry for check id %q", id)
		}
	}
}
