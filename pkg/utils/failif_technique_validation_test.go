package utils

import (
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func emptyReport() FileReport {
	return FileReport{Name: "x", Checks: map[string]checksec.Result{}}
}

// A technique predicate with an unknown or empty rule id must be rejected at
// validation time, not silently accepted as a no-op CI gate.
func TestFailIfRejectsUnknownTechniqueID(t *testing.T) {
	for _, bad := range []string{"exploit.technique=bogus", "exploit.technique="} {
		if _, err := EvaluateFailIf([]FileReport{emptyReport()}, []string{bad}); err == nil {
			t.Errorf("%q must be rejected as an unknown --fail-if key", bad)
		}
	}
}

func TestFailIfAcceptsKnownTechniqueID(t *testing.T) {
	if _, err := EvaluateFailIf([]FileReport{emptyReport()}, []string{"exploit.technique=got-overwrite"}); err != nil {
		t.Errorf("known technique id must be accepted, got error: %v", err)
	}
	if _, err := EvaluateFailIf([]FileReport{emptyReport()}, []string{"exploit.viable"}); err != nil {
		t.Errorf("exploit.viable must be accepted, got error: %v", err)
	}
}
