package checksec

import (
	"testing"
)

func TestSysctlCheck_ReturnsWellFormedOutput(t *testing.T) {
	results := SysctlCheck()
	if len(results) == 0 {
		t.Fatal("SysctlCheck() returned no results")
	}
	if len(results) != len(sysctlChecks) {
		t.Fatalf("results length %d != registry length %d", len(results), len(sysctlChecks))
	}

	valid := map[Status]bool{StatusGood: true, StatusWarn: true, StatusBad: true, StatusNA: true}
	for i, r := range results {
		if !valid[r.Result.Status] {
			t.Errorf("results[%d] has unexpected status %q", i, r.Result.Status)
		}
	}
}

func TestSysctlCheck_EachResultHasRequiredFields(t *testing.T) {
	for i, r := range SysctlCheck() {
		if r.Name == "" {
			t.Errorf("results[%d] missing Name", i)
		}
		if r.Desc == "" {
			t.Errorf("results[%d] missing Desc", i)
		}
		if r.Type != "Sysctl" {
			t.Errorf("results[%d] Type = %q, want Sysctl", i, r.Type)
		}
		if r.Result.Value == "" {
			t.Errorf("results[%d] missing Result.Value", i)
		}
	}
}
