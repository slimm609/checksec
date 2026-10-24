package utils

import (
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
	"github.com/slimm609/checksec/v3/pkg/target"
)

// Review Focus 5: core keys gate both formats; a format-specific key skips
// reports whose registry lacks it.
func TestEvaluateFailIf_MixedFormats(t *testing.T) {
	bad := checksec.Result{Value: "no", Status: checksec.StatusBad}
	reports := []FileReport{
		{Name: "/elf", Format: string(target.ELF), Checks: map[string]checksec.Result{"relro": bad, "pie": bad}},
		{Name: "/macho", Format: string(target.MachO), Checks: map[string]checksec.Result{"pie": bad, "hardened_runtime": bad}},
	}

	fails, err := EvaluateFailIf(reports, []string{"pie"})
	if err != nil || len(fails) != 2 {
		t.Fatalf("core key must gate both: %v %+v", err, fails)
	}
	fails, err = EvaluateFailIf(reports, []string{"relro"})
	if err != nil || len(fails) != 1 || fails[0].File != "/elf" {
		t.Fatalf("relro must skip the Mach-O row: %v %+v", err, fails)
	}
	fails, err = EvaluateFailIf(reports, []string{"hardened_runtime"})
	if err != nil || len(fails) != 1 || fails[0].File != "/macho" {
		t.Fatalf("hardened_runtime must skip the ELF row: %v %+v", err, fails)
	}
	// A key in the report's own registry but missing from Checks still fails.
	partial := []FileReport{{Name: "/e", Format: string(target.ELF), Checks: map[string]checksec.Result{}}}
	if fails, _ := EvaluateFailIf(partial, []string{"relro"}); len(fails) != 1 {
		t.Errorf("missing own-registry key must fail, got %+v", fails)
	}
	// Mach-O-only keys are valid --fail-if keys.
	if _, err := EvaluateFailIf(reports, []string{"signature", "entitlements"}); err != nil {
		t.Errorf("Mach-O keys must validate: %v", err)
	}
}
