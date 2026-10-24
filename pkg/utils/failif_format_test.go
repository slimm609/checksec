package utils

import (
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
	"github.com/slimm609/checksec/v3/pkg/target"
)

// A required key that applies to no scanned report is an error (fail closed).
func TestEvaluateFailIf_InapplicableKey(t *testing.T) {
	good := checksec.Result{Value: "yes", Status: checksec.StatusGood}
	bad := checksec.Result{Value: "no", Status: checksec.StatusBad}
	elf := FileReport{Name: "/elf", Format: string(target.ELF), Checks: map[string]checksec.Result{"relro": bad, "pie": good}}
	mo := FileReport{Name: "/macho", Format: string(target.MachO), Checks: map[string]checksec.Result{"pie": good, "hardened_runtime": bad}}

	if _, err := EvaluateFailIf([]FileReport{elf}, []string{"hardened_runtime"}); err == nil || !strings.Contains(err.Error(), "hardened_runtime") {
		t.Errorf("ELF-only + hardened_runtime: want error, got %v", err)
	}
	if _, err := EvaluateFailIf([]FileReport{mo}, []string{"relro"}); err == nil || !strings.Contains(err.Error(), "relro") {
		t.Errorf("Mach-O-only + relro: want error, got %v", err)
	}
	fails, err := EvaluateFailIf([]FileReport{elf, mo}, []string{"relro"})
	if err != nil || len(fails) != 1 || fails[0].File != "/elf" {
		t.Errorf("mixed + relro: %v %+v", err, fails)
	}
	if _, err := EvaluateFailIf([]FileReport{elf}, []string{"seccomp"}); err == nil || !strings.Contains(err.Error(), "seccomp") {
		t.Errorf("file report + seccomp: want error, got %v", err)
	}
	procGood := FileReport{Name: "good", Checks: map[string]checksec.Result{"seccomp": good}}
	procBad := FileReport{Name: "bad", Checks: map[string]checksec.Result{"seccomp": bad}}
	fails, err = EvaluateFailIf([]FileReport{procGood, procBad}, []string{"seccomp"})
	if err != nil || len(fails) != 1 || fails[0].File != "bad" {
		t.Errorf("proc seccomp: %v %+v", err, fails)
	}
	_, err = EvaluateFailIf([]FileReport{elf}, []string{"relro", "hardened_runtime"})
	if err == nil || !strings.Contains(err.Error(), "hardened_runtime") || strings.Contains(err.Error(), "relro") {
		t.Errorf("one applicable, one not: got %v", err)
	}
}

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
