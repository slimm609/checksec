package utils

import (
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
	"github.com/slimm609/checksec/v3/pkg/target"
)

// Spec 3.1: a fat file is opened once and every slice shares that descriptor.
func TestRunPathChecks_FatSharesOneDescriptor(t *testing.T) {
	p := requireMachoFixture(t, "fat")

	orig := openTarget
	defer func() { openTarget = orig }()
	var opens int
	var captured []*scanContext
	openTarget = func(path string) ([]*scanContext, error) {
		opens++
		ctxs, err := orig(path)
		captured = ctxs
		return ctxs, err
	}

	reports := RunPathChecks(p, "")
	if opens != 1 {
		t.Fatalf("openTarget called %d times for a fat file, want 1", opens)
	}
	if len(reports) != 2 || len(captured) != 2 {
		t.Fatalf("got %d reports / %d contexts, want 2 / 2", len(reports), len(captured))
	}
	if captured[0].target.Raw == nil || captured[0].target.Raw != captured[1].target.Raw {
		t.Errorf("fat slices must share one *os.File: %p vs %p", captured[0].target.Raw, captured[1].target.Raw)
	}
}

// Several inapplicable --fail-if keys are reported together, in the order given.
func TestEvaluateFailIf_SeveralInapplicableKeys(t *testing.T) {
	good := checksec.Result{Value: "yes", Status: checksec.StatusGood}
	elf := FileReport{Name: "/elf", Format: string(target.ELF), Checks: map[string]checksec.Result{"relro": good}}
	_, err := EvaluateFailIf([]FileReport{elf}, []string{"hardened_runtime", "signature"})
	if err == nil {
		t.Fatal("want error for two inapplicable keys")
	}
	if msg := err.Error(); !strings.Contains(msg, `keys "hardened_runtime", "signature" do not apply`) {
		t.Errorf("plural wording missing: %q", msg)
	}
}
