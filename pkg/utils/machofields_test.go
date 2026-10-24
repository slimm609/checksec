package utils

import (
	"strings"
	"testing"
)

func TestMachOFields_RegistryWellFormed(t *testing.T) {
	if len(MachOFields) == 0 {
		t.Fatal("MachOFields registry is empty")
	}
	seen := map[string]bool{}
	for _, f := range MachOFields {
		if f.Key == "" || f.Header == "" || f.Run == nil {
			t.Errorf("malformed field %+v", f)
		}
		if seen[f.Key] {
			t.Errorf("duplicate key %q", f.Key)
		}
		seen[f.Key] = true
	}
	for _, core := range []string{"pie", "nx", "canary", "symbols", "rpath", "separate_code", "cfi", "fortify_source", "sanitizers"} {
		if !seen[core] {
			t.Errorf("core key %q missing from MachOFields", core)
		}
	}
	for _, own := range []string{"signature", "hardened_runtime", "entitlements", "encrypted", "fixups", "dyld_env", "restrict", "arc", "min_os"} {
		if !seen[own] {
			t.Errorf("Mach-O key %q missing from MachOFields", own)
		}
	}
}

// Every Mach-O key gets a real value (not Err) on a real fixture.
func TestRunPathChecks_PopulatesEveryMachOField(t *testing.T) {
	p := requireMachoFixture(t, "exec_arm64")
	r := RunPathChecks(p, "")[0]
	if len(r.Checks) != len(MachOFields) {
		t.Errorf("report has %d checks, registry has %d", len(r.Checks), len(MachOFields))
	}
	for _, f := range MachOFields {
		res, ok := r.Checks[f.Key]
		if !ok {
			t.Errorf("missing %q", f.Key)
			continue
		}
		if res.Value == "" || res.Status == "" || strings.HasPrefix(res.Value, "Error checking") {
			t.Errorf("field %q = %+v", f.Key, res)
		}
	}
	if r.Checks["pie"].Value != "PIE Enabled" || r.Checks["signature"].Value != "Linker-signed" {
		t.Errorf("spot check failed: pie=%q signature=%q", r.Checks["pie"].Value, r.Checks["signature"].Value)
	}
}

// A fat slice that fails to parse still gets every Mach-O key as Err.
func TestRunPathChecks_BadSliceStillPopulates(t *testing.T) {
	orig := openTarget
	defer func() { openTarget = orig }()
	openTarget = func(path string) ([]*scanContext, error) {
		ctxs, err := orig(path)
		if err == nil && len(ctxs) > 0 {
			ctxs[0].target.MachO = nil // simulate an unparsable slice
		}
		return ctxs, err
	}
	p := requireMachoFixture(t, "fat")
	reports := RunPathChecks(p, "")
	for _, f := range MachOFields {
		if res, ok := reports[0].Checks[f.Key]; !ok || !strings.HasPrefix(res.Value, "Error checking") {
			t.Errorf("bad slice field %q = %+v, want Err", f.Key, res)
		}
	}
}
