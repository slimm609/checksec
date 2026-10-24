package macho

import (
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func TestPIE(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		want    string
		status  checksec.Status
	}{
		{"arm64 default", "exec_arm64", "PIE Enabled", checksec.StatusGood},
		{"x86_64 no_pie", "nopie_x86_64", "PIE Disabled", checksec.StatusBad},
		{"dylib", "dylib.dylib", "DSO", checksec.StatusInfo},
		{"object", "obj.o", "Object", checksec.StatusWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := PIE(loadFixture(t, tc.fixture))
			if r.Value != tc.want || r.Status != tc.status {
				t.Errorf("PIE(%s) = %+v, want %q/%q", tc.fixture, r, tc.want, tc.status)
			}
		})
	}
}

func TestPIE_OtherFileTypesAreNA(t *testing.T) {
	f := syntheticMachO(t, 7, 0) // MH_DYLINKER
	r := PIE(f)
	if r.Value != "N/A" || r.Status != checksec.StatusNA {
		t.Errorf("dylinker: got %+v", r)
	}
}
