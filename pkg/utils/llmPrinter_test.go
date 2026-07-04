package utils

import (
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func TestSevGlyph(t *testing.T) {
	cases := []struct {
		status checksec.Status
		want   string
	}{
		{checksec.StatusGood, "ok"},
		{checksec.StatusWarn, "~"},
		{checksec.StatusBad, "!"},
		{checksec.StatusError, "!"},
		{checksec.StatusInfo, "i"},
		{checksec.StatusNA, "i"},
	}

	for _, tc := range cases {
		if got := sevGlyph(tc.status); got != tc.want {
			t.Errorf("sevGlyph(%v) = %q, want %q", tc.status, got, tc.want)
		}
	}
}
