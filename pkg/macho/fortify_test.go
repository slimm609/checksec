// pkg/macho/fortify_test.go
package macho

import (
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func TestFortifySource(t *testing.T) {
	// Apple clang defaults to _FORTIFY_SOURCE=2 and test.c calls strcpy.
	if r := FortifySource(loadFixture(t, "exec_arm64")); r.Value != "Yes" || r.Status != checksec.StatusGood {
		t.Errorf("default: %+v", r)
	}
}

func TestClassifyFortify(t *testing.T) {
	cases := []struct {
		imports []string
		want    string
		status  checksec.Status
	}{
		{[]string{"___strcpy_chk", "_printf"}, "Yes", checksec.StatusGood},
		{[]string{"_strcpy", "_printf"}, "No", checksec.StatusBad},
		{[]string{"_malloc", "_free"}, "N/A", checksec.StatusNA},
		{nil, "N/A", checksec.StatusNA},
	}
	for _, tc := range cases {
		if v, s := classifyFortify(tc.imports); v != tc.want || s != tc.status {
			t.Errorf("classifyFortify(%v) = %q/%q, want %q/%q", tc.imports, v, s, tc.want, tc.status)
		}
	}
}
