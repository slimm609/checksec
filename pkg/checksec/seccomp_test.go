package checksec

import (
	"strings"
	"testing"
)

// TestParseSeccompStatus drives the pure /proc/<pid>/status parser. Values per
// proc(5): 0=disabled, 1=strict, 2=filter.
func TestParseSeccompStatus(t *testing.T) {
	tests := []struct {
		name       string
		status     string
		wantValue  string
		wantStatus Status
	}{
		{"disabled", "Name:\tcat\nSeccomp:\t0\n", "Disabled", StatusBad},
		{"strict", "Name:\tcat\nSeccomp:\t1\n", "Strict", StatusGood},
		{"filter", "Name:\tcat\nSeccomp:\t2\n", "Filter", StatusGood},
		{"filter with Seccomp_filters line", "Seccomp:\t2\nSeccomp_filters:\t3\n", "Filter", StatusGood},
		{"missing Seccomp line", "Name:\tcat\nState:\tS\n", "Unknown", StatusWarn},
		{"unrecognised value", "Seccomp:\t9\n", "Unknown", StatusWarn},
		{"leading/trailing whitespace", "Seccomp:   2  \n", "Filter", StatusGood},
		{"empty input", "", "Unknown", StatusWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := parseSeccompStatus(strings.NewReader(tt.status))
			if r.Value != tt.wantValue || r.Status != tt.wantStatus {
				t.Errorf("parseSeccompStatus(%q) = %+v, want {%q, %q}", tt.status, r, tt.wantValue, tt.wantStatus)
			}
		})
	}
}

func TestSeccomp_NonexistentPID(t *testing.T) {
	r := Seccomp(-1)
	if r.Value != "Unknown" {
		t.Errorf("Seccomp(-1) = %+v, want Unknown", r)
	}
}
