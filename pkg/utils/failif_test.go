package utils

import (
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// TestEvaluateFailIf drives the CI-gate evaluator: given a list of required
// check keys, return the (file, key) pairs where Status != StatusGood.
func TestEvaluateFailIf(t *testing.T) {
	good := checksec.Result{Value: "ok", Status: checksec.StatusGood}
	bad := checksec.Result{Value: "no", Status: checksec.StatusBad}
	warn := checksec.Result{Value: "?", Status: checksec.StatusWarn}
	info := checksec.Result{Value: "-", Status: checksec.StatusInfo}

	reports := []FileReport{
		{Name: "/a", Checks: map[string]checksec.Result{"relro": good, "canary": bad, "pie": warn}},
		{Name: "/b", Checks: map[string]checksec.Result{"relro": good, "canary": good, "pie": info}},
	}

	tests := []struct {
		name     string
		required []string
		wantLen  int
		wantErr  bool
	}{
		{"no requirements → no failures", nil, 0, false},
		{"all good", []string{"relro"}, 0, false},
		{"one bad", []string{"canary"}, 1, false},
		{"warn counts as failure", []string{"pie"}, 2, false},
		{"multiple keys", []string{"relro", "canary", "pie"}, 3, false},
		{"unknown key → error", []string{"nosuch"}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fails, err := EvaluateFailIf(reports, tt.required)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error for unknown key")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(fails) != tt.wantLen {
				t.Errorf("got %d failures, want %d: %+v", len(fails), tt.wantLen, fails)
			}
		})
	}
}

func TestEvaluateFailIf_FailureDetailsCorrect(t *testing.T) {
	reports := []FileReport{
		{Name: "/x", Checks: map[string]checksec.Result{"relro": {Value: "No RELRO", Status: checksec.StatusBad}}},
	}
	fails, _ := EvaluateFailIf(reports, []string{"relro"})
	if len(fails) != 1 || fails[0].File != "/x" || fails[0].Key != "relro" || fails[0].Result.Value != "No RELRO" {
		t.Fatalf("failure detail mismatch: %+v", fails)
	}
}

func TestParseFailIfKeys(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"relro", []string{"relro"}},
		{"relro,canary,pie", []string{"relro", "canary", "pie"}},
		{" relro , canary ", []string{"relro", "canary"}},
		{"relro,,canary", []string{"relro", "canary"}},
	}
	for _, tt := range tests {
		got := ParseFailIfKeys(tt.input)
		if strings.Join(got, "|") != strings.Join(tt.want, "|") {
			t.Errorf("ParseFailIfKeys(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
