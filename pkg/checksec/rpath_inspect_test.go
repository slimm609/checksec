package checksec

import (
	"os"
	"path/filepath"
	"testing"
)

// TestClassifyRunpathEntry drives the per-entry classifier for RPATH/RUNPATH
// values. The security signal is not "is RPATH set" but "does any entry let an
// attacker control the load path" — relative paths, $ORIGIN, or world-writable
// directories.
func TestClassifyRunpathEntry(t *testing.T) {
	safeDir := t.TempDir() // 0700 by default → not world-writable
	wwDir := filepath.Join(t.TempDir(), "ww")
	if err := os.Mkdir(wwDir, 0o777); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Some systems apply umask; force the mode.
	if err := os.Chmod(wwDir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	tests := []struct {
		name   string
		entry  string
		want   runpathRisk
		reason string
	}{
		{"absolute safe dir", safeDir, rpSafe, ""},
		{"world-writable dir", wwDir, rpInsecure, "world-writable"},
		{"empty entry → cwd", "", rpInsecure, "empty (cwd)"},
		{"relative path", "lib", rpInsecure, "relative"},
		{"dot", ".", rpInsecure, "relative"},
		{"$ORIGIN literal", "$ORIGIN", rpWarn, "$ORIGIN"},
		{"${ORIGIN} braced", "${ORIGIN}/../lib", rpWarn, "$ORIGIN"},
		{"nonexistent absolute", "/no/such/dir/anywhere", rpWarn, "nonexistent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk, reason := classifyRunpathEntry(tt.entry)
			if risk != tt.want {
				t.Errorf("classifyRunpathEntry(%q) risk = %v, want %v (reason=%q)", tt.entry, risk, tt.want, reason)
			}
			if tt.reason != "" && reason != tt.reason {
				t.Errorf("classifyRunpathEntry(%q) reason = %q, want %q", tt.entry, reason, tt.reason)
			}
		})
	}
}

// TestSummarizeRunpath collapses a colon-separated path string into a Result.
// Worst entry wins: any insecure → StatusBad; else any warn → StatusWarn; else
// StatusInfo (RPATH set but all entries safe).
func TestSummarizeRunpath(t *testing.T) {
	safe := t.TempDir()
	tests := []struct {
		name       string
		paths      []string
		wantStatus Status
	}{
		{"none set", nil, StatusGood},
		{"single safe", []string{safe}, StatusInfo},
		{"safe + $ORIGIN", []string{safe + ":$ORIGIN"}, StatusWarn},
		{"safe + relative", []string{safe + ":./lib"}, StatusBad},
		{"multiple DT entries", []string{safe, "."}, StatusBad},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := summarizeRunpath("RPATH", tt.paths)
			if r.Status != tt.wantStatus {
				t.Errorf("summarizeRunpath(%v) = %+v, want status %q", tt.paths, r, tt.wantStatus)
			}
		})
	}
}

func TestSummarizeRunpath_ValueIncludesPath(t *testing.T) {
	r := summarizeRunpath("RPATH", []string{"./lib"})
	if r.Value == "RPATH" || r.Value == "" {
		t.Errorf("expected Value to include the path detail, got %q", r.Value)
	}
}
