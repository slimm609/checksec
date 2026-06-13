package utils

import (
	"strings"
	"testing"
)

// TestReadPathList verifies the path-list reader: one path per line, blank
// lines and #-comments skipped, whitespace trimmed.
func TestReadPathList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"single", "/bin/ls\n", []string{"/bin/ls"}},
		{"multiple", "/bin/ls\n/bin/cat\n", []string{"/bin/ls", "/bin/cat"}},
		{"blank lines skipped", "/bin/ls\n\n\n/bin/cat\n", []string{"/bin/ls", "/bin/cat"}},
		{"comments skipped", "# header\n/bin/ls\n  # indented comment\n/bin/cat\n", []string{"/bin/ls", "/bin/cat"}},
		{"trailing whitespace trimmed", "/bin/ls  \n\t/bin/cat\t\n", []string{"/bin/ls", "/bin/cat"}},
		{"no trailing newline", "/bin/ls", []string{"/bin/ls"}},
		{"empty input", "", nil},
		{"only comments", "# a\n# b\n", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadPathList(strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("ReadPathList() error = %v", err)
			}
			if !equalSlices(got, tt.want) {
				t.Errorf("ReadPathList() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunListChecks(t *testing.T) {
	bin := buildLinuxELF(t)
	reports := RunListChecks([]string{bin, "/nonexistent/path"}, "")
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(reports))
	}
	if reports[0].Name != bin {
		t.Errorf("report[0].Name = %q, want %q", reports[0].Name, bin)
	}
	// Nonexistent path → all fields populated with Err results.
	if !strings.HasPrefix(reports[1].Checks["relro"].Value, "Error") {
		t.Errorf("expected error result for nonexistent path, got %+v", reports[1].Checks["relro"])
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
