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

// TestRunListChecksParallel asserts the parallel scanner returns one report
// per input path, in input order, and produces results identical to the
// serial path.
func TestRunListChecksParallel(t *testing.T) {
	bin := buildLinuxELF(t)
	paths := []string{bin, "/nonexistent/a", bin, "/nonexistent/b"}

	serial := RunListChecks(paths, "")
	parallel := RunListChecksParallel(paths, "", 4)

	if len(parallel) != len(paths) {
		t.Fatalf("parallel returned %d reports, want %d", len(parallel), len(paths))
	}
	for i := range paths {
		if parallel[i].Name != paths[i] {
			t.Errorf("parallel[%d].Name = %q, want %q (order not preserved)", i, parallel[i].Name, paths[i])
		}
		if parallel[i].Checks["relro"].Value != serial[i].Checks["relro"].Value {
			t.Errorf("parallel[%d] relro = %q, serial = %q", i,
				parallel[i].Checks["relro"].Value, serial[i].Checks["relro"].Value)
		}
	}
}

func TestRunListChecksParallel_WorkersClamp(t *testing.T) {
	bin := buildLinuxELF(t)
	// workers <= 0 must default to a sane value, not hang or panic.
	got := RunListChecksParallel([]string{bin}, "", 0)
	if len(got) != 1 {
		t.Fatalf("expected 1 report with workers=0, got %d", len(got))
	}
	got = RunListChecksParallel(nil, "", 4)
	if len(got) != 0 {
		t.Fatalf("expected 0 reports for nil input, got %d", len(got))
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
