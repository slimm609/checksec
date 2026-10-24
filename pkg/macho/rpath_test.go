// pkg/macho/rpath_test.go
package macho

import (
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func TestRPATH(t *testing.T) {
	if r := RPATH(loadFixture(t, "exec_arm64")); r.Value != "No RPATH" || r.Status != checksec.StatusGood {
		t.Errorf("default: %+v", r)
	}
	r := RPATH(loadFixture(t, "rpath_arm64"))
	if r.Status != checksec.StatusBad || !strings.Contains(r.Value, "(relative)") {
		t.Errorf("rpath fixture must be red for the relative entry: %+v", r)
	}
	for _, want := range []string{"@executable_path/../Frameworks", "/usr/lib", "lib"} {
		if !strings.Contains(r.Value, want) {
			t.Errorf("value %q missing entry %q", r.Value, want)
		}
	}
}

func TestClassifyRpathEntry(t *testing.T) {
	cases := []struct {
		entry  string
		risk   rpathRisk
		reason string
	}{
		{"", rpInsecure, "empty"},
		{"@executable_path/../Frameworks", rpWarn, "@-relative"},
		{"@loader_path/lib", rpWarn, "@-relative"},
		{"@rpath/x", rpWarn, "@-relative"},
		{"lib", rpInsecure, "relative"},
		{"/usr/lib", rpSafe, ""},
		{"/nonexistent/dir/for/checksec", rpWarn, "nonexistent"},
		{"/tmp", rpInsecure, "world-writable"},
	}
	for _, tc := range cases {
		risk, reason := classifyRpathEntry(tc.entry)
		if risk != tc.risk || reason != tc.reason {
			t.Errorf("classify(%q) = %v/%q, want %v/%q", tc.entry, risk, reason, tc.risk, tc.reason)
		}
	}
}

// Review Focus: Mach-O has one path per LC_RPATH; a colon inside a path is
// part of the path, never a separator.
func TestSummarizeRpath_DoesNotSplitOnColon(t *testing.T) {
	r := summarizeRpath([]string{"/opt/a:b"})
	if !strings.Contains(r.Value, "/opt/a:b") {
		t.Errorf("colon path mangled: %q", r.Value)
	}
}
