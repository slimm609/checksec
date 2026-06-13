package utils

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// TestFileFields_RegistryWellFormed asserts the single-source-of-truth registry
// is internally consistent: non-empty, unique keys, every field renderable.
func TestFileFields_RegistryWellFormed(t *testing.T) {
	if len(FileFields) == 0 {
		t.Fatal("FileFields registry is empty")
	}
	seen := map[string]bool{}
	for _, f := range FileFields {
		if f.Key == "" {
			t.Errorf("field with empty Key: %+v", f)
		}
		if f.Header == "" {
			t.Errorf("field %q has empty Header", f.Key)
		}
		if f.Run == nil {
			t.Errorf("field %q has nil Run", f.Key)
		}
		if seen[f.Key] {
			t.Errorf("duplicate field key %q", f.Key)
		}
		seen[f.Key] = true
	}
}

// TestFilePrinter_AllFieldsInAllFormats is the structural guarantee that makes
// the CFI-dropped-from-XML class of bug impossible: every registered field must
// appear in every output format. Adding a field to FileFields automatically
// extends this assertion.
func TestFilePrinter_AllFieldsInAllFormats(t *testing.T) {
	report := FileReport{
		Name:   "/bin/sentinel",
		Checks: make(map[string]checksec.Result, len(FileFields)),
	}
	for _, f := range FileFields {
		report.Checks[f.Key] = checksec.Result{
			Value:  "SENTINEL_" + f.Key,
			Status: checksec.StatusGood,
		}
	}

	for _, format := range []string{"json", "yaml", "xml", "csv", "table"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			FilePrinter(&buf, format, []FileReport{report}, PrintOptions{NoBanner: true, NoHeader: true})
			out := buf.String()
			for _, f := range FileFields {
				if !strings.Contains(out, "SENTINEL_"+f.Key) {
					t.Errorf("%s output dropped field %q\n---\n%s", format, f.Key, out)
				}
			}
			if !strings.Contains(out, "/bin/sentinel") {
				t.Errorf("%s output dropped report name\n---\n%s", format, out)
			}
		})
	}
}

// TestFilePrinter_TableHeaderMatchesRegistry asserts table headers are driven
// by the registry, not a hand-maintained printf string.
func TestFilePrinter_TableHeaderMatchesRegistry(t *testing.T) {
	var buf bytes.Buffer
	FilePrinter(&buf, "table", []FileReport{}, PrintOptions{NoBanner: true, NoHeader: false})
	out := buf.String()
	for _, f := range FileFields {
		if !strings.Contains(out, f.Header) {
			t.Errorf("table header missing %q\n---\n%s", f.Header, out)
		}
	}
}

// TestFilePrinter_JSONRoundTrips asserts the JSON output is the FileReport
// shape directly — no lossy intermediate struct.
func TestFilePrinter_JSONRoundTrips(t *testing.T) {
	want := FileReport{
		Name: "x",
		Checks: map[string]checksec.Result{
			"relro": {Value: "Full RELRO", Status: checksec.StatusGood},
		},
	}
	var buf bytes.Buffer
	FilePrinter(&buf, "json", []FileReport{want}, PrintOptions{NoBanner: true})

	var got []FileReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json output does not decode back into []FileReport: %v\n%s", err, buf.String())
	}
	if len(got) != 1 || got[0].Name != "x" || got[0].Checks["relro"].Value != "Full RELRO" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// TestRunFileChecks_PopulatesEveryRegisteredField asserts the scan produces a
// Result for every key in the registry — no field left zero-valued.
func TestRunFileChecks_PopulatesEveryRegisteredField(t *testing.T) {
	bin := buildLinuxELF(t)
	report := RunFileChecks(bin, "")

	if report.Name != bin {
		t.Errorf("report.Name = %q, want %q", report.Name, bin)
	}
	for _, f := range FileFields {
		res, ok := report.Checks[f.Key]
		if !ok {
			t.Errorf("RunFileChecks omitted field %q", f.Key)
			continue
		}
		if res.Value == "" {
			t.Errorf("field %q has empty Value", f.Key)
		}
		if res.Status == "" {
			t.Errorf("field %q has empty Status", f.Key)
		}
	}
	if len(report.Checks) != len(FileFields) {
		t.Errorf("report has %d checks, registry has %d", len(report.Checks), len(FileFields))
	}
}

// TestRunFileChecks_ErrorPathStillPopulates asserts a check that errors
// produces an error Result rather than a missing key — formats stay aligned.
func TestRunFileChecks_ErrorPathStillPopulates(t *testing.T) {
	report := RunFileChecks("/nonexistent/binary/path", "")
	for _, f := range FileFields {
		if _, ok := report.Checks[f.Key]; !ok {
			t.Errorf("error path dropped field %q", f.Key)
		}
	}
}

// TestRunProcChecks_AddsSeccomp asserts the proc-mode wrapper enriches the
// report with a seccomp field and that ProcFields contains it.
func TestRunProcChecks_AddsSeccomp(t *testing.T) {
	bin := buildLinuxELF(t)
	report := RunProcChecks(-1, bin, "") // -1 → no /proc → seccomp Unknown
	if _, ok := report.Checks["seccomp"]; !ok {
		t.Fatal("RunProcChecks did not populate seccomp")
	}
	// ProcFields must be FileFields + seccomp.
	if len(ProcFields) != len(FileFields)+1 {
		t.Fatalf("ProcFields len = %d, want %d", len(ProcFields), len(FileFields)+1)
	}
	if ProcFields[len(ProcFields)-1].Key != "seccomp" {
		t.Errorf("last ProcFields key = %q, want seccomp", ProcFields[len(ProcFields)-1].Key)
	}
	// And rendering with ProcFields must include it.
	var buf bytes.Buffer
	FilePrinter(&buf, "csv", []FileReport{report}, PrintOptions{NoBanner: true, Fields: ProcFields})
	if !strings.Contains(buf.String(), "Seccomp") {
		t.Errorf("ProcFields CSV output missing Seccomp column:\n%s", buf.String())
	}
}

// TestRunFileChecks_OpensTargetExactlyOnce is the structural guarantee that the
// ELF is opened once by scanContext and shared across every check. Verified by
// counting calls through the openTarget hook — any check that re-opened by path
// would not go through this hook, but the registry no longer passes c.path to
// checks, so they cannot.
func TestRunFileChecks_OpensTargetExactlyOnce(t *testing.T) {
	bin := buildLinuxELF(t)

	orig := openTarget
	defer func() { openTarget = orig }()
	var opens int
	openTarget = func(path string) (*scanContext, error) {
		opens++
		return orig(path)
	}

	_ = RunFileChecks(bin, "")
	if opens != 1 {
		t.Fatalf("openTarget called %d times, want 1", opens)
	}
}

// TestRunFileChecks_SurvivesUnlinkAfterOpen proves no check re-opens by path:
// the binary is unlinked immediately after scanContext acquires its handle, so
// any path-based elf.Open inside a check would fail and surface as an Error
// result. All checks must instead read from the shared open descriptor.
func TestRunFileChecks_SurvivesUnlinkAfterOpen(t *testing.T) {
	bin := buildLinuxELF(t)

	orig := openTarget
	defer func() { openTarget = orig }()
	openTarget = func(path string) (*scanContext, error) {
		c, err := orig(path)
		_ = os.Remove(path) // unlink AFTER the handle is acquired
		return c, err
	}

	report := RunFileChecks(bin, "")
	for _, f := range FileFields {
		res := report.Checks[f.Key]
		if strings.HasPrefix(res.Value, "Error checking") {
			t.Errorf("check %q re-opened by path after unlink: %+v", f.Key, res)
		}
	}
}
