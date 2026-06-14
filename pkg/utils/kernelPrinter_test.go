package utils

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func sampleKernelChecks() []checksec.KernelCheck {
	return []checksec.KernelCheck{
		{Name: "CONFIG_STACKPROTECTOR", Desc: "Stack Protector", Type: "Kernel Config",
			Result: checksec.Result{Value: "Enabled", Status: checksec.StatusGood}},
		{Name: "kernel.kptr_restrict", Desc: "Kernel Pointer Restrictions", Type: "Sysctl",
			Result: checksec.Result{Value: "Disabled", Status: checksec.StatusBad}},
	}
}

// TestKernelPrinter_AllFieldsInAllFormats — same structural guarantee as the
// file printer: every field of every check appears in every output format.
func TestKernelPrinter_AllFieldsInAllFormats(t *testing.T) {
	checks := sampleKernelChecks()
	for _, format := range []string{"json", "yaml", "xml", "csv", "table"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			KernelPrinter(&buf, format, checks, PrintOptions{NoBanner: true, NoHeader: true})
			out := buf.String()
			for _, c := range checks {
				for _, want := range []string{c.Name, c.Desc, c.Type, c.Result.Value} {
					if !strings.Contains(out, want) {
						t.Errorf("%s output missing %q\n---\n%s", format, want, out)
					}
				}
			}
		})
	}
}

func TestKernelPrinter_JSONRoundTrips(t *testing.T) {
	checks := sampleKernelChecks()
	var buf bytes.Buffer
	KernelPrinter(&buf, "json", checks, PrintOptions{NoBanner: true})
	var got []checksec.KernelCheck
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json output does not decode back into []KernelCheck: %v\n%s", err, buf.String())
	}
	if len(got) != len(checks) || got[0].Name != checks[0].Name || got[0].Result.Value != checks[0].Result.Value {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestKernelPrinter_XMLWellFormed(t *testing.T) {
	var buf bytes.Buffer
	KernelPrinter(&buf, "xml", sampleKernelChecks(), PrintOptions{NoBanner: true})
	var sink any
	if err := xml.Unmarshal(buf.Bytes(), &sink); err != nil {
		t.Fatalf("XML not well-formed: %v\n%s", err, buf.String())
	}
}

func TestKernelPrinter_TableHeader(t *testing.T) {
	var buf bytes.Buffer
	KernelPrinter(&buf, "table", sampleKernelChecks(), PrintOptions{NoBanner: true, NoHeader: false})
	for _, h := range []string{"Description", "Value", "Check Type", "Config Key"} {
		if !strings.Contains(buf.String(), h) {
			t.Errorf("table header missing %q", h)
		}
	}
}

func TestKernelPrinter_CSVParsesAndMatchesColumns(t *testing.T) {
	checks := sampleKernelChecks()
	var buf bytes.Buffer
	KernelPrinter(&buf, "csv", checks, PrintOptions{NoBanner: true, NoHeader: false})
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("CSV not parseable: %v\n%s", err, buf.String())
	}
	if len(rows) != 1+len(checks) {
		t.Fatalf("got %d rows, want %d", len(rows), 1+len(checks))
	}
	for i, col := range kernelColumns {
		if rows[0][i] != col.header {
			t.Errorf("header[%d] = %q, want %q", i, rows[0][i], col.header)
		}
	}
}

func TestKernelPrinter_EmptyInput(t *testing.T) {
	for _, format := range []string{"json", "yaml", "xml", "csv", "table"} {
		var buf bytes.Buffer
		KernelPrinter(&buf, format, []checksec.KernelCheck{}, PrintOptions{NoBanner: true, NoHeader: true})
	}
}

// TestParseKernel_TypedAndCombined asserts ParseKernel returns the typed slice
// directly (no map[string]any, no reflect.AppendSlice).
func TestParseKernel_TypedAndCombined(t *testing.T) {
	origK, origS := kernelConfigFn, sysctlCheckFn
	defer func() { kernelConfigFn, sysctlCheckFn = origK, origS }()

	kernelConfigFn = func(string) []checksec.KernelCheck {
		return []checksec.KernelCheck{{Name: "K", Desc: "kd", Type: "Kernel Config",
			Result: checksec.Result{Value: "Enabled", Status: checksec.StatusGood}}}
	}
	sysctlCheckFn = func() []checksec.KernelCheck {
		return []checksec.KernelCheck{{Name: "S", Desc: "sd", Type: "Sysctl",
			Result: checksec.Result{Value: "Disabled", Status: checksec.StatusBad}}}
	}

	got := ParseKernel("/tmp/config")
	if len(got) != 2 {
		t.Fatalf("expected 2 combined checks, got %d", len(got))
	}
	if got[0].Name != "K" || got[1].Name != "S" {
		t.Fatalf("kernel checks not preserved in order: %+v", got)
	}
}
