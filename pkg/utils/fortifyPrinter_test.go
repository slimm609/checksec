package utils

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func sampleFortifyReport() FortifyReport {
	return FortifyReport{
		Name:          "bin",
		FortifySource: checksec.Result{Value: "Yes", Status: checksec.StatusGood},
		LibcSupport:   checksec.Result{Value: "Yes", Status: checksec.StatusGood},
		Fortified:     "2",
		Fortifiable:   "3",
		NoFortify:     "1",
		NumLibcFunc:   "18",
		NumFileFunc:   "42",
		Functions: []checksec.FortifyFunc{
			{Name: "memcpy", Fortified: true},
			{Name: "strcpy", Fortified: false},
		},
	}
}

// TestFortifyPrinter_TableBreakdown asserts the per-function table replaces
// the "Coming Soon" placeholder and shows each function's checked status.
func TestFortifyPrinter_TableBreakdown(t *testing.T) {
	var buf bytes.Buffer
	FortifyPrinter(&buf, "table", sampleFortifyReport(), PrintOptions{NoBanner: true})
	out := buf.String()
	if strings.Contains(out, "Coming Soon") {
		t.Errorf("table still contains 'Coming Soon' placeholder:\n%s", out)
	}
	for _, want := range []string{"memcpy", "__memcpy_chk", "strcpy", "unchecked"} {
		if !strings.Contains(out, want) {
			t.Errorf("table breakdown missing %q:\n%s", want, out)
		}
	}
}

func TestFortifyPrinter_TableBreakdownEmpty(t *testing.T) {
	r := sampleFortifyReport()
	r.Functions = nil
	var buf bytes.Buffer
	FortifyPrinter(&buf, "table", r, PrintOptions{NoBanner: true})
	if !strings.Contains(buf.String(), "(none referenced)") {
		t.Errorf("expected '(none referenced)' for empty Functions:\n%s", buf.String())
	}
}

func TestFortifyPrinter_JSONIncludesFunctions(t *testing.T) {
	var buf bytes.Buffer
	FortifyPrinter(&buf, "json", sampleFortifyReport(), PrintOptions{NoBanner: true})
	var got FortifyReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Functions) != 2 || got.Functions[0].Name != "memcpy" {
		t.Errorf("JSON Functions not round-tripped: %+v", got.Functions)
	}
}

// TestFortifyPrinter_AllFieldsInAllFormats — every FortifyReport field appears
// in every output format.
func TestFortifyPrinter_AllFieldsInAllFormats(t *testing.T) {
	r := sampleFortifyReport()
	wants := []string{r.Name, r.FortifySource.Value, r.LibcSupport.Value,
		r.Fortified, r.Fortifiable, r.NoFortify, r.NumLibcFunc, r.NumFileFunc}

	for _, format := range []string{"json", "yaml", "xml", "table"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			FortifyPrinter(&buf, format, r, PrintOptions{NoBanner: true})
			out := buf.String()
			for _, w := range wants {
				if !strings.Contains(out, w) {
					t.Errorf("%s output missing %q\n---\n%s", format, w, out)
				}
			}
		})
	}
}

func TestFortifyPrinter_JSONRoundTrips(t *testing.T) {
	want := sampleFortifyReport()
	var buf bytes.Buffer
	FortifyPrinter(&buf, "json", want, PrintOptions{NoBanner: true})
	var got FortifyReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json output does not decode back: %v\n%s", err, buf.String())
	}
	if got.Name != want.Name || got.Fortified != want.Fortified || got.FortifySource.Value != want.FortifySource.Value {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestFortifyPrinter_XMLWellFormed(t *testing.T) {
	var buf bytes.Buffer
	FortifyPrinter(&buf, "xml", sampleFortifyReport(), PrintOptions{NoBanner: true})
	var sink any
	if err := xml.Unmarshal(buf.Bytes(), &sink); err != nil {
		t.Fatalf("XML not well-formed: %v\n%s", err, buf.String())
	}
}

func TestRunFortifyCheck_ErrorPathPopulates(t *testing.T) {
	r := RunFortifyCheck("/nonexistent/path", "")
	if r.FortifySource.Value == "" {
		t.Error("error path left FortifySource empty")
	}
}

func TestRunFortifyCheck_RealELF(t *testing.T) {
	bin := buildLinuxELF(t)
	r := RunFortifyCheck(bin, "")
	if r.Name != bin {
		t.Errorf("Name = %q, want %q", r.Name, bin)
	}
	// Pure-Go binary has no libc → N/A is expected; just assert populated.
	if r.FortifySource.Value == "" || r.Fortified == "" || r.Fortifiable == "" {
		t.Errorf("incomplete report: %+v", r)
	}
}
