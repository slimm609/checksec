package utils

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"regexp"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func sampleReport() FileReport {
	r := FileReport{Name: "bin", Checks: map[string]checksec.Result{}}
	for _, f := range FileFields {
		r.Checks[f.Key] = checksec.Result{Value: "v_" + f.Key, Status: checksec.StatusGood}
	}
	return r
}

func TestFilePrinter_JSONIsValid(t *testing.T) {
	var buf bytes.Buffer
	FilePrinter(&buf, "json", []FileReport{sampleReport()}, PrintOptions{NoBanner: true})
	if !json.Valid(buf.Bytes()) {
		t.Fatalf("invalid JSON:\n%s", buf.String())
	}
}

func TestFilePrinter_YAMLNonEmpty(t *testing.T) {
	var buf bytes.Buffer
	FilePrinter(&buf, "yaml", []FileReport{sampleReport()}, PrintOptions{NoBanner: true})
	if buf.Len() == 0 || !strings.Contains(buf.String(), "name:") {
		t.Fatalf("unexpected YAML:\n%s", buf.String())
	}
}

func TestFilePrinter_XMLWellFormed(t *testing.T) {
	var buf bytes.Buffer
	FilePrinter(&buf, "xml", []FileReport{sampleReport()}, PrintOptions{NoBanner: true})
	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "<") {
		t.Fatalf("expected XML, got:\n%s", out)
	}
	// Must parse as well-formed XML.
	var sink any
	if err := xml.Unmarshal(buf.Bytes(), &sink); err != nil {
		t.Fatalf("XML not well-formed: %v\n%s", err, out)
	}
}

func TestFilePrinter_TableNonEmpty(t *testing.T) {
	var buf bytes.Buffer
	FilePrinter(&buf, "table", []FileReport{sampleReport()}, PrintOptions{NoBanner: true, NoHeader: false})
	if buf.Len() == 0 {
		t.Fatal("expected table output")
	}
}

// TestFilePrinter_CSVParsesAndMatchesRegistry asserts CSV output parses with
// encoding/csv, has one header row + one data row per report, and column count
// equals len(FileFields)+1 (the trailing Name column).
func TestFilePrinter_CSVParsesAndMatchesRegistry(t *testing.T) {
	reports := []FileReport{sampleReport(), sampleReport()}
	reports[1].Name = "bin2"

	var buf bytes.Buffer
	FilePrinter(&buf, "csv", reports, PrintOptions{NoBanner: true, NoHeader: false})

	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("CSV not parseable: %v\n%s", err, buf.String())
	}
	wantRows := 1 + len(reports) // header + data
	if len(rows) != wantRows {
		t.Fatalf("got %d CSV rows, want %d\n%s", len(rows), wantRows, buf.String())
	}
	wantCols := len(FileFields) + 1 // checks + Name
	for i, row := range rows {
		if len(row) != wantCols {
			t.Fatalf("row %d has %d columns, want %d: %v", i, len(row), wantCols, row)
		}
	}
	// Header row must match registry headers in order.
	for i, f := range FileFields {
		if rows[0][i] != f.Header {
			t.Errorf("header[%d] = %q, want %q", i, rows[0][i], f.Header)
		}
	}
	if rows[0][wantCols-1] != "Name" {
		t.Errorf("last header = %q, want Name", rows[0][wantCols-1])
	}
	// Data row must carry the report name in the last column.
	if rows[1][wantCols-1] != "bin" || rows[2][wantCols-1] != "bin2" {
		t.Errorf("data rows missing names: %v / %v", rows[1], rows[2])
	}
}

func TestFilePrinter_CSVNoHeader(t *testing.T) {
	var buf bytes.Buffer
	FilePrinter(&buf, "csv", []FileReport{sampleReport()}, PrintOptions{NoBanner: true, NoHeader: true})
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("CSV not parseable: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 data row with NoHeader, got %d", len(rows))
	}
}

func TestFilePrinter_EmptyReports(t *testing.T) {
	for _, format := range []string{"json", "yaml", "xml", "csv", "table"} {
		var buf bytes.Buffer
		FilePrinter(&buf, format, []FileReport{}, PrintOptions{NoBanner: true, NoHeader: true})
		// Must not panic; json/yaml emit "[]" / "[]\n", xml emits root, table emits nothing.
		_ = buf.String()
	}
}

// TestFilePrinter_TableAlignedWithColor forces ANSI colours on and asserts that
// after stripping escape sequences, every value column starts at the same byte
// offset on every line. This guards against the tabwriter/ANSI-width bug.
func TestFilePrinter_TableAlignedWithColor(t *testing.T) {
	prev := color.NoColor
	color.NoColor = false
	defer func() { color.NoColor = prev }()

	reports := []FileReport{sampleReport(), sampleReport()}
	// Make row values differ in length so misalignment would be visible.
	reports[1].Checks["relro"] = checksec.Result{Value: "X", Status: checksec.StatusBad}

	var buf bytes.Buffer
	FilePrinter(&buf, "table", reports, PrintOptions{NoBanner: true, NoHeader: false})

	ansi := regexp.MustCompile("\x1b\\[[0-9;]*m")
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected header + 2 rows, got %d lines", len(lines))
	}
	plain := make([]string, len(lines))
	for i, l := range lines {
		plain[i] = ansi.ReplaceAllString(l, "")
	}
	// Second column header is FileFields[1].Header; find its offset on the
	// header line and assert each row's second-column value starts there too.
	col2 := strings.Index(plain[0], FileFields[1].Header)
	if col2 <= 0 {
		t.Fatalf("could not locate column 2 header in %q", plain[0])
	}
	for i, l := range plain[1:] {
		want := reports[i].Checks[FileFields[1].Key].Value
		if got := strings.Index(l, want); got != col2 {
			t.Errorf("row %d column 2 misaligned: header at %d, value %q at %d\n%s",
				i, col2, want, got, strings.Join(plain, "\n"))
		}
	}
}

func TestColumnWidths(t *testing.T) {
	r := FileReport{Name: "x", Checks: map[string]checksec.Result{}}
	for _, f := range FileFields {
		r.Checks[f.Key] = checksec.Result{Value: "ab"}
	}
	long := strings.Repeat("z", 40)
	r.Checks[FileFields[0].Key] = checksec.Result{Value: long}

	w := columnWidths([]FileReport{r}, FileFields)
	if w[0] != len(long) {
		t.Errorf("col 0 width = %d, want %d", w[0], len(long))
	}
	if w[1] != len(FileFields[1].Header) {
		t.Errorf("col 1 width = %d, want header len %d", w[1], len(FileFields[1].Header))
	}
}

// TestFilePrinter_CustomFieldList asserts opts.Fields overrides the column set
// for ordered formats — the mechanism proc/procAll use to add Seccomp.
func TestFilePrinter_CustomFieldList(t *testing.T) {
	custom := append(append([]Field{}, FileFields...), Field{Key: "extra", Header: "Extra"})
	r := sampleReport()
	r.Checks["extra"] = checksec.Result{Value: "EXTRA_VAL", Status: checksec.StatusGood}

	for _, format := range []string{"table", "csv", "xml"} {
		var buf bytes.Buffer
		FilePrinter(&buf, format, []FileReport{r}, PrintOptions{NoBanner: true, NoHeader: false, Fields: custom})
		if !strings.Contains(buf.String(), "EXTRA_VAL") {
			t.Errorf("%s: custom field not rendered\n%s", format, buf.String())
		}
	}
	// Default field list must NOT include the extra column.
	var buf bytes.Buffer
	FilePrinter(&buf, "csv", []FileReport{r}, PrintOptions{NoBanner: true})
	if strings.Contains(buf.String(), "EXTRA_VAL") {
		t.Error("default field list leaked custom column")
	}
}

func TestFilePrinter_MultipleReports(t *testing.T) {
	reports := []FileReport{sampleReport(), sampleReport()}
	reports[1].Name = "bin2"
	var buf bytes.Buffer
	FilePrinter(&buf, "json", reports, PrintOptions{NoBanner: true})
	var got []FileReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 || got[0].Name != "bin" || got[1].Name != "bin2" {
		t.Fatalf("expected 2 reports preserved in order, got %+v", got)
	}
}
