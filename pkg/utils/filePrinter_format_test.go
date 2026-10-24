package utils

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
	"github.com/slimm609/checksec/v3/pkg/target"
)

func sampleMachOReport(name string) FileReport {
	r := FileReport{Name: name, Format: string(target.MachO), Arch: "arm64", Checks: map[string]checksec.Result{}}
	for _, f := range MachOFields {
		r.Checks[f.Key] = checksec.Result{Value: "m_" + f.Key, Status: checksec.StatusGood}
	}
	return r
}

func sampleELFReport(name string) FileReport {
	r := sampleReport()
	r.Name = name
	r.Format = string(target.ELF)
	return r
}

func TestGroupReports(t *testing.T) {
	unknown := FileReport{Name: "u", Format: string(target.Unknown), Checks: map[string]checksec.Result{}}
	reports := []FileReport{unknown, sampleMachOReport("m1"), sampleELFReport("e1"), sampleMachOReport("m2")}
	groups := groupReports(reports, PrintOptions{})
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3 (unknown, macho, elf)", len(groups))
	}
	if groups[0].reports[0].Name != "u" || len(groups[0].fields) != len(ELFFields) {
		t.Errorf("group 0 should be the unknown report rendered with ELF fields")
	}
	if len(groups[1].reports) != 2 || groups[1].reports[1].Name != "m2" || len(groups[1].fields) != len(MachOFields) {
		t.Errorf("group 1 should hold both macho reports in order: %+v", groups[1])
	}
	if groups[2].reports[0].Name != "e1" {
		t.Errorf("group 2 should be ELF")
	}
	// Legacy reports without Format land in the ELF group.
	legacy := []FileReport{sampleReport(), sampleELFReport("e")}
	if g := groupReports(legacy, PrintOptions{}); len(g) != 1 {
		t.Errorf("empty Format and \"elf\" must share a group, got %d groups", len(g))
	}
	// Explicit Fields override collapses everything into one group.
	if g := groupReports(reports, PrintOptions{Fields: ProcFields}); len(g) != 1 || len(g[0].fields) != len(ProcFields) {
		t.Errorf("Fields override must yield one group with those fields")
	}
	// No reports: one empty ELF group so headers still print.
	if g := groupReports(nil, PrintOptions{}); len(g) != 1 || len(g[0].fields) != len(ELFFields) {
		t.Errorf("empty input must yield one ELF group")
	}
}

// Review Focus 5: unknown first, then Mach-O; one header per group in order.
func TestTable_GroupsByFormatWithHeaders(t *testing.T) {
	unknown := FileReport{Name: "u", Format: string(target.Unknown), Checks: map[string]checksec.Result{}}
	for _, f := range ELFFields {
		unknown.Checks[f.Key] = checksec.Err(f.Key)
	}
	var buf bytes.Buffer
	FilePrinter(&buf, "table", []FileReport{unknown, sampleMachOReport("m")}, PrintOptions{NoBanner: true})
	out := buf.String()
	if strings.Count(out, "RELRO") != 1 {
		t.Errorf("ELF header should print once:\n%s", out)
	}
	if strings.Count(out, "Hardened") != 1 || strings.Count(out, "Entitlements") != 1 {
		t.Errorf("Mach-O header should print once:\n%s", out)
	}
	if strings.Index(out, "RELRO") > strings.Index(out, "Hardened") {
		t.Errorf("groups must print in first-seen order:\n%s", out)
	}
	if !strings.Contains(out, "m_signature") {
		t.Errorf("Mach-O values missing:\n%s", out)
	}
}

func TestTable_MachOOnlyPrintsNoELFHeader(t *testing.T) {
	var buf bytes.Buffer
	FilePrinter(&buf, "table", []FileReport{sampleMachOReport("m")}, PrintOptions{NoBanner: true})
	if strings.Contains(buf.String(), "RELRO") {
		t.Errorf("ELF header must not appear for a Mach-O only run:\n%s", buf.String())
	}
}

func TestCSV_UnionColumnsPlusFormat(t *testing.T) {
	var buf bytes.Buffer
	FilePrinter(&buf, "csv", []FileReport{sampleELFReport("e"), sampleMachOReport("m")}, PrintOptions{NoBanner: true})
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("csv: %v\n%s", err, buf.String())
	}
	all := AllFields()
	wantCols := len(all) + 2
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want header + 2", len(rows))
	}
	for i, row := range rows {
		if len(row) != wantCols {
			t.Fatalf("row %d has %d cols, want %d", i, len(row), wantCols)
		}
	}
	if rows[0][wantCols-2] != "Format" || rows[0][wantCols-1] != "Name" {
		t.Errorf("trailing headers = %q %q", rows[0][wantCols-2], rows[0][wantCols-1])
	}
	col := map[string]int{}
	for i, f := range all {
		col[f.Key] = i
	}
	if rows[1][col["relro"]] != "v_relro" || rows[1][col["signature"]] != "" || rows[1][wantCols-2] != "elf" {
		t.Errorf("ELF row wrong: %v", rows[1])
	}
	if rows[2][col["signature"]] != "m_signature" || rows[2][col["relro"]] != "" || rows[2][wantCols-2] != "macho" {
		t.Errorf("Mach-O row wrong: %v", rows[2])
	}
}

func TestXML_PerFormatKeysAndAttrs(t *testing.T) {
	var buf bytes.Buffer
	FilePrinter(&buf, "xml", []FileReport{sampleELFReport("e"), sampleMachOReport("m")}, PrintOptions{NoBanner: true})
	out := buf.String()
	var sink any
	if err := xml.Unmarshal(buf.Bytes(), &sink); err != nil {
		t.Fatalf("not well-formed: %v\n%s", err, out)
	}
	if !strings.Contains(out, `format="macho"`) || !strings.Contains(out, `arch="arm64"`) || !strings.Contains(out, `format="elf"`) {
		t.Errorf("missing format/arch attrs:\n%s", out)
	}
	if strings.Count(out, "<signature") != 1 || strings.Count(out, "<relro") != 1 {
		t.Errorf("each file must list only its own registry's keys:\n%s", out)
	}
}

func TestLLM_MixedFormats(t *testing.T) {
	m := sampleMachOReport("m")
	m.Checks["hardened_runtime"] = checksec.Result{Value: "Disabled", Status: checksec.StatusBad}
	var buf bytes.Buffer
	FilePrinter(&buf, "llm", []FileReport{sampleELFReport("e"), m}, PrintOptions{NoBanner: true})
	out := buf.String()
	if !strings.Contains(out, "## Target: e (elf)") || !strings.Contains(out, "## Target: m (macho)") {
		t.Errorf("target headers must name the format:\n%s", out)
	}
	if !strings.Contains(out, "- [!] hardened_runtime = Disabled") {
		t.Errorf("Mach-O rows must render with their own fields:\n%s", out)
	}
	if !strings.Contains(out, "Fix: `codesign --options runtime`") {
		t.Errorf("knowledge block must include the Mach-O fix for a red check:\n%s", out)
	}
	if strings.Count(out, "## Checks present") != 1 {
		t.Errorf("knowledge block must appear once:\n%s", out)
	}
	if !strings.Contains(out, "- relro") {
		t.Errorf("knowledge block must still cover ELF ids:\n%s", out)
	}
}
