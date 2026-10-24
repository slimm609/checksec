package utils

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/slimm609/checksec/v3/pkg/checksec"
	"github.com/slimm609/checksec/v3/pkg/output"
	"github.com/slimm609/checksec/v3/pkg/target"
	"sigs.k8s.io/yaml"
)

// PrintOptions controls FilePrinter rendering.
type PrintOptions struct {
	NoBanner bool
	NoHeader bool
	// Fields overrides the column set for table/CSV/XML rendering. When nil,
	// the default FileFields registry is used. proc/procAll set this to
	// ProcFields to add the per-process Seccomp column.
	Fields []Field
	// Chain enables rendering a hypothesis exploit chain (via RenderChain)
	// for reports that carry exploitability data.
	Chain bool
	// LLMNoPreamble suppresses the grounding preamble emitted by writeLLM
	// for the "llm" output format.
	LLMNoPreamble bool
}

func (o PrintOptions) fields() []Field {
	if o.Fields != nil {
		return o.Fields
	}
	return FileFields
}

// reportGroup is a run of reports that share a field registry.
type reportGroup struct {
	fields  []Field
	reports []FileReport
}

// fieldsForReport picks the registry a report renders with: the explicit
// override when set (proc mode), else the report's own format.
func fieldsForReport(r FileReport, opts PrintOptions) []Field {
	if opts.Fields != nil {
		return opts.Fields
	}
	return FieldsFor(target.Format(r.Format))
}

// groupReports splits reports by format in first-seen order. An explicit
// Fields override yields one group. No reports yields one empty ELF group so
// a header still prints.
func groupReports(reports []FileReport, opts PrintOptions) []reportGroup {
	if opts.Fields != nil {
		return []reportGroup{{fields: opts.Fields, reports: reports}}
	}
	var groups []reportGroup
	index := map[string]int{}
	for _, r := range reports {
		key := r.Format
		if key == "" || key == string(target.ELF) {
			key = string(target.ELF)
		}
		if i, ok := index[key]; ok {
			groups[i].reports = append(groups[i].reports, r)
			continue
		}
		index[key] = len(groups)
		groups = append(groups, reportGroup{fields: FieldsFor(target.Format(r.Format)), reports: []FileReport{r}})
	}
	if len(groups) == 0 {
		groups = []reportGroup{{fields: opts.fields()}}
	}
	return groups
}

// FilePrinter renders reports in the requested format. All ordered formats
// (table/CSV/XML) iterate opts.fields(), so a field added there appears
// everywhere with no printer changes. JSON/YAML marshal the FileReport map
// directly, so they carry every key present in Checks regardless of the field
// list.
func FilePrinter(w io.Writer, format string, reports []FileReport, opts PrintOptions) {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(reports)
	case "yaml":
		b, err := yaml.Marshal(reports)
		if err != nil {
			fmt.Fprintf(w, "err: %v\n", err)
			return
		}
		_, _ = w.Write(b)
	case "xml":
		writeXML(w, reports, opts.fields(), opts)
	case "csv":
		writeCSV(w, reports, opts.fields(), opts)
	case "llm":
		writeLLM(w, reports, opts)
	default:
		writeTable(w, reports, opts.fields(), opts)
	}
}

// writeCSV renders one rectangular table. Columns are the union of every
// registry (or the explicit Fields override) followed by Format and Name; a
// column that does not apply to a row is empty.
func writeCSV(w io.Writer, reports []FileReport, _ []Field, opts PrintOptions) {
	fields := opts.Fields
	if fields == nil {
		fields = AllFields()
	}
	cw := csv.NewWriter(w)
	if !opts.NoHeader {
		row := make([]string, 0, len(fields)+2)
		for _, f := range fields {
			row = append(row, f.Header)
		}
		_ = cw.Write(append(row, "Format", "Name"))
	}
	for _, r := range reports {
		row := make([]string, 0, len(fields)+2)
		for _, f := range fields {
			row = append(row, r.Checks[f.Key].Value) // zero Result -> ""
		}
		format := r.Format
		if format == "" {
			format = string(target.ELF)
		}
		_ = cw.Write(append(row, format, r.Name))
	}
	cw.Flush()
}

// writeTable renders reports as aligned, colourised tables, one per format
// group with its own header. Widths are computed from the visible (pre-ANSI)
// text and padding is applied before colouring.
func writeTable(w io.Writer, reports []FileReport, _ []Field, opts PrintOptions) {
	output.PrintLogo(opts.NoBanner)

	pad := func(s string, width int) string {
		return fmt.Sprintf("%-*s", width+2, s)
	}
	for gi, g := range groupReports(reports, opts) {
		if gi > 0 {
			fmt.Fprintln(w)
		}
		widths := columnWidths(g.reports, g.fields)
		if !opts.NoHeader {
			for i, f := range g.fields {
				fmt.Fprint(w, output.ColorPrinter(pad(f.Header, widths[i]), "unset"))
			}
			fmt.Fprintln(w, output.ColorPrinter("Name", "unset"))
		}
		for _, r := range g.reports {
			for i, f := range g.fields {
				res := r.Checks[f.Key]
				fmt.Fprint(w, output.ColorPrinter(pad(res.Value, widths[i]), string(res.Status)))
			}
			fmt.Fprintln(w, output.ColorPrinter(r.Name, "unset"))
			if r.Exploitability != nil {
				RenderExploitTable(w, r.Exploitability)
			}
			if r.Exploitability != nil && opts.Chain {
				RenderChain(w, r.Exploitability)
			}
		}
	}
}

// columnWidths returns the max visible width per field column across the
// header and all report rows.
func columnWidths(reports []FileReport, fields []Field) []int {
	widths := make([]int, len(fields))
	for i, f := range fields {
		widths[i] = len(f.Header)
		for _, r := range reports {
			if l := len(r.Checks[f.Key].Value); l > widths[i] {
				widths[i] = l
			}
		}
	}
	return widths
}

// xmlCheck / xmlReport are thin adapters that give XML a stable, ordered
// element list (encoding/xml cannot marshal map keys deterministically).
type xmlCheck struct {
	XMLName xml.Name
	Status  checksec.Status `xml:"status,attr"`
	Value   string          `xml:",chardata"`
}

type xmlReport struct {
	XMLName xml.Name   `xml:"file"`
	Name    string     `xml:"name,attr"`
	Format  string     `xml:"format,attr"`
	Arch    string     `xml:"arch,attr,omitempty"`
	Checks  []xmlCheck `xml:"checks>check"`
}

func writeXML(w io.Writer, reports []FileReport, _ []Field, opts PrintOptions) {
	root := struct {
		XMLName xml.Name    `xml:"checksec"`
		Files   []xmlReport `xml:"file"`
	}{}
	for _, r := range reports {
		format := r.Format
		if format == "" {
			format = string(target.ELF)
		}
		xr := xmlReport{Name: r.Name, Format: format, Arch: r.Arch}
		for _, f := range fieldsForReport(r, opts) {
			res := r.Checks[f.Key]
			xr.Checks = append(xr.Checks, xmlCheck{
				XMLName: xml.Name{Local: f.Key},
				Status:  res.Status,
				Value:   res.Value,
			})
		}
		root.Files = append(root.Files, xr)
	}
	b, err := xml.MarshalIndent(root, "", "  ")
	if err != nil {
		fmt.Fprintf(w, "err: %v\n", err)
		return
	}
	_, _ = w.Write(b)
	fmt.Fprintln(w)
}
