package utils

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/slimm609/checksec/v3/pkg/checksec"
	"github.com/slimm609/checksec/v3/pkg/output"
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
}

func (o PrintOptions) fields() []Field {
	if o.Fields != nil {
		return o.Fields
	}
	return FileFields
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
		writeXML(w, reports, opts.fields())
	case "csv":
		writeCSV(w, reports, opts.fields(), opts)
	default:
		writeTable(w, reports, opts.fields(), opts)
	}
}

// writeCSV renders reports as RFC 4180 CSV. Column order matches fields, with
// the file name as the trailing column.
func writeCSV(w io.Writer, reports []FileReport, fields []Field, opts PrintOptions) {
	cw := csv.NewWriter(w)
	if !opts.NoHeader {
		row := make([]string, 0, len(fields)+1)
		for _, f := range fields {
			row = append(row, f.Header)
		}
		_ = cw.Write(append(row, "Name"))
	}
	for _, r := range reports {
		row := make([]string, 0, len(fields)+1)
		for _, f := range fields {
			row = append(row, r.Checks[f.Key].Value)
		}
		_ = cw.Write(append(row, r.Name))
	}
	cw.Flush()
}

// writeTable renders reports as an aligned, colourised table. Column order and
// headers come from fields. Widths are computed from the visible (pre-ANSI)
// text and padding is applied before colouring, so escape sequences never
// affect alignment.
func writeTable(w io.Writer, reports []FileReport, fields []Field, opts PrintOptions) {
	output.PrintLogo(opts.NoBanner)

	widths := columnWidths(reports, fields)
	pad := func(s string, width int) string {
		return fmt.Sprintf("%-*s", width+2, s)
	}

	if !opts.NoHeader {
		for i, f := range fields {
			fmt.Fprint(w, output.ColorPrinter(pad(f.Header, widths[i]), "unset"))
		}
		fmt.Fprintln(w, output.ColorPrinter("Name", "unset"))
	}

	for _, r := range reports {
		for i, f := range fields {
			res := r.Checks[f.Key]
			fmt.Fprint(w, output.ColorPrinter(pad(res.Value, widths[i]), string(res.Status)))
		}
		fmt.Fprintln(w, output.ColorPrinter(r.Name, "unset"))
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
	Checks  []xmlCheck `xml:"checks>check"`
}

func writeXML(w io.Writer, reports []FileReport, fields []Field) {
	root := struct {
		XMLName xml.Name    `xml:"checksec"`
		Files   []xmlReport `xml:"file"`
	}{}
	for _, r := range reports {
		xr := xmlReport{Name: r.Name}
		for _, f := range fields {
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
