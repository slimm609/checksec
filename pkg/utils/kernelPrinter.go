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

// KernelPrinter renders kernel checks in the requested format. All formats
// encode []checksec.KernelCheck directly — no map→JSON→struct round-trip.
func KernelPrinter(w io.Writer, format string, checks []checksec.KernelCheck, opts PrintOptions) {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(checks)
	case "yaml":
		b, err := yaml.Marshal(checks)
		if err != nil {
			fmt.Fprintf(w, "err: %v\n", err)
			return
		}
		_, _ = w.Write(b)
	case "xml":
		root := struct {
			XMLName xml.Name               `xml:"checksec"`
			Checks  []checksec.KernelCheck `xml:"check"`
		}{Checks: checks}
		b, err := xml.MarshalIndent(root, "", "  ")
		if err != nil {
			fmt.Fprintf(w, "err: %v\n", err)
			return
		}
		_, _ = w.Write(b)
		fmt.Fprintln(w)
	case "csv":
		cw := csv.NewWriter(w)
		if !opts.NoHeader {
			row := make([]string, len(kernelColumns))
			for i, col := range kernelColumns {
				row[i] = col.header
			}
			_ = cw.Write(row)
		}
		for _, c := range checks {
			row := make([]string, len(kernelColumns))
			for i, col := range kernelColumns {
				row[i], _ = col.cell(c)
			}
			_ = cw.Write(row)
		}
		cw.Flush()
	default:
		writeKernelTable(w, checks, opts)
	}
}

// kernelColumns defines the table layout. Order here is column order.
type kernelColumn struct {
	header string
	cell   func(checksec.KernelCheck) (string, checksec.Status)
}

var kernelColumns = []kernelColumn{
	{"Description", func(c checksec.KernelCheck) (string, checksec.Status) { return c.Desc, checksec.StatusInfo }},
	{"Value", func(c checksec.KernelCheck) (string, checksec.Status) { return c.Result.Value, c.Result.Status }},
	{"Check Type", func(c checksec.KernelCheck) (string, checksec.Status) { return c.Type, checksec.StatusInfo }},
	{"Config Key", func(c checksec.KernelCheck) (string, checksec.Status) { return c.Name, checksec.StatusInfo }},
}

func writeKernelTable(w io.Writer, checks []checksec.KernelCheck, opts PrintOptions) {
	output.PrintLogo(opts.NoBanner)

	widths := make([]int, len(kernelColumns))
	for i, col := range kernelColumns {
		widths[i] = len(col.header)
		for _, c := range checks {
			v, _ := col.cell(c)
			if len(v) > widths[i] {
				widths[i] = len(v)
			}
		}
	}
	pad := func(s string, width int) string { return fmt.Sprintf("%-*s", width+2, s) }

	if !opts.NoHeader {
		fmt.Fprintln(w, "Kernel configs only print what is supported by the specific kernel/kernel config")
		for i, col := range kernelColumns {
			fmt.Fprint(w, output.ColorPrinter(pad(col.header, widths[i]), "unset"))
		}
		fmt.Fprintln(w)
	}
	for _, c := range checks {
		for i, col := range kernelColumns {
			v, s := col.cell(c)
			fmt.Fprint(w, output.ColorPrinter(pad(v, widths[i]), string(s)))
		}
		fmt.Fprintln(w)
	}
}
