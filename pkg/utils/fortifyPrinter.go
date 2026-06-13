package utils

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/slimm609/checksec/v3/pkg/checksec"
	"github.com/slimm609/checksec/v3/pkg/output"
	"sigs.k8s.io/yaml"
)

// FortifyReport is the detailed FORTIFY_SOURCE breakdown for one binary. It is
// the wire format for JSON/YAML/XML directly and the source for table output.
type FortifyReport struct {
	Name          string          `json:"name"           xml:"name,attr"`
	FortifySource checksec.Result `json:"fortify_source" xml:"fortify_source"`
	LibcSupport   checksec.Result `json:"libcSupport"    xml:"libcSupport"`
	Fortified     string          `json:"fortified"      xml:"fortified"`
	Fortifiable   string          `json:"fortifyable"    xml:"fortifyable"`
	NoFortify     string          `json:"noFortify"      xml:"noFortify"`
	NumLibcFunc   string          `json:"numLibcFunc"    xml:"numLibcFunc"`
	NumFileFunc   string          `json:"numFileFunc"    xml:"numFileFunc"`
}

// RunFortifyCheck runs the detailed fortify analysis and adapts it into the
// typed FortifyReport. On error every field is still populated so all output
// formats stay aligned.
func RunFortifyCheck(file, libc string) FortifyReport {
	ctx := newScanContext(file, libc)
	defer ctx.Close()
	if ctx.elf == nil {
		return fortifyErrReport(file)
	}
	r, err := checksec.Fortify(file, ctx.elf, libc)
	if err != nil || r == nil {
		return fortifyErrReport(file)
	}
	return FortifyReport{
		Name:          file,
		FortifySource: checksec.Result{Value: r.Output, Status: checksec.Status(r.Color)},
		LibcSupport:   checksec.Result{Value: r.LibcSupport, Status: checksec.Status(r.LibcSupportColor)},
		Fortified:     r.Fortified,
		Fortifiable:   r.Fortifiable,
		NoFortify:     r.NoFortify,
		NumLibcFunc:   r.NumLibcFunc,
		NumFileFunc:   r.NumFileFunc,
	}
}

func fortifyErrReport(file string) FortifyReport {
	return FortifyReport{
		Name:          file,
		FortifySource: checksec.Err("Fortify"),
		LibcSupport:   checksec.Result{Value: "N/A", Status: checksec.StatusInfo},
		Fortified:     "N/A", Fortifiable: "N/A", NoFortify: "N/A",
		NumLibcFunc: "N/A", NumFileFunc: "N/A",
	}
}

// FortifyPrinter renders a FortifyReport in the requested format.
func FortifyPrinter(w io.Writer, format string, r FortifyReport, opts PrintOptions) {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	case "yaml":
		b, err := yaml.Marshal(r)
		if err != nil {
			fmt.Fprintf(w, "err: %v\n", err)
			return
		}
		_, _ = w.Write(b)
	case "xml":
		root := struct {
			XMLName xml.Name `xml:"fortify"`
			FortifyReport
		}{FortifyReport: r}
		b, err := xml.MarshalIndent(root, "", "  ")
		if err != nil {
			fmt.Fprintf(w, "err: %v\n", err)
			return
		}
		_, _ = w.Write(b)
		fmt.Fprintln(w)
	default:
		writeFortifyTable(w, r, opts)
	}
}

func writeFortifyTable(w io.Writer, r FortifyReport, opts PrintOptions) {
	output.PrintLogo(opts.NoBanner)
	fmt.Fprintf(w, "* File: %s\n", output.ColorPrinter(r.Name, "unset"))
	fmt.Fprintf(w, "* FORTIFY_SOURCE support available (libc): %s\n",
		output.ColorPrinter(r.LibcSupport.Value, string(r.LibcSupport.Status)))
	fmt.Fprintf(w, "* Binary compiled with FORTIFY_SOURCE support: %s\n\n",
		output.ColorPrinter(r.FortifySource.Value, string(r.FortifySource.Status)))
	fmt.Fprintln(w, "------ EXECUTABLE-FILE ------- | -------- LIBC --------")
	fmt.Fprintln(w, "Fortifiable library functions  | Checked function names")
	// TODO: add function breakdown
	fmt.Fprintln(w, "Coming Soon")
	fmt.Fprintf(w, "\n%s\n", output.ColorPrinter("SUMMARY", "green"))
	fmt.Fprintf(w, "* Number of checked functions in libc                : %s\n", output.ColorPrinter(r.NumLibcFunc, "unset"))
	fmt.Fprintf(w, "* Total number of library functions in the executable: %s\n", output.ColorPrinter(r.NumFileFunc, "unset"))
	fmt.Fprintf(w, "* Number of Fortifiable functions in the executable  : %s\n", output.ColorPrinter(r.Fortifiable, "unset"))
	fmt.Fprintf(w, "* Number of checked functions in the executable      : %s\n", output.ColorPrinter(r.Fortified, "green"))
	fmt.Fprintf(w, "* Number of unchecked functions in the executable    : %s\n", output.ColorPrinter(r.NoFortify, "red"))
}
