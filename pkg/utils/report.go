package utils

import (
	"debug/elf"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// FileReport is the complete check output for one binary. It is the wire
// format for JSON/YAML directly and the source for table/XML rendering.
type FileReport struct {
	Name   string                     `json:"name"   yaml:"name"`
	Checks map[string]checksec.Result `json:"checks" yaml:"checks"`
}

// scanContext holds per-binary state shared across check thunks so the ELF is
// opened once and expensive results (fortify) are computed once.
type scanContext struct {
	path string
	elf  *elf.File
	libc string

	fortifyOnce bool
	fortifyRes  checksec.Result // summary (Yes/No/N-A)
	fortified   checksec.Result // count of fortified calls
	fortifiable checksec.Result // count of fortifiable calls
}

func newScanContext(path, libc string) *scanContext {
	c := &scanContext{path: path, libc: libc}
	if f, err := elf.Open(path); err == nil {
		c.elf = f
	}
	return c
}

func (c *scanContext) Close() {
	if c.elf != nil {
		_ = c.elf.Close()
	}
}

// fortify runs the fortify check once and caches the three derived columns.
func (c *scanContext) fortify() {
	if c.fortifyOnce {
		return
	}
	c.fortifyOnce = true
	r, err := checksec.Fortify(c.path, c.elf, c.libc)
	if err != nil || r == nil {
		c.fortifyRes = checksec.Err("Fortify")
		c.fortified = checksec.Result{Value: "N/A", Status: checksec.StatusInfo}
		c.fortifiable = checksec.Result{Value: "N/A", Status: checksec.StatusInfo}
		return
	}
	c.fortifyRes = checksec.Result{Value: r.Output, Status: checksec.Status(r.Color)}
	c.fortified = checksec.Result{Value: r.Fortified, Status: checksec.StatusInfo}
	c.fortifiable = checksec.Result{Value: r.Fortifiable, Status: checksec.StatusInfo}
}

// Field is one column in the file report. The fileFields slice is the single
// source of truth: its order is the table-column / XML-element order, and its
// keys are the JSON/YAML map keys. Adding a check means appending one Field.
type Field struct {
	Key    string
	Header string
	Run    func(*scanContext) checksec.Result
}

// run wraps a (path → *Result, error) check into a registry thunk that yields
// a value-typed Result, mapping errors to checksec.Err.
func run(key string, fn func(string) (*checksec.Result, error)) func(*scanContext) checksec.Result {
	return func(c *scanContext) checksec.Result {
		r, err := fn(c.path)
		if err != nil || r == nil {
			return checksec.Err(key)
		}
		return *r
	}
}

var fileFields = []Field{
	{"relro", "RELRO", run("RELRO", checksec.RELRO)},
	{"canary", "Stack Canary", run("canary", checksec.Canary)},
	{"cfi", "CFI", run("CFI", checksec.Cfi)},
	{"nx", "NX", func(c *scanContext) checksec.Result {
		if c.elf == nil {
			return checksec.Err("NX")
		}
		return *checksec.NX(c.path, c.elf)
	}},
	{"pie", "PIE", func(c *scanContext) checksec.Result {
		if c.elf == nil {
			return checksec.Err("PIE")
		}
		return *checksec.PIE(c.path, c.elf)
	}},
	{"rpath", "RPATH", run("RPATH", checksec.RPATH)},
	{"runpath", "RUNPATH", run("RUNPATH", checksec.RUNPATH)},
	{"symbols", "Symbols", run("SYMBOLS", checksec.SYMBOLS)},
	{"safestack", "SafeStack", run("SafeStack", checksec.SafeStack)},
	{"fortify_source", "FORTIFY", func(c *scanContext) checksec.Result {
		c.fortify()
		return c.fortifyRes
	}},
	{"fortified", "Fortified", func(c *scanContext) checksec.Result {
		c.fortify()
		return c.fortified
	}},
	{"fortifyable", "Fortifiable", func(c *scanContext) checksec.Result {
		c.fortify()
		return c.fortifiable
	}},
}

// RunFileChecks runs every registered check against filename and returns a
// fully-populated FileReport. Every key in fileFields is guaranteed present
// in the result, even on error paths.
func RunFileChecks(filename, libc string) FileReport {
	ctx := newScanContext(filename, libc)
	defer ctx.Close()

	report := FileReport{
		Name:   filename,
		Checks: make(map[string]checksec.Result, len(fileFields)),
	}
	for _, f := range fileFields {
		report.Checks[f.Key] = f.Run(ctx)
	}
	return report
}
