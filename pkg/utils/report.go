package utils

import (
	"debug/elf"
	"fmt"
	"os"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// FileReport is the complete check output for one binary. It is the wire
// format for JSON/YAML directly and the source for table/XML rendering.
type FileReport struct {
	Name   string                     `json:"name"   yaml:"name"`
	Checks map[string]checksec.Result `json:"checks" yaml:"checks"`
}

// scanContext holds per-binary state shared across check thunks. The target is
// opened exactly once (raw + parsed view) and every check reads from these
// handles — no check re-opens by path.
type scanContext struct {
	path string
	raw  *os.File  // underlying descriptor (for FunctionsFromSymbolTable)
	elf  *elf.File // parsed view of raw
	libc string

	fortifyOnce bool
	fortifyRes  checksec.Result // summary (Yes/No/N-A)
	fortified   checksec.Result // count of fortified calls
	fortifiable checksec.Result // count of fortifiable calls
}

// openTarget is the single point where the scan target is opened. Indirection
// for testability (open-count assertion, post-open unlink).
var openTarget = func(path string) (*scanContext, error) {
	raw, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", path, err)
	}
	ef, err := elf.NewFile(raw)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("not an ELF file %s: %w", path, err)
	}
	return &scanContext{path: path, raw: raw, elf: ef}, nil
}

func newScanContext(path, libc string) *scanContext {
	c, err := openTarget(path)
	if err != nil {
		// Return a context with nil handles; every thunk will yield Err().
		return &scanContext{path: path, libc: libc}
	}
	c.libc = libc
	return c
}

func (c *scanContext) Close() {
	if c.raw != nil {
		_ = c.raw.Close()
	}
}

// fortify runs the fortify check once and caches the three derived columns.
// Fortify still needs the path (for libc auto-resolution via ldd) but reuses
// the already-open ELF for the target's own symbol scan.
func (c *scanContext) fortify() {
	if c.fortifyOnce {
		return
	}
	c.fortifyOnce = true
	if c.elf == nil {
		c.fortifyRes = checksec.Err("Fortify")
		c.fortified = checksec.Result{Value: "N/A", Status: checksec.StatusInfo}
		c.fortifiable = checksec.Result{Value: "N/A", Status: checksec.StatusInfo}
		return
	}
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

// Field is one column in the file report. The FileFields slice is the single
// source of truth: its order is the table-column / XML-element order, and its
// keys are the JSON/YAML map keys. Adding a check means appending one Field.
type Field struct {
	Key    string
	Header string
	Run    func(*scanContext) checksec.Result
}

// run wraps an (*elf.File → *Result) check into a registry thunk.
func run(key string, fn func(*elf.File) *checksec.Result) func(*scanContext) checksec.Result {
	return func(c *scanContext) checksec.Result {
		if c.elf == nil {
			return checksec.Err(key)
		}
		return *fn(c.elf)
	}
}

// runRaw wraps an (*elf.File, *os.File → *Result) check (for symbol-table
// fallbacks that need raw ReadAt).
func runRaw(key string, fn func(*elf.File, *os.File) *checksec.Result) func(*scanContext) checksec.Result {
	return func(c *scanContext) checksec.Result {
		if c.elf == nil {
			return checksec.Err(key)
		}
		return *fn(c.elf, c.raw)
	}
}

var FileFields = []Field{
	{"relro", "RELRO", run("RELRO", checksec.RELRO)},
	{"canary", "Stack Canary", runRaw("canary", checksec.Canary)},
	{"cfi", "CFI", run("CFI", checksec.Cfi)},
	{"nx", "NX", run("NX", checksec.NX)},
	{"pie", "PIE", run("PIE", checksec.PIE)},
	{"rpath", "RPATH", run("RPATH", checksec.RPATH)},
	{"runpath", "RUNPATH", run("RUNPATH", checksec.RUNPATH)},
	{"symbols", "Symbols", run("SYMBOLS", checksec.SYMBOLS)},
	{"safestack", "SafeStack", runRaw("SafeStack", checksec.SafeStack)},
	{"stack_clash", "Stack Clash", run("StackClash", checksec.StackClash)},
	{"separate_code", "W^X Seg", run("SeparateCode", checksec.SeparateCode)},
	{"selfrando", "Selfrando", run("Selfrando", checksec.Selfrando)},
	{"sanitizers", "Sanitizers", run("Sanitizers", checksec.Sanitizers)},
	{"fortify_level", "FORTIFY Lvl", run("FortifyLevel", checksec.FortifyLevel)},
	{"glibcxx_assert", "GLIBCXX Assert", run("GlibcxxAssertions", checksec.GlibcxxAssertions)},
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

// ProcFields extends FileFields with the per-process Seccomp column. The
// seccomp Result is populated by RunProcChecks (it's PID-derived, not
// ELF-derived, so Run is nil and RunFileChecks ignores it).
var ProcFields = append(append([]Field{}, FileFields...), Field{Key: "seccomp", Header: "Seccomp"})

// RunProcChecks runs the file checks on the process's executable and enriches
// the report with the per-PID seccomp mode.
func RunProcChecks(pid int, exePath, libc string) FileReport {
	report := RunFileChecks(exePath, libc)
	report.Checks["seccomp"] = checksec.Seccomp(pid)
	return report
}

// RunFileChecks runs every registered check against filename and returns a
// fully-populated FileReport. Every key in FileFields is guaranteed present
// in the result, even on error paths.
func RunFileChecks(filename, libc string) FileReport {
	ctx := newScanContext(filename, libc)
	defer ctx.Close()

	report := FileReport{
		Name:   filename,
		Checks: make(map[string]checksec.Result, len(FileFields)),
	}
	for _, f := range FileFields {
		report.Checks[f.Key] = f.Run(ctx)
	}
	return report
}
