// pkg/utils/report.go
package utils

import (
	"debug/elf"
	dm "debug/macho"
	"fmt"
	"os"

	"github.com/slimm609/checksec/v3/pkg/checksec"
	"github.com/slimm609/checksec/v3/pkg/exploit"
	"github.com/slimm609/checksec/v3/pkg/target"
)

// FileReport is the complete check output for one image. It is the wire
// format for JSON/YAML directly and the source for table/XML rendering.
// Format selects the field registry used to render it; Arch is set for Mach-O
// and is part of Name for fat slices ("<path> [<arch>]").
type FileReport struct {
	Name           string                     `json:"name"   yaml:"name"`
	Format         string                     `json:"format" yaml:"format"`
	Arch           string                     `json:"arch,omitempty" yaml:"arch,omitempty"`
	Checks         map[string]checksec.Result `json:"checks" yaml:"checks"`
	Exploitability *exploit.Report            `json:"exploitability,omitempty" yaml:"exploitability,omitempty"`
}

// scanOptions holds the optional analysis passes RunFileChecks may run on top
// of the base checks.
type scanOptions struct {
	exploit bool
}

// Option configures an optional analysis pass on top of the base checks.
type Option func(*scanOptions)

// WithExploit enables the exploitability reasoning pass (ELF only). Chain
// synthesis is a render-time concern driven by PrintOptions.Chain.
func WithExploit() Option {
	return func(o *scanOptions) { o.exploit = true }
}

// scanContext holds per-image state shared across check thunks. The file is
// opened exactly once by target.Open; every check reads from the parsed view
// or the shared descriptor and never re-opens by path.
type scanContext struct {
	path   string
	target *target.Target
	libc   string

	fortifyOnce bool
	fortifyRes  checksec.Result
	fortified   checksec.Result
	fortifiable checksec.Result
}

func (c *scanContext) elf() *elf.File {
	if c.target == nil {
		return nil
	}
	return c.target.ELF
}

func (c *scanContext) macho() *dm.File {
	if c.target == nil {
		return nil
	}
	return c.target.MachO
}

func (c *scanContext) raw() *os.File {
	if c.target == nil {
		return nil
	}
	return c.target.Raw
}

func (c *scanContext) format() target.Format {
	if c.target == nil {
		return target.Unknown
	}
	return c.target.Format
}

// openTarget is the single point where the scan target is opened. One context
// per image: a fat Mach-O returns one per slice. Indirection for testability.
var openTarget = func(path string) ([]*scanContext, error) {
	targets, err := target.Open(path)
	if err != nil {
		return nil, err
	}
	ctxs := make([]*scanContext, len(targets))
	for i, t := range targets {
		ctxs[i] = &scanContext{path: path, target: t}
	}
	return ctxs, nil
}

func (c *scanContext) Close() {
	if c.target != nil {
		c.target.Close()
	}
}

// fortify runs the ELF fortify check once and caches the three derived columns.
func (c *scanContext) fortify() {
	if c.fortifyOnce {
		return
	}
	c.fortifyOnce = true
	ef := c.elf()
	if ef == nil {
		c.fortifyRes = checksec.Err("Fortify")
		c.fortified = checksec.Result{Value: "N/A", Status: checksec.StatusInfo}
		c.fortifiable = checksec.Result{Value: "N/A", Status: checksec.StatusInfo}
		return
	}
	r, err := checksec.Fortify(c.path, ef, c.libc)
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

// Field is one column in a file report. Each format has its own registry; the
// slice order is the table-column / XML-element order and the keys are the
// JSON/YAML map keys. Adding a check means appending one Field.
type Field struct {
	Key    string
	Header string
	Run    func(*scanContext) checksec.Result
}

// run wraps an (*elf.File -> *Result) check into a registry thunk.
func run(key string, fn func(*elf.File) *checksec.Result) func(*scanContext) checksec.Result {
	return func(c *scanContext) checksec.Result {
		ef := c.elf()
		if ef == nil {
			return checksec.Err(key)
		}
		return *fn(ef)
	}
}

// runRaw wraps an (*elf.File, *os.File -> *Result) check.
func runRaw(key string, fn func(*elf.File, *os.File) *checksec.Result) func(*scanContext) checksec.Result {
	return func(c *scanContext) checksec.Result {
		ef := c.elf()
		if ef == nil {
			return checksec.Err(key)
		}
		return *fn(ef, c.raw())
	}
}

// runMachO wraps a (*macho.File -> *Result) check into a registry thunk.
func runMachO(key string, fn func(*dm.File) *checksec.Result) func(*scanContext) checksec.Result {
	return func(c *scanContext) checksec.Result {
		mf := c.macho()
		if mf == nil {
			return checksec.Err(key)
		}
		return *fn(mf)
	}
}

// ELFFields is the ELF check registry.
var ELFFields = []Field{
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

// FileFields is the historical name of the ELF registry, kept for callers.
var FileFields = ELFFields

// MachOFields is the Mach-O check registry (populated in machofields.go).
var MachOFields []Field

// FieldsFor returns the registry for a format. Unknown and legacy reports
// with an empty Format render with the ELF registry.
func FieldsFor(f target.Format) []Field {
	if f == target.MachO {
		return MachOFields
	}
	return ELFFields
}

// AllFields is the union of every registry, ELF first, deduped by key.
func AllFields() []Field {
	seen := make(map[string]bool, len(ELFFields)+len(MachOFields))
	out := make([]Field, 0, len(ELFFields)+len(MachOFields))
	for _, reg := range [][]Field{ELFFields, MachOFields} {
		for _, f := range reg {
			if !seen[f.Key] {
				seen[f.Key] = true
				out = append(out, f)
			}
		}
	}
	return out
}

// ProcFields extends ELFFields with the per-process Seccomp column.
var ProcFields = append(append([]Field{}, ELFFields...), Field{Key: "seccomp", Header: "Seccomp"})

// RunProcChecks runs the file checks on the process's executable and enriches
// the report with the per-PID seccomp mode.
func RunProcChecks(pid int, exePath, libc string) FileReport {
	report := RunFileChecks(exePath, libc)
	report.Checks["seccomp"] = checksec.Seccomp(pid)
	return report
}

// runChecks evaluates the registry for the context's format into a report.
func runChecks(ctx *scanContext, o scanOptions) FileReport {
	fields := FieldsFor(ctx.format())
	name := ctx.path
	arch := ""
	if ctx.target != nil {
		arch = ctx.target.Arch
		if ctx.target.Fat {
			name = fmt.Sprintf("%s [%s]", ctx.path, arch)
		}
	}
	report := FileReport{
		Name:   name,
		Format: string(ctx.format()),
		Arch:   arch,
		Checks: make(map[string]checksec.Result, len(fields)),
	}
	for _, f := range fields {
		report.Checks[f.Key] = f.Run(ctx)
	}
	if o.exploit && ctx.format() == target.ELF && ctx.elf() != nil {
		r := exploit.Assess(ctx.elf(), report.Checks)
		report.Exploitability = &r
	}
	return report
}

// RunPathChecks opens filename once and returns one FileReport per image:
// one for a thin file, one per slice for a fat Mach-O. Every key of the
// chosen registry is present in each report, even on error paths.
func RunPathChecks(filename, libc string, opts ...Option) []FileReport {
	var o scanOptions
	for _, fn := range opts {
		fn(&o)
	}
	ctxs, err := openTarget(filename)
	if err != nil || len(ctxs) == 0 {
		return []FileReport{runChecks(&scanContext{path: filename, libc: libc}, o)}
	}
	defer ctxs[0].Close()
	reports := make([]FileReport, 0, len(ctxs))
	for _, ctx := range ctxs {
		ctx.libc = libc
		reports = append(reports, runChecks(ctx, o))
	}
	return reports
}

// RunFileChecks returns the first report for filename. Callers that may see
// fat Mach-O files should use RunPathChecks.
func RunFileChecks(filename, libc string, opts ...Option) FileReport {
	return RunPathChecks(filename, libc, opts...)[0]
}
