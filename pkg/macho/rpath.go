// pkg/macho/rpath.go
package macho

import (
	dm "debug/macho"
	"fmt"
	"os"
	"strings"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

type rpathRisk int

const (
	rpSafe rpathRisk = iota
	rpWarn
	rpInsecure
)

// classifyRpathEntry mirrors the ELF classifier. @executable_path, @loader_path
// and @rpath are context-dependent like $ORIGIN. A bare relative path, an empty
// entry, or a world-writable directory lets an attacker choose the library.
func classifyRpathEntry(entry string) (rpathRisk, string) {
	if entry == "" {
		return rpInsecure, "empty"
	}
	if strings.HasPrefix(entry, "@") {
		return rpWarn, "@-relative"
	}
	if !strings.HasPrefix(entry, "/") {
		return rpInsecure, "relative"
	}
	fi, err := os.Stat(entry)
	if err != nil {
		return rpWarn, "nonexistent"
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return rpInsecure, "world-writable"
	}
	return rpSafe, ""
}

// summarizeRpath renders the LC_RPATH list the way the ELF check renders
// DT_RPATH: entries joined with ':' for display only; entries are never split.
func summarizeRpath(paths []string) checksec.Result {
	if len(paths) == 0 {
		return checksec.Result{Value: "No RPATH", Status: checksec.StatusGood}
	}
	worst, reason := rpSafe, ""
	for _, p := range paths {
		if r, why := classifyRpathEntry(p); r > worst {
			worst, reason = r, why
		}
	}
	joined := strings.Join(paths, ":")
	switch worst {
	case rpInsecure:
		return checksec.Result{Value: fmt.Sprintf("RPATH [%s] (%s)", joined, reason), Status: checksec.StatusBad}
	case rpWarn:
		return checksec.Result{Value: fmt.Sprintf("RPATH [%s] (%s)", joined, reason), Status: checksec.StatusWarn}
	}
	return checksec.Result{Value: fmt.Sprintf("RPATH [%s]", joined), Status: checksec.StatusInfo}
}

// RPATH classifies every LC_RPATH entry.
func RPATH(f *dm.File) *checksec.Result {
	var paths []string
	for _, l := range f.Loads {
		if rp, ok := l.(*dm.Rpath); ok {
			paths = append(paths, rp.Path)
		}
	}
	r := summarizeRpath(paths)
	return &r
}
