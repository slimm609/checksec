package checksec

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"
)

// runpathRisk is the per-entry classification for an RPATH/RUNPATH directory.
type runpathRisk int

const (
	rpSafe     runpathRisk = iota // absolute, exists, not world-writable
	rpWarn                        // $ORIGIN-relative or nonexistent (depends on deploy context)
	rpInsecure                    // relative path / empty (cwd) / world-writable
)

// classifyRunpathEntry classifies one RPATH/RUNPATH entry. The actual security
// signal is whether an attacker can control where libraries load from — a
// relative path, an empty entry (== cwd), or a world-writable directory all
// allow that. $ORIGIN is context-dependent (safe for setuid-stripped binaries
// in trusted dirs, risky otherwise) so it's a warning.
func classifyRunpathEntry(entry string) (runpathRisk, string) {
	if entry == "" {
		return rpInsecure, "empty (cwd)"
	}
	if strings.Contains(entry, "$ORIGIN") || strings.Contains(entry, "${ORIGIN}") {
		return rpWarn, "$ORIGIN"
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

// summarizeRunpath collapses zero or more colon-separated DT_RPATH/DT_RUNPATH
// strings into a single Result. The worst entry's risk determines Status; the
// Value carries the joined path string and the worst reason.
func summarizeRunpath(label string, paths []string) Result {
	if len(paths) == 0 {
		return Result{Value: "No " + label, Status: StatusGood}
	}
	worst := rpSafe
	worstReason := ""
	var all []string
	for _, p := range paths {
		for _, entry := range strings.Split(p, ":") {
			all = append(all, entry)
			risk, reason := classifyRunpathEntry(entry)
			if risk > worst {
				worst, worstReason = risk, reason
			}
		}
	}
	joined := strings.Join(all, ":")
	switch worst {
	case rpInsecure:
		return Result{Value: fmt.Sprintf("%s [%s] (%s)", label, joined, worstReason), Status: StatusBad}
	case rpWarn:
		return Result{Value: fmt.Sprintf("%s [%s] (%s)", label, joined, worstReason), Status: StatusWarn}
	default:
		return Result{Value: fmt.Sprintf("%s [%s]", label, joined), Status: StatusInfo}
	}
}

func RPATH(file *elf.File) *Result {
	paths, _ := file.DynString(elf.DT_RPATH)
	r := summarizeRunpath("RPATH", paths)
	return &r
}
