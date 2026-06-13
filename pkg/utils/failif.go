package utils

import (
	"fmt"
	"strings"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// FailIfFailure is one (file, check) pair that did not meet the --fail-if gate.
type FailIfFailure struct {
	File   string
	Key    string
	Result checksec.Result
}

// ParseFailIfKeys splits a comma-separated --fail-if value, trimming whitespace
// and dropping empty entries.
func ParseFailIfKeys(s string) []string {
	if s == "" {
		return nil
	}
	var keys []string
	for _, k := range strings.Split(s, ",") {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}
	return keys
}

// EvaluateFailIf returns every (file, key) where the named check's Status is
// not StatusGood. An unknown key is an error so typos don't pass silently.
func EvaluateFailIf(reports []FileReport, required []string) ([]FailIfFailure, error) {
	if len(required) == 0 {
		return nil, nil
	}
	known := make(map[string]bool, len(FileFields)+len(ProcFields))
	for _, f := range ProcFields { // ProcFields ⊇ FileFields
		known[f.Key] = true
	}
	for _, k := range required {
		if !known[k] {
			return nil, fmt.Errorf("unknown --fail-if key %q (valid keys: %s)", k, strings.Join(fieldKeys(), ", "))
		}
	}
	var fails []FailIfFailure
	for _, r := range reports {
		for _, k := range required {
			res, ok := r.Checks[k]
			if !ok || res.Status != checksec.StatusGood {
				fails = append(fails, FailIfFailure{File: r.Name, Key: k, Result: res})
			}
		}
	}
	return fails, nil
}

func fieldKeys() []string {
	keys := make([]string, len(ProcFields))
	for i, f := range ProcFields {
		keys[i] = f.Key
	}
	return keys
}
