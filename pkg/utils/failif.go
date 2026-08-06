package utils

import (
	"fmt"
	"strings"

	"github.com/slimm609/checksec/v3/pkg/checksec"
	"github.com/slimm609/checksec/v3/pkg/exploit"
)

// exploitViableKey is the special --fail-if key that fails a report if any
// exploitability verdict reached the highest (VIABLE) tier.
const exploitViableKey = "exploit.viable"

// exploitTechniquePrefix is the prefix for the parameterized --fail-if key
// exploit.technique=<rule id>, which fails a report if it has a verdict for
// the named rule at TierRequiresLeak or above.
const exploitTechniquePrefix = "exploit.technique="

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
		if !known[k] && !isExploitPredicateKey(k) {
			return nil, fmt.Errorf("unknown --fail-if key %q (valid keys: %s)", k, strings.Join(fieldKeys(), ", "))
		}
	}
	var fails []FailIfFailure
	for _, r := range reports {
		for _, k := range required {
			if matched, isExploitKey := matchExploitPredicate(r, k); isExploitKey {
				if matched {
					fails = append(fails, FailIfFailure{
						File:   r.Name,
						Key:    k,
						Result: checksec.Result{Value: exploitPredicateDescription(k), Status: checksec.StatusBad},
					})
				}
				continue
			}
			res, ok := r.Checks[k]
			if !ok || res.Status != checksec.StatusGood {
				fails = append(fails, FailIfFailure{File: r.Name, Key: k, Result: res})
			}
		}
	}
	return fails, nil
}

// isExploitPredicateKey reports whether key is one of the special exploit.*
// --fail-if predicates rather than a plain checksec.Result key.
func isExploitPredicateKey(key string) bool {
	if key == exploitViableKey {
		return true
	}
	// A technique predicate is valid only when it names a real rule id; an empty
	// or typo'd id is rejected so it can't silently pass as a no-op CI gate.
	if id, ok := strings.CutPrefix(key, exploitTechniquePrefix); ok {
		return exploit.IsKnownRuleID(id)
	}
	return false
}

// matchExploitPredicate evaluates an exploit.* --fail-if predicate against a
// report's Exploitability data. isExploitKey is false when key is not one of
// the exploit predicates, in which case matched is meaningless and the
// caller should fall back to evaluating key against r.Checks. A nil
// Exploitability report never matches (no failure).
func matchExploitPredicate(r FileReport, key string) (matched bool, isExploitKey bool) {
	switch {
	case key == exploitViableKey:
		if r.Exploitability == nil {
			return false, true
		}
		for _, v := range r.Exploitability.Verdicts {
			if v.Tier == exploit.TierViable {
				return true, true
			}
		}
		return false, true
	case strings.HasPrefix(key, exploitTechniquePrefix):
		if r.Exploitability == nil {
			return false, true
		}
		ruleID := strings.TrimPrefix(key, exploitTechniquePrefix)
		for _, v := range r.Exploitability.Verdicts {
			if v.RuleID == ruleID && v.Tier >= exploit.TierRequiresLeak {
				return true, true
			}
		}
		return false, true
	default:
		return false, false
	}
}

// exploitPredicateDescription builds a human-readable Result.Value for a
// failing exploit.* predicate.
func exploitPredicateDescription(key string) string {
	if key == exploitViableKey {
		return "a VIABLE exploitation verdict was found"
	}
	ruleID := strings.TrimPrefix(key, exploitTechniquePrefix)
	return fmt.Sprintf("technique %q is unobstructed (tier >= REQUIRES-LEAK)", ruleID)
}

func fieldKeys() []string {
	keys := make([]string, len(ProcFields))
	for i, f := range ProcFields {
		keys[i] = f.Key
	}
	return keys
}
