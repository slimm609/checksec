package cmd

import (
	"fmt"
	"os"

	"github.com/slimm609/checksec/v3/pkg/output"
	"github.com/slimm609/checksec/v3/pkg/utils"
)

// applyFailIf evaluates the global --fail-if gate against reports and, if any
// required check is not StatusGood, prints the failures to stderr and exits 1.
func applyFailIf(reports []utils.FileReport) {
	keys := utils.ParseFailIfKeys(failIf)
	if len(keys) == 0 {
		return
	}
	fails, err := utils.EvaluateFailIf(reports, keys)
	if err != nil {
		output.Fatalf("%v", err)
	}
	if len(fails) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\nchecksec: --fail-if gate failed (%d violation(s)):\n", len(fails))
	for _, f := range fails {
		fmt.Fprintf(os.Stderr, "  %s: %s = %q (%s)\n", f.File, f.Key, f.Result.Value, f.Result.Status)
	}
	os.Exit(1)
}
