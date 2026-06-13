package cmd

import (
	"strconv"

	"github.com/slimm609/checksec/v3/pkg/checksec"
	"github.com/slimm609/checksec/v3/pkg/output"
	"github.com/slimm609/checksec/v3/pkg/utils"
	"github.com/spf13/cobra"
)

// procLibsCmd scans every ELF file mapped into the address space of a running
// process — the executable plus all loaded shared libraries.
var procLibsCmd = &cobra.Command{
	Use:   "procLibs <pid>",
	Short: "Check all libraries mapped into a running process",
	Args:  cobra.ExactArgs(1),
	Example: `
  checksec procLibs 1234
  checksec procLibs $$ -o json`,
	Run: func(cmd *cobra.Command, args []string) {
		pid, err := strconv.Atoi(args[0])
		if err != nil {
			output.Fatalf("invalid pid %q: %v", args[0], err)
		}
		paths, err := checksec.ProcLibs(pid)
		if err != nil {
			output.Fatalf("cannot read /proc/%d/maps: %v", pid, err)
		}
		var reports []utils.FileReport
		for _, p := range paths {
			if !utils.CheckIfElf(p) {
				continue
			}
			reports = append(reports, utils.RunFileChecks(p, libc))
		}
		utils.FilePrinter(cmd.OutOrStdout(), outputFormat, reports,
			utils.PrintOptions{NoBanner: noBanner, NoHeader: noHeader})
		applyFailIf(reports)
	},
}

func init() {
	rootCmd.AddCommand(procLibsCmd)
}
