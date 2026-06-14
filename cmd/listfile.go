package cmd

import (
	"io"
	"os"

	"github.com/slimm609/checksec/v3/pkg/output"
	"github.com/slimm609/checksec/v3/pkg/utils"
	"github.com/spf13/cobra"
)

// listfileCmd scans every path listed (one per line) in the given file, or
// stdin when the argument is "-". Restores the v2.x --listfile feature.
var listfileCmd = &cobra.Command{
	Use:   "listfile <path|->",
	Short: "Check every binary listed in a file (or stdin via -)",
	Args:  cobra.ExactArgs(1),
	Example: `
  checksec listfile targets.txt
  find /usr/bin -type f | checksec listfile -`,
	Run: func(cmd *cobra.Command, args []string) {
		var r io.Reader
		if args[0] == "-" {
			r = cmd.InOrStdin()
		} else {
			f, err := os.Open(args[0])
			if err != nil {
				output.Fatalf("cannot open list file: %v", err)
			}
			defer f.Close()
			r = f
		}
		paths, err := utils.ReadPathList(r)
		if err != nil {
			output.Fatalf("reading list: %v", err)
		}
		reports := utils.RunListChecksParallel(paths, libc, 0)
		utils.FilePrinter(cmd.OutOrStdout(), outputFormat, reports, utils.PrintOptions{NoBanner: noBanner, NoHeader: noHeader})
		applyFailIf(reports)
	},
}

func init() {
	rootCmd.AddCommand(listfileCmd)
}
