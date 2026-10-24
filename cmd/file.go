package cmd

import (
	"github.com/slimm609/checksec/v3/pkg/utils"

	"github.com/spf13/cobra"
)

// fileCmd represents the file command
var fileCmd = &cobra.Command{
	Use:   "file <file>",
	Short: "Check a single binary file",
	Args:  cobra.ExactArgs(1),
	Example: `
  checksec file /usr/bin/ls
  checksec file /usr/bin/ls --no-banner`,
	Run: func(cmd *cobra.Command, args []string) {
		file := args[0]

		utils.CheckBinaryExists(file)
		var opts []utils.Option
		if exploitEnabled || chainEnabled {
			opts = append(opts, utils.WithExploit())
		}
		reports := []utils.FileReport{utils.RunFileChecks(file, libc, opts...)}
		utils.FilePrinter(cmd.OutOrStdout(), outputFormat, reports, utils.PrintOptions{NoBanner: noBanner, NoHeader: noHeader, Chain: chainEnabled, LLMNoPreamble: llmNoPreamble})
		warnExploitNonELF(reports)
		applyFailIf(reports)
	},
}

func init() {
	rootCmd.AddCommand(fileCmd)
}
