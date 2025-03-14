package cmd

import (
	"github.com/slimm609/checksec/pkg/utils"

	"github.com/spf13/cobra"
)

// fileCmd represents the file command
var fileCmd = &cobra.Command{
	Use:   "file",
	Short: "Check a single binary file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		file := args[0]

		utils.CheckElfExists(file)
		data, color := utils.RunFileChecks(file, libc)
		utils.FilePrinter(outputFormat, data, color)
	},
}

func init() {
	rootCmd.AddCommand(fileCmd)
}
