package cmd

import (
	"github.com/slimm609/checksec/v3/pkg/utils"

	"github.com/spf13/cobra"
)

// fortifyFileCmd represents the fortifyFile command
var fortifyFileCmd = &cobra.Command{
	Use:   "fortifyFile",
	Short: "Check Fortify for binary file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		file := args[0]
		utils.CheckElfExists(file)
		report := utils.RunFortifyCheck(file, libc)
		utils.FortifyPrinter(cmd.OutOrStdout(), outputFormat, report, utils.PrintOptions{NoBanner: noBanner, NoHeader: noHeader})
	},
}

func init() {
	rootCmd.AddCommand(fortifyFileCmd)
}
