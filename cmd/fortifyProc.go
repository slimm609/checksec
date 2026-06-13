package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/slimm609/checksec/v3/pkg/utils"

	"github.com/spf13/cobra"
)

// fortifyProcCmd represents the fortifyProc command
var fortifyProcCmd = &cobra.Command{
	Use:   "fortifyProc",
	Short: "Check Fortify for running process",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		proc := args[0]

		filePath := filepath.Join("/proc", proc, "exe")
		file := filePath
		if target, err := os.Readlink(filePath); err == nil {
			file = target
			if _, statErr := os.Stat(file); statErr != nil {
				file = filePath
			}
		} else {
			fmt.Fprintf(os.Stderr, "Error: Pid %s not found/no access\n", proc)
			os.Exit(1)
		}

		utils.CheckElfExists(file)
		report := utils.RunFortifyCheck(file, libc)
		utils.FortifyPrinter(cmd.OutOrStdout(), outputFormat, report, utils.PrintOptions{NoBanner: noBanner, NoHeader: noHeader})
	},
}

func init() {
	rootCmd.AddCommand(fortifyProcCmd)
}
