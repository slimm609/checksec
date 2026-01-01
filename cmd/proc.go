package cmd

import (
	"fmt"
	"os"

	"github.com/slimm609/checksec/v3/pkg/utils"

	"path/filepath"

	"github.com/spf13/cobra"
)

// procCmd represents the proc command
var procCmd = &cobra.Command{
	Use:   "proc",
	Short: "Check a file of a running process",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		proc := args[0]

		file, err := os.Readlink(filepath.Join("/proc", proc, "exe"))
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("Error: Pid %s not found", proc)
			} else if os.IsPermission(err) {
				fmt.Printf("Error: Permission denied to access /proc/%s/exe", proc)
			} else {
				fmt.Printf("Error: %s", err.Error())
			}
			os.Exit(1)
		}

		utils.CheckElfExists(file)
		data, color := utils.RunFileChecks(file, libc)
		utils.FilePrinter(outputFormat, data, color, noBanner, noHeader)
	},
}

func init() {
	rootCmd.AddCommand(procCmd)
}
