package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/slimm609/checksec/pkg/utils"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/spf13/cobra"
)

// procAllCmd represents the procAll command
var procAllCmd = &cobra.Command{
	Use:   "procAll",
	Short: "Check all running processes",
	Run: func(cmd *cobra.Command, args []string) {

		var Elements []interface{}
		var ElementColors []interface{}
		processes, _ := process.Processes()
		for _, process := range processes {
			proc := process.Pid
			filePath := filepath.Join("/proc", fmt.Sprint(proc), "exe")
			file, err := os.Readlink(filePath)
			if err != nil {
				fmt.Printf("Error: Pid %d not found", proc)
				os.Exit(1)
			}
			data, color := utils.RunFileChecks(file)
			Elements = append(Elements, data...)
			ElementColors = append(ElementColors, color...)
		}
		utils.FilePrinter(outputFormat, Elements, ElementColors)
	},
}

func init() {
	rootCmd.AddCommand(procAllCmd)
}
