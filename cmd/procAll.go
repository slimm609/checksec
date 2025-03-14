package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
			// skip checksec
			if proc == int32(os.Getpid()) {
				continue
			}
			filePath := filepath.Join("/proc", fmt.Sprint(proc), "exe")
			file, err := os.Readlink(filePath)
			file = strings.Split(file, " ")[0]
			if err != nil {
				continue
			}
			data, color := utils.RunFileChecks(file, libc)
			Elements = append(Elements, data...)
			ElementColors = append(ElementColors, color...)
		}
		utils.FilePrinter(outputFormat, Elements, ElementColors)
	},
}

func init() {
	rootCmd.AddCommand(procAllCmd)
}
