package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/slimm609/checksec/v3/pkg/utils"

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
			// skip kthreadd
			if proc == 2 {
				continue
			}
			// Check parent process ID (kthreadd has PID 2)
			if ppid, err := process.Ppid(); err == nil && ppid == 2 {
				continue
			}
			filePath := filepath.Join("/proc", fmt.Sprint(proc), "exe")

			file := filePath
			if target, err := os.Readlink(filePath); err == nil {
				file = strings.Split(target, " ")[0]
				if _, statErr := os.Stat(file); statErr != nil {
					// Fall back to /proc/<pid>/exe when target is not accessible
					file = filePath
				}
			} else {
				// If we cannot read the link, try using the symlink path
				file = filePath
			}

			// Skip non-ELF files (scripts, etc.)
			if !utils.CheckIfElf(file) {
				continue
			}

			data, color := utils.RunFileChecks(file, libc)
			Elements = append(Elements, data...)
			ElementColors = append(ElementColors, color...)
		}
		utils.FilePrinter(outputFormat, Elements, ElementColors, noBanner, noHeader)
	},
}

func init() {
	rootCmd.AddCommand(procAllCmd)
}
