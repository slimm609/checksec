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

			// Skip kernel threads; they do not have an exe.
			if isKthread(proc) {
				continue
			}

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

			if _, err := os.Stat(file); err != nil {
				// Cannot access exe (e.g., permission denied); skip this process
				continue
			}
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

func isKthread(pid int32) bool {
	statusPath := filepath.Join("/proc", fmt.Sprint(pid), "status")
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Kthread:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "1" {
				return true
			}
			break
		}
	}
	return false
}
