package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/slimm609/checksec/v3/pkg/utils"
	"github.com/spf13/cobra"
)

// kernelCmd represents the kernel command
var kernelCmd = &cobra.Command{
	Use:   "kernel",
	Short: "Check kernel security flags",
	Run: func(cmd *cobra.Command, args []string) {
		var configFile string
		if len(args) > 0 {
			configFile = args[0]
		} else if _, err := os.Stat("/proc/config.gz"); err == nil {
			configFile = "/proc/config.gz"
		} else {
			osReleaseFile := "/proc/sys/kernel/osrelease"
			_, err := os.Stat(osReleaseFile)
			if err != nil {
				fmt.Println("Error: could not find kernel config")
				os.Exit(1)
			}
			osReleaseVersion, err := os.ReadFile(osReleaseFile)
			if err != nil {
				fmt.Println("Error: could not find kernel config")
				os.Exit(1)
			}
			content := strings.ReplaceAll(string(osReleaseVersion), "\n", "")
			configFile = fmt.Sprintf("%s-%s", "/boot/config", content)
			_, err = os.Stat(configFile)
			if err != nil {
				fmt.Println("Error: could not find kernel config")
				os.Exit(1)
			}
		}

		utils.CheckFileExists(configFile)

		kernel, kernelColors := utils.ParseKernel(configFile)
		utils.KernelPrinter(outputFormat, kernel, kernelColors, noBanner, noHeader)
	},
}

func init() {
	rootCmd.AddCommand(kernelCmd)
}
