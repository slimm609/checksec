package cmd

import (
	"checksec/pkg/utils"

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
		} else {
			configFile = "/proc/config.gz"
		}

		utils.CheckFileExists(configFile)

		kernel, kernelColors := utils.ParseKernel(configFile)
		utils.KernelPrinter(outputFormat, kernel, kernelColors)
	},
}

func init() {
	rootCmd.AddCommand(kernelCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// kernelCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// kernelCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
