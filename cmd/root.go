package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	outputFormat string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "checksec",
	Short: "A binary scanning security tool",
	Long:  `A tool used to quickly survey mitigation technologies in use by processes on a Linux system.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format (table, xml, json or yaml)")
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
