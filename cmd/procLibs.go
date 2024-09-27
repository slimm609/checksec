package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// procLibsCmd represents the procLibs command
var procLibsCmd = &cobra.Command{
	Use:   "procLibs",
	Short: "check process libraries",
	// hide until refactored
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("procLibs called")
	},
}

func init() {
	rootCmd.AddCommand(procLibsCmd)
}
