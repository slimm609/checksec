package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// procLibsCmd represents the procLibs command
var procLibsCmd = &cobra.Command{
	Use:   "procLibs",
	Short: "check process libraries",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("procLibs called")
	},
}

func init() {
	rootCmd.AddCommand(procLibsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// procLibsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// procLibsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
