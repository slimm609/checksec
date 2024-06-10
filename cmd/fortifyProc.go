package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// fortifyProcCmd represents the fortifyProc command
var fortifyProcCmd = &cobra.Command{
	Use:   "fortifyProc",
	Short: "Check Fortify for running process",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("fortifyProc called")
	},
}

func init() {
	rootCmd.AddCommand(fortifyProcCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// fortifyProcCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// fortifyProcCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
