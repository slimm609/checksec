package cmd

import (
	"github.com/slimm609/checksec/v3/pkg/utils"

	"github.com/spf13/cobra"
)

// dirCmd represents the dir command
var dirCmd = &cobra.Command{
	Use:   "dir <directory>",
	Short: "check all files in a directory",
	Args:  cobra.ExactArgs(1),
	Example: `
  checksec dir /usr/bin/
  checksec dir /usr/bin/ --recursive`,
	Run: func(cmd *cobra.Command, args []string) {
		dir := args[0]
		recursive, _ := cmd.Flags().GetBool("recursive")
		utils.CheckDirExists(dir)
		var reports []utils.FileReport
		for _, file := range utils.GetAllFilesFromDir(dir, recursive) {
			reports = append(reports, utils.RunFileChecks(file, libc))
		}
		utils.FilePrinter(cmd.OutOrStdout(), outputFormat, reports, utils.PrintOptions{NoBanner: noBanner, NoHeader: noHeader})
	},
}

func init() {
	rootCmd.AddCommand(dirCmd)
	dirCmd.Flags().BoolP("recursive", "r", false, "Enable recursive through the directories")
}
