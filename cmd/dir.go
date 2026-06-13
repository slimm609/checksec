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
		paths := utils.GetAllFilesFromDir(dir, recursive)
		reports := utils.RunListChecksParallel(paths, libc, 0)
		utils.FilePrinter(cmd.OutOrStdout(), outputFormat, reports, utils.PrintOptions{NoBanner: noBanner, NoHeader: noHeader})
		applyFailIf(reports)
	},
}

func init() {
	rootCmd.AddCommand(dirCmd)
	dirCmd.Flags().BoolP("recursive", "r", false, "Enable recursive through the directories")
}
