package cmd

import (
	"github.com/slimm609/checksec/pkg/utils"

	"github.com/spf13/cobra"
)

// dirCmd represents the dir command
var dirCmd = &cobra.Command{
	Use:   "dir",
	Short: "check all files in a directory",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dir := args[0]
		recursive, _ := cmd.Flags().GetBool("recursive")
		utils.CheckDirExists(dir)
		var Elements []interface{}
		var ElementColors []interface{}
		for _, file := range utils.GetAllFilesFromDir(dir, recursive) {
			data, color := utils.RunFileChecks(file, libc)
			Elements = append(Elements, data...)
			ElementColors = append(ElementColors, color...)
		}
		utils.FilePrinter(outputFormat, Elements, ElementColors)

	},
}

func init() {
	rootCmd.AddCommand(dirCmd)
	dirCmd.Flags().BoolP("recursive", "r", false, "Enable recursive through the directories")
}
