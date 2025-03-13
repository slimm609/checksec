package cmd

import (
	"fmt"
	"os"

	"github.com/slimm609/checksec/pkg/checksec"
	"github.com/slimm609/checksec/pkg/utils"

	"github.com/spf13/cobra"
)

// fortifyFileCmd represents the fortifyFile command
var fortifyFileCmd = &cobra.Command{
	Use:   "fortifyFile",
	Short: "Check Fortify for binary file",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fmt.Printf("Error: no filename provided")
			os.Exit(1)
		}
		file := args[0]

		utils.CheckElfExists(file)
		binary := utils.GetBinary(file)
		fortify := checksec.Fortify(file, binary, libc)
		output := []interface{}{
			map[string]interface{}{
				"name": file,
				"checks": map[string]interface{}{
					"fortify_source": fortify.Output,
					"fortified":      fortify.Fortified,
					"fortifyable":    fortify.Fortifiable,
					"noFortify":      fortify.NoFortify,
					"libcSupport":    fortify.LibcSupport,
					"numLibcFunc":    fortify.NumLibcFunc,
					"numFileFunc":    fortify.NumFileFunc,
				},
			},
		}
		color := []interface{}{
			map[string]interface{}{
				"name": file,
				"checks": map[string]interface{}{
					"fortified":           fortify.Fortified,
					"fortifiedColor":      "unset",
					"noFortify":           fortify.NoFortify,
					"fortifyable":         fortify.Fortifiable,
					"fortifyableColor":    "unset",
					"fortify_source":      fortify.Output,
					"fortify_sourceColor": fortify.Color,
					"libcSupport":         fortify.LibcSupport,
					"libcSupportColor":    fortify.LibcSupportColor,
					"numLibcFunc":         fortify.NumLibcFunc,
					"numFileFunc":         fortify.NumFileFunc,
				},
			},
		}
		utils.FortifyPrinter(outputFormat, output, color)
	},
}

func init() {
	rootCmd.AddCommand(fortifyFileCmd)
}
