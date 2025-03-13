package utils

import (
	"reflect"

	"github.com/slimm609/checksec/pkg/checksec"
)

// RunFileChecks - Run the file checks
func RunFileChecks(filename string, libc string) ([]interface{}, []interface{}) {

	binary := GetBinary(filename)
	relro := checksec.RELRO(filename)
	canary := checksec.Canary(filename)
	nx := checksec.NX(filename, binary)
	pie := checksec.PIE(filename, binary)
	rpath := checksec.RPATH(filename)
	runpath := checksec.RUNPATH(filename)
	symbols := checksec.SYMBOLS(filename)
	fortify := checksec.Fortify(filename, binary, libc)

	data := []interface{}{
		map[string]interface{}{
			"name": filename,
			"checks": map[string]interface{}{
				"relro":          relro.Output,
				"canary":         canary.Output,
				"nx":             nx.Output,
				"pie":            pie.Output,
				"rpath":          rpath.Output,
				"runpath":        runpath.Output,
				"symbols":        symbols.Output,
				"fortify_source": fortify.Output,
				"fortified":      fortify.Fortified,
				"fortifyable":    fortify.Fortifiable,
			},
		},
	}

	color := []interface{}{
		map[string]interface{}{
			"name": filename,
			"checks": map[string]interface{}{
				"canary":              canary.Output,
				"canaryColor":         canary.Color,
				"fortified":           fortify.Fortified,
				"fortifiedColor":      "unset",
				"fortifyable":         fortify.Fortifiable,
				"fortifyableColor":    "unset",
				"fortify_source":      fortify.Output,
				"fortify_sourceColor": fortify.Color,
				"nx":                  nx.Output,
				"nxColor":             nx.Color,
				"pie":                 pie.Output,
				"pieColor":            pie.Color,
				"relro":               relro.Output,
				"relroColor":          relro.Color,
				"rpath":               rpath.Output,
				"rpathColor":          rpath.Color,
				"runpath":             runpath.Output,
				"runpathColor":        runpath.Color,
				"symbols":             symbols.Output,
				"symbolsColor":        symbols.Color,
			},
		},
	}

	return data, color
}

// ParseKernel - Parses the kernel config and runs the checks
func ParseKernel(filename string) (any, any) {

	kernelCheckResults, kernelCheckResultsColors := checksec.KernelConfig(filename)
	sysctlCheckResults, sysctlCheckResultsColors := checksec.SysctlCheck()

	data := reflect.AppendSlice(reflect.ValueOf(kernelCheckResults), reflect.ValueOf(sysctlCheckResults)).Interface()
	dataColors := reflect.AppendSlice(reflect.ValueOf(kernelCheckResultsColors), reflect.ValueOf(sysctlCheckResultsColors)).Interface()

	return data, dataColors

}
