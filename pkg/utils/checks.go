package utils

import (
	"debug/elf"
	"reflect"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// Function indirections for testability
var (
	getBinaryFn = GetBinary

	relroFn = func(filename string) (result interface{}) {
		defer func() {
			if r := recover(); r != nil {
				result = &struct {
					Output string
					Color  string
				}{Output: "Error checking RELRO", Color: "red"}
			}
		}()
		return checksec.RELRO(filename)
	}
	canaryFn = func(filename string) interface{} {
		result, err := checksec.Canary(filename)
		if err != nil {
			return &checksec.CanaryResult{
				Output: "Error checking canary",
				Color:  "red",
			}
		}
		return result
	}
	cfiFn = func(filename string) interface{} {
		result, err := checksec.Cfi(filename)
		if err != nil {
			return &checksec.CfiResult{
				Output: "Error checking CFI",
				Color:  "red",
			}
		}
		return result
	}
	nxFn = func(filename string, binary interface{}) (result interface{}) {
		defer func() {
			if r := recover(); r != nil {
				result = &struct {
					Output string
					Color  string
				}{Output: "Error checking NX", Color: "red"}
			}
		}()
		return checksec.NX(filename, binary.(*elf.File))
	}
	pieFn = func(filename string, binary interface{}) (result interface{}) {
		defer func() {
			if r := recover(); r != nil {
				result = &struct {
					Output string
					Color  string
				}{Output: "Error checking PIE", Color: "red"}
			}
		}()
		return checksec.PIE(filename, binary.(*elf.File))
	}
	rpathFn = func(filename string) (result interface{}) {
		defer func() {
			if r := recover(); r != nil {
				result = &struct {
					Output string
					Color  string
				}{Output: "Error checking RPATH", Color: "red"}
			}
		}()
		return checksec.RPATH(filename)
	}
	runpathFn = func(filename string) (result interface{}) {
		defer func() {
			if r := recover(); r != nil {
				result = &struct {
					Output string
					Color  string
				}{Output: "Error checking RUNPATH", Color: "red"}
			}
		}()
		return checksec.RUNPATH(filename)
	}
	symbolsFn = func(filename string) (result interface{}) {
		defer func() {
			if r := recover(); r != nil {
				result = &struct {
					Output string
					Color  string
				}{Output: "Error checking SYMBOLS", Color: "red"}
			}
		}()
		return checksec.SYMBOLS(filename)
	}
	fortifyFn = func(filename string, binary interface{}, libc string) (result interface{}) {
		defer func() {
			if r := recover(); r != nil {
				result = &struct {
					Output      string
					Color       string
					Fortified   string
					Fortifiable string
				}{Output: "Error checking Fortify", Color: "red", Fortified: "", Fortifiable: ""}
			}
		}()
		return checksec.Fortify(filename, binary.(*elf.File), libc)
	}

	kernelConfigFn = checksec.KernelConfig
	sysctlCheckFn  = checksec.SysctlCheck
)

func getStringField(v interface{}, fieldName string) string {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if rv.IsValid() && rv.Kind() == reflect.Struct {
		f := rv.FieldByName(fieldName)
		if f.IsValid() && f.Kind() == reflect.String {
			return f.String()
		}
	}
	return ""
}

// RunFileChecks - Run the file checks
func RunFileChecks(filename string, libc string) ([]interface{}, []interface{}) {

	binary := getBinaryFn(filename)
	relro := relroFn(filename)
	canary := canaryFn(filename)
	cfi := cfiFn(filename)
	nx := nxFn(filename, binary)
	pie := pieFn(filename, binary)
	rpath := rpathFn(filename)
	runpath := runpathFn(filename)
	symbols := symbolsFn(filename)
	fortify := fortifyFn(filename, binary, libc)

	data := []interface{}{
		map[string]interface{}{
			"name": filename,
			"checks": map[string]interface{}{
				"relro":          getStringField(relro, "Output"),
				"canary":         getStringField(canary, "Output"),
				"cfi":            getStringField(cfi, "Output"),
				"nx":             getStringField(nx, "Output"),
				"pie":            getStringField(pie, "Output"),
				"rpath":          getStringField(rpath, "Output"),
				"runpath":        getStringField(runpath, "Output"),
				"symbols":        getStringField(symbols, "Output"),
				"fortify_source": getStringField(fortify, "Output"),
				"fortified":      getStringField(fortify, "Fortified"),
				"fortifyable":    getStringField(fortify, "Fortifiable"),
			},
		},
	}

	color := []interface{}{
		map[string]interface{}{
			"name": filename,
			"checks": map[string]interface{}{
				"canary":              getStringField(canary, "Output"),
				"canaryColor":         getStringField(canary, "Color"),
				"cfi":                 getStringField(cfi, "Output"),
				"cfiColor":            getStringField(cfi, "Color"),
				"fortified":           getStringField(fortify, "Fortified"),
				"fortifiedColor":      "unset",
				"fortifyable":         getStringField(fortify, "Fortifiable"),
				"fortifyableColor":    "unset",
				"fortify_source":      getStringField(fortify, "Output"),
				"fortify_sourceColor": getStringField(fortify, "Color"),
				"nx":                  getStringField(nx, "Output"),
				"nxColor":             getStringField(nx, "Color"),
				"pie":                 getStringField(pie, "Output"),
				"pieColor":            getStringField(pie, "Color"),
				"relro":               getStringField(relro, "Output"),
				"relroColor":          getStringField(relro, "Color"),
				"rpath":               getStringField(rpath, "Output"),
				"rpathColor":          getStringField(rpath, "Color"),
				"runpath":             getStringField(runpath, "Output"),
				"runpathColor":        getStringField(runpath, "Color"),
				"symbols":             getStringField(symbols, "Output"),
				"symbolsColor":        getStringField(symbols, "Color"),
			},
		},
	}

	return data, color
}

// ParseKernel - Parses the kernel config and runs the checks
func ParseKernel(filename string) (any, any) {

	kernelCheckResults, kernelCheckResultsColors := kernelConfigFn(filename)
	sysctlCheckResults, sysctlCheckResultsColors := sysctlCheckFn()

	data := reflect.AppendSlice(reflect.ValueOf(kernelCheckResults), reflect.ValueOf(sysctlCheckResults)).Interface()
	dataColors := reflect.AppendSlice(reflect.ValueOf(kernelCheckResultsColors), reflect.ValueOf(sysctlCheckResultsColors)).Interface()

	return data, dataColors

}
