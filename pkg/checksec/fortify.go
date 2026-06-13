package checksec

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/slimm609/checksec/v3/pkg/output"
	uroot "github.com/u-root/u-root/pkg/ldd"
)

type fortify struct {
	Output           string
	Color            string
	Fortifiable      string
	Fortified        string
	NoFortify        string
	LibcSupport      string
	LibcSupportColor string
	NumLibcFunc      string
	NumFileFunc      string
}

// Fortify reports FORTIFY_SOURCE coverage for the binary at name. The already-
// open binary is reused for the target's symbol scan; name is needed only for
// libc auto-resolution via ldd. ldd may be a pre-resolved libc path, or "" to
// resolve it automatically.
func Fortify(name string, binary *elf.File, ldd string) (*fortify, error) {
	// limit to only checks that can actually be foritifed
	// https://github.com/gcc-mirror/gcc/blob/master/gcc/builtins.def#L1112
	supportedFuncs := []string{"__memcpy_chk", "__memmove_chk", "__mempcpy_chk", "__memset_chk", "__stpcpy_chk", "__stpncpy_chk", "__strcat_chk", "__strcpy_chk", "__strncat_chk", "__strncpy_chk", "__snprintf_chk", "__sprintf_chk", "__vsnprintf_chk", "__vsprintf_chk", "__fprintf_chk", "__printf_chk", "__vfprintf_chk", "__vprintf_chk"}
	sort.Strings(supportedFuncs)

	if ldd == "" {
		ldd = getLdd(name, binary)
	}

	return fortifyWithLdd(binary, ldd, supportedFuncs)
}

// fortifyWithLdd runs the fortify analysis given a resolved libc path (ldd).
func fortifyWithLdd(file *elf.File, ldd string, supportedFuncs []string) (*fortify, error) {
	res := fortify{}
	var chkFuncLibs []string
	var funcLibs []string
	var fileFunc []string
	checked := 0
	total := 0

	if ldd == "none" || ldd == "unk" {
		res.Output = "N/A"
		res.Color = "unset"
		res.Fortified = "0"
		res.Fortifiable = "0"
		res.LibcSupport = "N/A"
		return &res, nil
	}

	libcfile, err := os.Open(ldd)
	if err != nil {
		return nil, fmt.Errorf("error opening libc file: %w", err)
	}
	defer libcfile.Close()
	libc, err := elf.NewFile(libcfile)
	if err != nil {
		return nil, fmt.Errorf("error parsing libc file: %w", err)
	}

	libcDynSymbols, err := libc.DynamicSymbols()
	if err != nil {
		libcDynSymbols, err = FunctionsFromSymbolTable(libcfile)
		if err != nil {
			return nil, fmt.Errorf("error getting dynamic symbols from libc file: %w", err)
		}
	}

	// Determine which fortifiable __*_chk functions the libc actually provides.
	chkFuncLibs, funcLibs = fortifyLibcFuncs(libcDynSymbols, supportedFuncs)

	if len(chkFuncLibs) > 0 {
		res.LibcSupport = "Yes"
		res.LibcSupportColor = "green"
		res.NumLibcFunc = strconv.Itoa(len(chkFuncLibs))
	} else {
		res.LibcSupport = "No"
		res.LibcSupportColor = "red"
		res.NumLibcFunc = "0"
	}

	dynSymbols, err := file.DynamicSymbols()
	if err != nil {
		// No .dynsym — static binary; nothing fortifiable via libc.
		dynSymbols = nil
	}

	// Iterate through dynamic symbols and print their information
	for _, sym := range dynSymbols {
		fileFunc = append(fileFunc, strings.Trim(sym.Name, "__"))
	}

	checked, total = computeFortifyCounts(chkFuncLibs, funcLibs, fileFunc)

	if checked > 0 {
		res.Output = "Yes"
		res.Color = "green"
		res.Fortified = strconv.Itoa(checked)
		res.Fortifiable = strconv.Itoa(total)
		res.NoFortify = strconv.Itoa(total - checked)
		res.NumFileFunc = strconv.Itoa(len(dynSymbols))
		return &res, nil
	} else {
		res.Output = "No"
		res.Color = "red"
		res.Fortified = strconv.Itoa(checked)
		res.Fortifiable = strconv.Itoa(total)
		res.NoFortify = strconv.Itoa(total - checked)
		res.NumFileFunc = strconv.Itoa(len(dynSymbols))
		return &res, nil
	}

}

// fortifyLibcFuncs extracts, from a libc's symbols, the fortifiable __*_chk
// functions it provides (chkFuncs) and their unprotected base names (baseFuncs),
// limited to the compiler-supported fortify functions.
func fortifyLibcFuncs(libcSyms []elf.Symbol, supportedFuncs []string) (chkFuncs, baseFuncs []string) {
	for _, sym := range libcSyms {
		if strings.HasPrefix(sym.Name, "__") && strings.HasSuffix(sym.Name, "_chk") {
			if isInSlice(sym.Name, supportedFuncs) {
				chkFuncs = append(chkFuncs, strings.Trim(sym.Name, "__"))
				baseFuncs = append(baseFuncs, strings.Trim(strings.Trim(sym.Name, "__"), "_chk"))
			}
		}
	}
	return chkFuncs, baseFuncs
}

// computeFortifyCounts compares the libc's fortifiable functions against the
// functions present in the target binary. It returns the number of fortified
// calls and the total fortifiable count (fortified plus fortifiable-but-unprotected).
func computeFortifyCounts(chkFuncs, baseFuncs, fileFuncs []string) (fortified, fortifiable int) {
	sort.Strings(chkFuncs)
	sort.Strings(baseFuncs)
	sort.Strings(fileFuncs)

	for _, item := range chkFuncs {
		if isInSlice(item, fileFuncs) {
			fortified++
		}
	}
	fortifiable = fortified
	for _, item := range baseFuncs {
		if isInSlice(item, fileFuncs) {
			fortifiable++
		}
	}
	return fortified, fortifiable
}

// getLdd resolves the libc path for the binary at filename. The already-open
// ELF is reused for the PT_DYNAMIC check; the path itself is required only by
// uroot.FList (which inspects the on-disk binary's dependencies).
func getLdd(filename string, file *elf.File) string {
	dynamic := false
	for _, prog := range file.Progs {
		if prog.Type == elf.PT_DYNAMIC {
			dynamic = true
		}
	}

	abs, _ := filepath.Abs(filename)

	files, _ := uroot.FList(abs)
	if dynamic && len(files) == 0 {
		output.Warnf("Warning: %s: Dynamic Binary found but missing libc. Fortify results will be skipped", abs)
		return "unk"
	}

	for _, libc := range files {
		if strings.Contains(libc, "libc.") {
			return libc
		}
	}
	return "none"
}

func isInSlice(item string, slice []string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
