package checksec

import (
	"debug/elf"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

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

func Fortify(name string, binary *elf.File, ldd string) *fortify {
	res := fortify{}
	var chkFuncLibs []string
	var funcLibs []string
	var fileFunc []string
	// limit to only checks that can actually be foritifed
	// https://github.com/gcc-mirror/gcc/blob/master/gcc/builtins.def#L1112
	supportedFuncs := []string{"__memcpy_chk", "__memmove_chk", "__mempcpy_chk", "__memset_chk", "__stpcpy_chk", "__stpncpy_chk", "__strcat_chk", "__strcpy_chk", "__strncat_chk", "__strncpy_chk", "__snprintf_chk", "__sprintf_chk", "__vsnprintf_chk", "__vsprintf_chk", "__fprintf_chk", "__printf_chk", "__vfprintf_chk", "__vprintf_chk"}
	sort.Strings(supportedFuncs)
	checked := 0
	total := 0

	if ldd == "" {
		ldd = getLdd(name)
	}

	if ldd == "none" || ldd == "unk" {
		res.Output = "N/A"
		res.Color = "unset"
		res.Fortified = "0"
		res.Fortifiable = "0"
		res.LibcSupport = "N/A"
		return &res
	}

	libcfile, err := os.Open(ldd)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer libcfile.Close()
	libc, err := elf.NewFile(libcfile)

	libcDynSymbols, err := libc.DynamicSymbols()
	if err != nil {
		libcDynSymbols, err = FunctionsFromSymbolTable(libcfile);
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
	}

	// Iterate through dynamic symbols and print their information
	for _, sym := range libcDynSymbols {
		if strings.HasPrefix(sym.Name, "__") && strings.HasSuffix(sym.Name, "_chk") {
			if isInSlice(sym.Name, supportedFuncs) {
				chkFuncLibs = append(chkFuncLibs, strings.Trim(sym.Name, "__"))
				funcLibs = append(funcLibs, strings.Trim(strings.Trim(sym.Name, "__"), "_chk"))
			}
		}
	}

	if len(chkFuncLibs) > 0 {
		res.LibcSupport = "Yes"
		res.LibcSupportColor = "green"
		res.NumLibcFunc = strconv.Itoa(len(chkFuncLibs))
	} else {
		res.LibcSupport = "No"
		res.LibcSupportColor = "red"
		res.NumLibcFunc = "0"
	}

	f, err := os.Open(name)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer f.Close()

	file, err := elf.NewFile(f)
	if err != nil {
		fmt.Println("Error parsing ELF file:", err)
		os.Exit(1)
	}

	dynSymbols, err := file.DynamicSymbols()
	if err != nil {
		dynSymbols, err = FunctionsFromSymbolTable(f)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
	}

	// Iterate through dynamic symbols and print their information
	for _, sym := range dynSymbols {
		fileFunc = append(fileFunc, strings.Trim(sym.Name, "__"))
	}

	sort.Strings(chkFuncLibs)
	sort.Strings(funcLibs)
	sort.Strings(fileFunc)

	for _, item := range chkFuncLibs {
		if isInSlice(item, fileFunc) {
			checked++
		}
	}

	total = checked
	for _, item := range funcLibs {
		if isInSlice(item, fileFunc) {
			total++
		}
	}

	if checked > 0 {
		res.Output = "Yes"
		res.Color = "green"
		res.Fortified = strconv.Itoa(checked)
		res.Fortifiable = strconv.Itoa(total)
		res.NoFortify = strconv.Itoa(total - checked)
		res.NumFileFunc = strconv.Itoa(len(dynSymbols))
		return &res
	} else {
		res.Output = "No"
		res.Color = "red"
		res.Fortified = strconv.Itoa(checked)
		res.Fortifiable = strconv.Itoa(total)
		res.NoFortify = strconv.Itoa(total - checked)
		res.NumFileFunc = strconv.Itoa(len(dynSymbols))
		return &res
	}

}

func getLdd(filename string) string {
	dynamic := false
	file, err := elf.Open(filename)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer file.Close()
	for _, prog := range file.Progs {
		if prog.Type == elf.PT_DYNAMIC {
			dynamic = true
		}
	}

	files, _ := uroot.FList(filename)
	if dynamic && len(files) == 0 {
		fmt.Println("Warning: Dynamic Binary found but missing libc. Fortify results will be skipped")
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
