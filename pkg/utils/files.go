package utils

import (
	"debug/elf"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/slimm609/checksec/v3/pkg/output"
	"github.com/slimm609/checksec/v3/pkg/target"
)

// Indirections for testability
var (
	checkFileExistsFn   = CheckFileExists
	checkIfElfFn        = CheckIfElf
	isSupportedBinaryFn = IsSupportedBinary
)

// IsSupportedBinary reports whether path is a format checksec has a check
// registry for (ELF or Mach-O, thin or fat). It reads only the magic.
func IsSupportedBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return target.Supported(target.Detect(f))
}

// CheckBinaryExists exits with an error unless path exists and is a supported
// binary format. Used by `file`; the ELF-only commands keep CheckElfExists.
func CheckBinaryExists(path string) bool {
	if !checkFileExistsFn(path) {
		output.Fatalf("File not found: %v", path)
	}
	if !isSupportedBinaryFn(path) {
		output.Fatalf("File is not a supported binary (ELF or Mach-O): %v", path)
	}
	return true
}

// CheckElfExists - Check if file exists and is an Elf file
func CheckElfExists(fileName string) bool {
	if !checkFileExistsFn(fileName) {
		output.Fatalf("File not found: %v", fileName)
	}
	if !checkIfElfFn(fileName) {
		output.Fatalf("File is not an ELF file: %v", fileName)
	}

	return true
}

// CheckIfElf - Check if the file is an Elf file
func CheckIfElf(fileName string) bool {
	_, err := elf.Open(fileName)
	if err != nil {
		return false
	}

	return true
}

// CheckDirExists - Check if the directory exists
func CheckDirExists(dirName string) bool {
	dirInfo, err := os.Stat(dirName)
	if err != nil {
		if os.IsNotExist(err) {
			output.Fatalf("Directory not found: %v", dirName)
		} else {
			output.Fatalf("An error occurred: %v", err)
		}
	}

	if !dirInfo.IsDir() {
		output.Fatalf("%s is not a Directory", dirName)
	}

	return true
}

// CheckFileExists - check if the file exists
func CheckFileExists(fileName string) bool {
	_, err := os.Stat(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			output.Fatalf("File not found: %v", fileName)
		} else {
			output.Fatalf("An error occurred: %v", err)
		}
	}

	return true
}

// GetAllFilesFromDir - get the list of all supported binaries from a directory (or recursively)
func GetAllFilesFromDir(dirName string, recursive bool) []string {
	var results []string
	var fileList []string

	if recursive {
		filepath.WalkDir(dirName, func(path string, file fs.DirEntry, err error) error {
			if err != nil {
				return fs.SkipDir
			}
			if !file.IsDir() && isSupportedBinaryFn(path) && file.Type().IsRegular() {
				results = append(results, path)
			}

			return nil
		})
	} else {
		fileList, _ = filepath.Glob(fmt.Sprintf("%s/*", dirName))
		for _, j := range fileList {
			dirInfo, _ := os.Stat(j)
			if dirInfo == nil {
				continue
			}
			if j != "." && !dirInfo.IsDir() && isSupportedBinaryFn(j) {
				results = append(results, j)
			}
		}

	}

	if len(results) == 0 {
		log.Fatalf("Error: No binary files found in %s", dirName)
	}
	return results
}

// GetBinary - Return the ELF file handle.
// Callers must close the returned *elf.File when finished.
func GetBinary(fileName string) *elf.File {
	binary, err := elf.Open(fileName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	return binary
}
