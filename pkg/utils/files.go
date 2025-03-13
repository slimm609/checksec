package utils

import (
	"debug/elf"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
)

// CheckElfExists - Check if file exists and is an Elf file
func CheckElfExists(fileName string) bool {
	if !CheckFileExists(fileName) {
		fmt.Println("File not found:", fileName)
		os.Exit(1)
	}
	if !CheckIfElf(fileName) {
		fmt.Println("File is not an ELF file:", fileName)
		os.Exit(1)
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
			fmt.Println("Directory not found:", dirName)
			os.Exit(1)
		} else {
			fmt.Println("An error occurred:", err)
			os.Exit(1)
		}
	}

	if !dirInfo.IsDir() {
		fmt.Printf("%s is not a Directory", dirName)
		os.Exit(1)
	}

	return true
}

// CheckFileExists - check if the file exists
func CheckFileExists(fileName string) bool {
	_, err := os.Stat(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("File not found:", fileName)
			os.Exit(1)
		} else {
			fmt.Println("An error occurred:", err)
			os.Exit(1)
		}
	}

	return true
}

// GetAllFilesFromDir - get the list of all elf files from a directory (or recursively)
func GetAllFilesFromDir(dirName string, recursive bool) []string {
	var results []string
	var fileList []string

	if recursive {
		filepath.WalkDir(dirName, func(path string, file fs.DirEntry, err error) error {
			if err != nil {
				return fs.SkipDir
			}
			if !file.IsDir() && CheckIfElf(path) && file.Type().IsRegular() {
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
			if j != "." && !dirInfo.IsDir() && CheckIfElf(j) {
				results = append(results, j)
			}
		}

	}

	if len(results) == 0 {
		log.Fatalf("Error: No binary files found in %s", dirName)
	}
	return results
}

// GetBinary - Return the binary details
func GetBinary(fileName string) *elf.File {

	binary, err := elf.Open(fileName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func(f *elf.File) {
		err := f.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(binary)

	return binary
}
