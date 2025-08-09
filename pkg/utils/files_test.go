package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Test CheckElfExists behavior without causing os.Exit by using a child process
func TestCheckElfExists_PositivePath(t *testing.T) {
	// Create a temporary file; it is not an ELF, so we bypass the actual checks by overriding hooks
	dir := t.TempDir()
	f := filepath.Join(dir, "bin")
	if err := os.WriteFile(f, []byte("dummy"), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}

	// override functions to avoid os.Exit for negative paths
	origCheckFile, origCheckElf := checkFileExistsFn, checkIfElfFn
	defer func() { checkFileExistsFn, checkIfElfFn = origCheckFile, origCheckElf }()
	checkFileExistsFn = func(string) bool { return true }
	checkIfElfFn = func(string) bool { return true }

	if !CheckElfExists(f) {
		t.Fatalf("expected true")
	}
}

func TestGetAllFilesFromDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path permissions differ on windows")
	}
	dir := t.TempDir()
	// files: one elf-like, one not
	good := filepath.Join(dir, "elf1")
	bad := filepath.Join(dir, "text1")
	_ = os.WriteFile(good, []byte("dummy"), 0o644)
	_ = os.WriteFile(bad, []byte("dummy"), 0o644)

	// stub CheckIfElf to only accept good
	orig := checkIfElfFn
	defer func() { checkIfElfFn = orig }()
	checkIfElfFn = func(path string) bool { return filepath.Base(path) == "elf1" }

	got := GetAllFilesFromDir(dir, false)
	if len(got) != 1 || filepath.Base(got[0]) != "elf1" {
		t.Fatalf("expected only elf1, got %#v", got)
	}
}
