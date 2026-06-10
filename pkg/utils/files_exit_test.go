package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// runFatalSubprocess re-executes the named test in a child process with FATAL_CASE
// set, and asserts the child exits non-zero (i.e. the code under test called
// os.Exit/log.Fatal). This is the standard way to cover os.Exit branches.
func runFatalSubprocess(t *testing.T, testName, fatalCase string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(), "FATAL_CASE="+fatalCase)
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok && !exitErr.Success() {
		return // expected: child exited non-zero
	}
	t.Fatalf("expected %s to exit non-zero, got err=%v", fatalCase, err)
}

func TestCheckFileExists_MissingExits(t *testing.T) {
	if os.Getenv("FATAL_CASE") == "file-missing" {
		CheckFileExists(filepath.Join(t.TempDir(), "does-not-exist"))
		return
	}
	runFatalSubprocess(t, "TestCheckFileExists_MissingExits", "file-missing")
}

func TestCheckDirExists_MissingExits(t *testing.T) {
	if os.Getenv("FATAL_CASE") == "dir-missing" {
		CheckDirExists(filepath.Join(t.TempDir(), "no-such-dir"))
		return
	}
	runFatalSubprocess(t, "TestCheckDirExists_MissingExits", "dir-missing")
}

func TestCheckDirExists_NotADirExits(t *testing.T) {
	if os.Getenv("FATAL_CASE") == "dir-is-file" {
		f := filepath.Join(t.TempDir(), "afile")
		_ = os.WriteFile(f, []byte("x"), 0o644)
		CheckDirExists(f)
		return
	}
	runFatalSubprocess(t, "TestCheckDirExists_NotADirExits", "dir-is-file")
}

func TestGetBinary_BadFileExits(t *testing.T) {
	if os.Getenv("FATAL_CASE") == "getbinary-bad" {
		f := filepath.Join(t.TempDir(), "notelf")
		_ = os.WriteFile(f, []byte("not an elf"), 0o644)
		GetBinary(f)
		return
	}
	runFatalSubprocess(t, "TestGetBinary_BadFileExits", "getbinary-bad")
}

func TestGetAllFilesFromDir_EmptyExits(t *testing.T) {
	if os.Getenv("FATAL_CASE") == "dir-empty" {
		GetAllFilesFromDir(t.TempDir(), false)
		return
	}
	runFatalSubprocess(t, "TestGetAllFilesFromDir_EmptyExits", "dir-empty")
}

func TestCheckElfExists_NotElfExits(t *testing.T) {
	if os.Getenv("FATAL_CASE") == "checkelf-notelf" {
		f := filepath.Join(t.TempDir(), "plain")
		_ = os.WriteFile(f, []byte("plain text"), 0o644)
		CheckElfExists(f)
		return
	}
	runFatalSubprocess(t, "TestCheckElfExists_NotElfExits", "checkelf-notelf")
}
