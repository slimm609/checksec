package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildLinuxELF cross-compiles a trivial Go program to a linux/amd64 ELF and
// returns its path, skipping the test if the toolchain is unavailable.
func buildLinuxELF(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	bin := filepath.Join(dir, "app")
	if err := os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build linux ELF: %v (%s)", err, out)
	}
	return bin
}
