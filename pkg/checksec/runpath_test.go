package checksec

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRUNPATH_NoRunpath(t *testing.T) {
	tempDir := t.TempDir()
	src := filepath.Join(tempDir, "main.go")
	bin := filepath.Join(tempDir, "app")

	if err := os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build linux test ELF: %v (%s)", err, out)
	}

	result := RUNPATH(bin)
	if result == nil {
		t.Fatal("RUNPATH() returned nil")
	}
	if result.Output != "No RUNPATH" {
		t.Errorf("Output = %q, want %q", result.Output, "No RUNPATH")
	}
	if result.Color != "green" {
		t.Errorf("Color = %q, want %q", result.Color, "green")
	}
}

func TestRUNPATH_WithRunpath(t *testing.T) {
	t.Skip("requires C binary with RUNPATH set — needs gcc/ld")
}
