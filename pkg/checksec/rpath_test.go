package checksec

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRPATH_NoRpath(t *testing.T) {
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

	result, err := RPATH(bin)
	if err != nil {
		t.Fatalf("RPATH() error = %v", err)
	}
	if result == nil {
		t.Fatal("RPATH() returned nil")
	}
	if result.Value != "No RPATH" {
		t.Errorf("Output = %q, want %q", result.Value, "No RPATH")
	}
	if result.Status != "green" {
		t.Errorf("Color = %q, want %q", result.Status, "green")
	}
}

func TestRPATH_WithRpath(t *testing.T) {
	// The committed "rpath" fixture is a real ELF carrying DT_RPATH ([./]).
	bin := requireFixture(t, "rpath")

	result, err := RPATH(bin)
	if err != nil {
		t.Fatalf("RPATH() error = %v", err)
	}
	if result == nil {
		t.Fatal("RPATH() returned nil")
	}
	if result.Value != "RPATH" {
		t.Errorf("Output = %q, want %q", result.Value, "RPATH")
	}
	if result.Status != "red" {
		t.Errorf("Color = %q, want %q", result.Status, "red")
	}
}
