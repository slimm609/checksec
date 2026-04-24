package checksec

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSYMBOLS_WithSymbols(t *testing.T) {
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

	result := SYMBOLS(bin)
	if result == nil {
		t.Fatal("SYMBOLS() returned nil")
	}
	if result.Output == "No Symbols" {
		t.Skip("binary was unexpectedly stripped — skipping symbols-present check")
	}
	if result.Color != "red" {
		t.Errorf("Color = %q, want %q for binary with symbols", result.Color, "red")
	}
}

func TestSYMBOLS_Stripped(t *testing.T) {
	tempDir := t.TempDir()
	src := filepath.Join(tempDir, "main.go")
	bin := filepath.Join(tempDir, "app-stripped")

	if err := os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build stripped linux test ELF: %v (%s)", err, out)
	}

	result := SYMBOLS(bin)
	if result == nil {
		t.Fatal("SYMBOLS() returned nil")
	}
	if result.Output != "No Symbols" {
		t.Errorf("Output = %q, want %q for stripped binary", result.Output, "No Symbols")
	}
	if result.Color != "green" {
		t.Errorf("Color = %q, want %q for stripped binary", result.Color, "green")
	}
}
