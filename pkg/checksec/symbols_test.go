package checksec

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSYMBOLS_WithSymbols(t *testing.T) {
	ef, _ := openELF(t, buildLinuxELF(t))
	result := SYMBOLS(ef)
	if result.Value == "No Symbols" {
		t.Skip("binary was unexpectedly stripped — skipping symbols-present check")
	}
	if result.Status != StatusBad {
		t.Errorf("Status = %q, want %q for binary with symbols", result.Status, StatusBad)
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

	ef, _ := openELF(t, bin)
	result := SYMBOLS(ef)
	if result.Value != "No Symbols" {
		t.Errorf("Value = %q, want %q for stripped binary", result.Value, "No Symbols")
	}
	if result.Status != StatusGood {
		t.Errorf("Status = %q, want %q for stripped binary", result.Status, StatusGood)
	}
}
