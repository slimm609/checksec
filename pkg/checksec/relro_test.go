package checksec

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func buildLinuxELF(t *testing.T) string {
	t.Helper()
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
	return bin
}

func TestRELRO_StaticGoElf(t *testing.T) {
	bin := buildLinuxELF(t)

	result, err := RELRO(bin)
	if err != nil {
		t.Fatalf("RELRO() error = %v", err)
	}
	if result == nil {
		t.Fatal("RELRO() returned nil")
	}
	validOutputs := map[string]bool{
		"Full RELRO":    true,
		"Partial RELRO": true,
		"No RELRO":      true,
	}
	if !validOutputs[result.Output] {
		t.Errorf("unexpected Output = %q", result.Output)
	}
	validColors := map[string]bool{"green": true, "yellow": true, "red": true}
	if !validColors[result.Color] {
		t.Errorf("unexpected Color = %q", result.Color)
	}
}

func TestRELRO_NoProgHeaders(t *testing.T) {
	bin := "../../tests/binaries/output/rel.o"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("rel.o fixture not found: %v", err)
	}

	result, err := RELRO(bin)
	if err != nil {
		t.Fatalf("RELRO() error = %v", err)
	}
	if result == nil {
		t.Fatal("RELRO() returned nil")
	}
	validOutputs := map[string]bool{"N/A": true, "No RELRO": true}
	if !validOutputs[result.Output] {
		t.Errorf("unexpected Output for rel.o = %q", result.Output)
	}
}
