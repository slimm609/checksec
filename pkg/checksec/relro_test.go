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
	ef, _ := openELF(t, buildLinuxELF(t))
	result := RELRO(ef)
	if result == nil {
		t.Fatal("RELRO() returned nil")
	}
	validOutputs := map[string]bool{
		"Full RELRO":    true,
		"Partial RELRO": true,
		"No RELRO":      true,
	}
	if !validOutputs[result.Value] {
		t.Errorf("unexpected Value = %q", result.Value)
	}
	validStatus := map[Status]bool{StatusGood: true, StatusWarn: true, StatusBad: true}
	if !validStatus[result.Status] {
		t.Errorf("unexpected Status = %q", result.Status)
	}
}

func TestRELRO_NoProgHeaders(t *testing.T) {
	ef, _ := openELF(t, requireFixture(t, "rel.o"))
	result := RELRO(ef)
	if result == nil {
		t.Fatal("RELRO() returned nil")
	}
	validOutputs := map[string]bool{"N/A": true, "No RELRO": true}
	if !validOutputs[result.Value] {
		t.Errorf("unexpected Value for rel.o = %q", result.Value)
	}
}
