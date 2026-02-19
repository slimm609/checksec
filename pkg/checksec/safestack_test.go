package checksec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHasSafeStackSymbol(t *testing.T) {
	if !hasSafeStackSymbol("__safestack_init") {
		t.Fatal("expected exact symbol to match")
	}
	if !hasSafeStackSymbol("__safestack_init_extra") {
		t.Fatal("expected prefixed symbol to match")
	}
	if hasSafeStackSymbol("__stack_chk_fail") {
		t.Fatal("did not expect stack canary symbol to match")
	}
}

func TestSafeStackInputValidation(t *testing.T) {
	_, err := SafeStack("")
	if err == nil || !strings.Contains(err.Error(), "filename cannot be empty") {
		t.Fatalf("expected empty filename error, got: %v", err)
	}

	_, err = SafeStack("/definitely/not/a/real/file")
	if err == nil || !strings.Contains(err.Error(), "cannot access file") {
		t.Fatalf("expected cannot access file error, got: %v", err)
	}
}

func TestSafeStackNonELF(t *testing.T) {
	tempDir := t.TempDir()
	txt := filepath.Join(tempDir, "not-elf.txt")
	if err := os.WriteFile(txt, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	_, err := SafeStack(txt)
	if err == nil || !strings.Contains(err.Error(), "invalid ELF file") {
		t.Fatalf("expected invalid ELF file error, got: %v", err)
	}
}

func TestSafeStackLinuxELFNoSafeStack(t *testing.T) {
	tempDir := t.TempDir()
	src := filepath.Join(tempDir, "main.go")
	bin := filepath.Join(tempDir, "app")

	if err := os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build linux test ELF: %v (%s)", err, string(out))
	}

	res, err := SafeStack(bin)
	if err != nil {
		t.Fatalf("SafeStack returned error: %v", err)
	}
	if res.Output != "No SafeStack Found" || res.Color != "red" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
