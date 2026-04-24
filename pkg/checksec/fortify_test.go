package checksec

import (
	"debug/elf"
	"testing"
)

func TestFortify_NoneDynamic(t *testing.T) {
	binary := &elf.File{}
	result := Fortify("test", binary, "none")
	if result == nil {
		t.Fatal("Fortify() returned nil")
	}
	if result.Output != "N/A" {
		t.Errorf("Output = %q, want N/A for ldd=none", result.Output)
	}
	if result.Color != "unset" {
		t.Errorf("Color = %q, want unset for ldd=none", result.Color)
	}
	if result.Fortified != "0" {
		t.Errorf("Fortified = %q, want 0", result.Fortified)
	}
	if result.Fortifiable != "0" {
		t.Errorf("Fortifiable = %q, want 0", result.Fortifiable)
	}
	if result.LibcSupport != "N/A" {
		t.Errorf("LibcSupport = %q, want N/A", result.LibcSupport)
	}
}

func TestFortify_UnknownLDD(t *testing.T) {
	binary := &elf.File{}
	result := Fortify("test", binary, "unk")
	if result == nil {
		t.Fatal("Fortify() returned nil")
	}
	if result.Output != "N/A" {
		t.Errorf("Output = %q, want N/A for ldd=unk", result.Output)
	}
	if result.Color != "unset" {
		t.Errorf("Color = %q, want unset for ldd=unk", result.Color)
	}
}
