package checksec

import (
	"debug/elf"
	"testing"
)

func TestFortify_NoneDynamic(t *testing.T) {
	binary := &elf.File{}
	result, err := Fortify("test", binary, "none")
	if err != nil {
		t.Fatalf("Fortify() error = %v", err)
	}
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

// TestFortifyBreakdown drives the per-function classifier: for each fortifiable
// libc function, report whether the target uses the _chk variant (fortified) or
// the base name (unprotected). Functions the target doesn't use are omitted.
func TestFortifyBreakdown(t *testing.T) {
	// libc provides memcpy_chk + strcpy_chk; target uses __memcpy_chk and plain
	// strcpy (and an unrelated printf).
	chkFuncs := []string{"memcpy_chk", "strcpy_chk"}
	baseFuncs := []string{"memcpy", "strcpy"}
	fileFuncs := []string{"memcpy_chk", "strcpy", "printf"}

	got := fortifyBreakdown(chkFuncs, baseFuncs, fileFuncs)
	want := []FortifyFunc{
		{Name: "memcpy", Fortified: true},
		{Name: "strcpy", Fortified: false},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestFortifyBreakdown_BothVariantsPresent(t *testing.T) {
	// Target uses BOTH memcpy and __memcpy_chk → fortified=true (any protection
	// counts; the unprotected call site is reflected in the count, not the label).
	got := fortifyBreakdown(
		[]string{"memcpy_chk"}, []string{"memcpy"},
		[]string{"memcpy", "memcpy_chk"})
	if len(got) != 1 || got[0].Name != "memcpy" || got[0].Fortified != true {
		t.Errorf("got %+v, want [{memcpy true}]", got)
	}
}

func TestFortifyBreakdown_NoneUsed(t *testing.T) {
	got := fortifyBreakdown([]string{"memcpy_chk"}, []string{"memcpy"}, []string{"puts"})
	if len(got) != 0 {
		t.Errorf("expected empty breakdown, got %+v", got)
	}
}

func TestFortifyBreakdown_SortedByName(t *testing.T) {
	got := fortifyBreakdown(
		[]string{"strcpy_chk", "memcpy_chk"}, []string{"strcpy", "memcpy"},
		[]string{"strcpy", "memcpy"})
	if len(got) != 2 || got[0].Name != "memcpy" || got[1].Name != "strcpy" {
		t.Errorf("expected sorted [memcpy, strcpy], got %+v", got)
	}
}

func TestFortify_UnknownLDD(t *testing.T) {
	binary := &elf.File{}
	result, err := Fortify("test", binary, "unk")
	if err != nil {
		t.Fatalf("Fortify() error = %v", err)
	}
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
