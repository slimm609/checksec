package checksec

import (
	"debug/elf"
	"testing"
)

// TestFortify_NilBinaryDoesNotPanic guards the PR-review finding: Fortify is
// exported and historically accepted a nil *elf.File; with ldd=="" that now
// reaches getLdd(file.Progs) which would nil-deref. Must return an error
// instead.
func TestFortify_NilBinaryDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Fortify(_, nil, \"\") panicked: %v", r)
		}
	}()
	_, err := Fortify("/bin/anything", nil, "")
	if err == nil {
		t.Error("expected error for nil binary, got nil")
	}
}

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

// TestFortify_OutputByFortifiableCounts drives the Yes / No / N/A verdict from
// real ELF fixtures against the stand-in libc dso.so (which provides
// __printf_chk and __strcpy_chk). A binary that references no fortifiable libc
// function at all has nothing for _FORTIFY_SOURCE to protect, so it must be
// N/A rather than No (docs/checks/fortify.md; checksec.bash did the same when
// the fortifiable total was 0).
func TestFortify_OutputByFortifiableCounts(t *testing.T) {
	libc := requireFixture(t, "dso.so")

	tests := []struct {
		name        string
		target      func(t *testing.T) string
		wantOutput  string
		wantColor   string
		wantFortif  string
		wantFortble string
		wantNoFort  string
	}{
		{
			name:        "fortified calls",
			target:      func(t *testing.T) string { return requireFixture(t, "all") },
			wantOutput:  "Yes",
			wantColor:   "green",
			wantFortif:  "2",
			wantFortble: "2",
			wantNoFort:  "0",
		},
		{
			name:        "fortifiable but unfortified calls",
			target:      func(t *testing.T) string { return requireFixture(t, "none") },
			wantOutput:  "No",
			wantColor:   "red",
			wantFortif:  "0",
			wantFortble: "2",
			wantNoFort:  "2",
		},
		{
			// Dynamically linked executable (PT_DYNAMIC, a few dynsyms) that
			// calls nothing fortifiable: the fszero* case.
			name:        "dynamic binary with nothing fortifiable",
			target:      func(t *testing.T) string { return goStdlibELFFixture(t, "gcc-amd64-linux-exec") },
			wantOutput:  "N/A",
			wantColor:   "unset",
			wantFortif:  "0",
			wantFortble: "0",
			wantNoFort:  "0",
		},
		{
			name:        "no dynamic symbols at all",
			target:      func(t *testing.T) string { return requireFixture(t, "rel.o") },
			wantOutput:  "N/A",
			wantColor:   "unset",
			wantFortif:  "0",
			wantFortble: "0",
			wantNoFort:  "0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.target(t)
			ef, _ := openELF(t, target)

			res, err := Fortify(target, ef, libc)
			if err != nil {
				t.Fatalf("Fortify() error = %v", err)
			}
			if res.Output != tt.wantOutput {
				t.Errorf("Output = %q, want %q", res.Output, tt.wantOutput)
			}
			if res.Color != tt.wantColor {
				t.Errorf("Color = %q, want %q", res.Color, tt.wantColor)
			}
			if res.Fortified != tt.wantFortif {
				t.Errorf("Fortified = %q, want %q", res.Fortified, tt.wantFortif)
			}
			if res.Fortifiable != tt.wantFortble {
				t.Errorf("Fortifiable = %q, want %q", res.Fortifiable, tt.wantFortble)
			}
			if res.NoFortify != tt.wantNoFort {
				t.Errorf("NoFortify = %q, want %q", res.NoFortify, tt.wantNoFort)
			}
			// libc itself supports fortify in every case; N/A must not hide that.
			if res.LibcSupport != "Yes" {
				t.Errorf("LibcSupport = %q, want Yes", res.LibcSupport)
			}
		})
	}
}
