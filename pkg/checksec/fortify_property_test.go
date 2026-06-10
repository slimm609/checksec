package checksec

import (
	"debug/elf"
	"sort"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// fortifySupported mirrors the compiler-fortifiable function list used by Fortify.
var fortifySupported = []string{
	"__memcpy_chk", "__memmove_chk", "__mempcpy_chk", "__memset_chk",
	"__stpcpy_chk", "__stpncpy_chk", "__strcat_chk", "__strcpy_chk",
	"__strncat_chk", "__strncpy_chk", "__snprintf_chk", "__sprintf_chk",
	"__vsnprintf_chk", "__vsprintf_chk", "__fprintf_chk", "__printf_chk",
	"__vfprintf_chk", "__vprintf_chk",
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

// fortifyLibcFuncs must (a) keep only supported __*_chk functions and (b) derive
// the chk name and base name as the symbol minus its "__" prefix and "_chk"
// suffix. Symbols that are unsupported or not __*_chk must be dropped.
func TestProp_FortifyLibcFuncs_OracleAndFiltering(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var syms []elf.Symbol
		var wantChk, wantBase []string
		for _, n := range fortifySupported {
			if rapid.Bool().Draw(t, "incl_"+n) {
				syms = append(syms, elf.Symbol{Name: n})
				wantChk = append(wantChk, strings.TrimPrefix(n, "__"))
				wantBase = append(wantBase, strings.TrimSuffix(strings.TrimPrefix(n, "__"), "_chk"))
			}
		}
		// Noise that must be filtered: has __ prefix and _chk suffix but is not
		// a supported function, plus assorted unrelated symbols.
		for _, noise := range []string{"__foo_chk", "malloc", "free", "__init", "printf"} {
			if rapid.Bool().Draw(t, "noise_"+noise) {
				syms = append(syms, elf.Symbol{Name: noise})
			}
		}

		chk, base := fortifyLibcFuncs(syms, fortifySupported)
		if !sameStringSet(chk, wantChk) {
			t.Fatalf("chkFuncs=%v want set %v", chk, wantChk)
		}
		if !sameStringSet(base, wantBase) {
			t.Fatalf("baseFuncs=%v want set %v", base, wantBase)
		}
	})
}

// computeFortifyCounts must never report more fortified than fortifiable, and
// counts are non-negative.
func TestProp_ComputeFortifyCounts_Ordering(t *testing.T) {
	gen := rapid.SliceOfN(rapid.SampledFrom([]string{"memcpy", "strcpy", "printf", "x", "y"}), 0, 6)
	rapid.Check(t, func(t *rapid.T) {
		chk := gen.Draw(t, "chk")
		base := gen.Draw(t, "base")
		file := gen.Draw(t, "file")
		fortified, fortifiable := computeFortifyCounts(chk, base, file)
		if fortified < 0 || fortifiable < 0 {
			t.Fatalf("negative counts: fortified=%d fortifiable=%d", fortified, fortifiable)
		}
		if fortified > fortifiable {
			t.Fatalf("fortified %d exceeds fortifiable %d", fortified, fortifiable)
		}
	})
}

// hasSafeStackSymbol is true exactly for names with the __safestack_init prefix.
func TestProp_HasSafeStackSymbol_Oracle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		suffix := rapid.StringN(0, 16, 16).Draw(t, "suffix")
		name := rapid.SampledFrom([]string{"", "x", "__safestack", SafeStackInit}).Draw(t, "prefix") + suffix
		want := strings.HasPrefix(name, SafeStackInit)
		if got := hasSafeStackSymbol(name); got != want {
			t.Fatalf("name=%q got=%v want=%v", name, got, want)
		}
	})
}
