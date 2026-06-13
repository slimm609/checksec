package checksec

import (
	"testing"
)

// TestIsCanarySymbol verifies the symbol-name predicate that drives Canary().
// This is the regression guard for parity with checksec.bash, which matches
// __stack_chk_fail | __stack_chk_guard | __intel_security_cookie.
func TestIsCanarySymbol(t *testing.T) {
	tests := []struct {
		symbol string
		want   bool
		why    string
	}{
		// GCC / Clang -fstack-protector (dynamically linked)
		{"__stack_chk_fail", true, "glibc canary failure handler"},
		{"__stack_chk_fail_local", true, "glibc local-alias canary handler (PIC)"},
		// Statically linked / freestanding: only the guard variable is present
		{"__stack_chk_guard", true, "glibc/musl canary guard variable (static link)"},
		// Intel ICC compiler
		{"__intel_security_cookie", true, "Intel ICC stack cookie"},
		{"__intel_security_check_cookie", true, "Intel ICC stack cookie check (prefix match)"},
		// Negatives
		{"__stack_chk", false, "incomplete prefix must not match"},
		{"stack_chk_fail", false, "missing leading underscores"},
		{"__safestack_init", false, "SafeStack symbol, not a canary"},
		{"main", false, "unrelated symbol"},
		{"", false, "empty symbol"},
	}

	for _, tt := range tests {
		t.Run(tt.symbol+"/"+tt.why, func(t *testing.T) {
			if got := isCanarySymbol(tt.symbol); got != tt.want {
				t.Errorf("isCanarySymbol(%q) = %v, want %v (%s)", tt.symbol, got, tt.want, tt.why)
			}
		})
	}
}

func TestCanary_ValidELFWithoutCanary(t *testing.T) {
	// A pure-Go linux/amd64 binary has no glibc stack-protector symbols.
	ef, raw := openELF(t, buildLinuxELF(t))
	res := Canary(ef, raw)
	if res.Value != "No Canary Found" || res.Status != StatusBad {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestCanary_ValidELFWithCanary(t *testing.T) {
	// Uses the committed gcc fixture built with -fstack-protector-all.
	ef, raw := openELF(t, requireFixture(t, "all"))
	res := Canary(ef, raw)
	if res.Value != "Canary Found" || res.Status != StatusGood {
		t.Fatalf("expected Canary Found/StatusGood, got: %+v", res)
	}
}

func TestCanary_NilRawFallback(t *testing.T) {
	// raw=nil disables the stripped-binary fallback; result still valid.
	ef, _ := openELF(t, buildLinuxELF(t))
	res := Canary(ef, nil)
	if res.Value != "No Canary Found" {
		t.Fatalf("unexpected result with nil raw: %+v", res)
	}
}
