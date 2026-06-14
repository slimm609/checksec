package checksec

import (
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

func TestSafeStackLinuxELFNoSafeStack(t *testing.T) {
	ef, raw := openELF(t, buildLinuxELF(t))
	res := SafeStack(ef, raw)
	if res.Value != "No SafeStack Found" || res.Status != StatusBad {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestSafeStack_NilRawFallback(t *testing.T) {
	ef, _ := openELF(t, buildLinuxELF(t))
	res := SafeStack(ef, nil)
	if res.Value != "No SafeStack Found" {
		t.Fatalf("unexpected result with nil raw: %+v", res)
	}
}
