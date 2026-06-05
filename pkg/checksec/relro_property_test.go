package checksec

import (
	"debug/elf"
	"testing"

	"pgregory.net/rapid"
)

// A present DT_BIND_NOW dynamic entry indicates bind-now ("Full RELRO")
// regardless of its d_val, which is unused by the ELF spec. relroBindNow must
// therefore report true whenever the bind slice is non-empty.
func TestProp_RelroBindNow_PresenceImpliesBindNow(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.Uint64().Draw(t, "bind_dval")
		if !relroBindNow([]uint64{v}, nil, nil) {
			t.Fatalf("DT_BIND_NOW present (d_val=%d) must imply bind-now", v)
		}
	})
}

// The DF_BIND_NOW bit in DT_FLAGS implies bind-now; any other flag bits must not.
func TestProp_RelroBindNow_FlagsBindNowBit(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		flags := rapid.Uint64().Draw(t, "dt_flags")
		want := flags&uint64(elf.DF_BIND_NOW) != 0
		if got := relroBindNow(nil, []uint64{flags}, nil); got != want {
			t.Fatalf("DT_FLAGS=%#x: relroBindNow=%v, want %v", flags, got, want)
		}
	})
}

// The DF_1_NOW bit in DT_FLAGS_1 implies bind-now; any other flag bits must not.
func TestProp_RelroBindNow_Flags1NowBit(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		flags1 := rapid.Uint64().Draw(t, "dt_flags_1")
		want := flags1&uint64(elf.DF_1_NOW) != 0
		if got := relroBindNow(nil, nil, []uint64{flags1}); got != want {
			t.Fatalf("DT_FLAGS_1=%#x: relroBindNow=%v, want %v", flags1, got, want)
		}
	})
}

// With no dynamic flags set at all, a binary is never bind-now.
func TestProp_RelroBindNow_EmptyNeverBindNow(t *testing.T) {
	if relroBindNow(nil, nil, nil) {
		t.Fatal("no dynamic flags must not imply bind-now")
	}
}
