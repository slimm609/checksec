package macho

import (
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func TestSymbols(t *testing.T) {
	r := Symbols(loadFixture(t, "exec_arm64"))
	if r.Status != checksec.StatusBad || !strings.HasSuffix(r.Value, " symbols") {
		t.Errorf("unstripped: %+v", r)
	}
	if r := Symbols(loadFixture(t, "stripped_arm64")); r.Value != "No Symbols" || r.Status != checksec.StatusGood {
		t.Errorf("stripped: %+v", r)
	}
}

func TestDefinedSymbolCount_IgnoresImportsAndStabs(t *testing.T) {
	f := loadFixture(t, "exec_arm64")
	n := definedSymbolCount(f)
	imports := len(importedNames(f))
	if !(n > 0 && n < len(f.Symtab.Syms)) {
		t.Errorf("defined %d (imports %d) not in (0, total %d)", n, imports, len(f.Symtab.Syms))
	}
}

func TestRawLoads_IncludesCommandHeader(t *testing.T) {
	f := loadFixture(t, "exec_arm64")
	loads := rawLoads(f)
	if len(loads) != len(f.Loads) {
		t.Fatalf("rawLoads returned %d, file has %d", len(loads), len(f.Loads))
	}
	for _, l := range loads {
		if len(l.Data) < 8 || f.ByteOrder.Uint32(l.Data[0:4]) != l.Cmd {
			t.Errorf("load %#x: Data does not start with its own header", l.Cmd)
		}
	}
	if _, ok := findLoad(f, lcCodeSignature); !ok {
		t.Error("default fixture should carry LC_CODE_SIGNATURE")
	}
}

func TestLinkeditData_BoundsChecked(t *testing.T) {
	// A linkedit_data_command pointing past the (absent) __LINKEDIT segment.
	payload := make([]byte, 8)
	f := syntheticMachO(t, 2, 0, lc(lcCodeSignature, payload))
	if _, ok, err := linkeditData(f, lcCodeSignature); !ok || err == nil {
		t.Errorf("want ok=true err!=nil for missing __LINKEDIT, got ok=%v err=%v", ok, err)
	}
	if _, ok, _ := linkeditData(f, lcEncryptionInfo64); ok {
		t.Error("absent command must report ok=false")
	}
}
