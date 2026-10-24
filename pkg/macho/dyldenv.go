package macho

import (
	"bytes"
	dm "debug/macho"
	"strings"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// DyldEnv lists LC_DYLD_ENVIRONMENT entries. A binary that sets DYLD_* for
// itself re-opens the injection paths the hardened runtime closes.
func DyldEnv(f *dm.File) *checksec.Result {
	var vars []string
	malformed := false
	for _, l := range rawLoads(f) {
		if l.Cmd != lcDyldEnvironment {
			continue
		}
		if len(l.Data) < 12 {
			malformed = true
			continue
		}
		off := f.ByteOrder.Uint32(l.Data[8:12])
		if uint64(off) >= uint64(len(l.Data)) {
			malformed = true
			continue
		}
		s := l.Data[off:]
		if i := bytes.IndexByte(s, 0); i >= 0 {
			s = s[:i]
		}
		vars = append(vars, string(s))
	}
	switch {
	case len(vars) > 0:
		return &checksec.Result{Value: strings.Join(vars, "; "), Status: checksec.StatusBad}
	case malformed:
		return &checksec.Result{Value: "(malformed)", Status: checksec.StatusBad}
	}
	return &checksec.Result{Value: "None", Status: checksec.StatusGood}
}
