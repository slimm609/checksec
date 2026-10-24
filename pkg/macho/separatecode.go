// pkg/macho/separatecode.go
package macho

import (
	dm "debug/macho"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

const (
	vmProtWrite   uint32 = 0x2
	vmProtExecute uint32 = 0x4
)

func classifySegments(initprots []uint32) (string, checksec.Status) {
	if len(initprots) == 0 {
		return "N/A", checksec.StatusNA
	}
	for _, p := range initprots {
		if p&vmProtWrite != 0 && p&vmProtExecute != 0 {
			return "WX Segment", checksec.StatusBad
		}
	}
	return "Enabled", checksec.StatusGood
}

// SeparateCode asserts no segment is mapped writable and executable at once.
// Object files hold one unnamed rwx segment by construction, so they are N/A.
func SeparateCode(f *dm.File) *checksec.Result {
	if f.Type == dm.TypeObj {
		return &checksec.Result{Value: "N/A", Status: checksec.StatusNA}
	}
	var prots []uint32
	for _, l := range f.Loads {
		if seg, ok := l.(*dm.Segment); ok {
			prots = append(prots, seg.Prot)
		}
	}
	v, s := classifySegments(prots)
	return &checksec.Result{Value: v, Status: s}
}
