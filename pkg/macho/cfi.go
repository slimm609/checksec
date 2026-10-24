// pkg/macho/cfi.go
package macho

import (
	dm "debug/macho"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

const cpuSubtypeArm64E uint32 = 2

// classifyPAC maps cpu type/subtype to the pointer-authentication verdict.
// arm64e is the only Darwin ABI with PAC; x86 has no hardware CFI on Darwin.
func classifyPAC(cpu dm.Cpu, sub uint32) (string, checksec.Status) {
	if cpu != dm.CpuArm64 {
		return "N/A", checksec.StatusNA
	}
	if sub&0x00ffffff == cpuSubtypeArm64E {
		return "PAC", checksec.StatusGood
	}
	return "NO PAC", checksec.StatusWarn
}

// CFI reports pointer authentication (PAC) availability by ABI.
func CFI(f *dm.File) *checksec.Result {
	v, s := classifyPAC(f.Cpu, f.SubCpu)
	return &checksec.Result{Value: v, Status: s}
}
