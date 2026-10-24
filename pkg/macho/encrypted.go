package macho

import (
	dm "debug/macho"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// Encrypted reports FairPlay encryption: LC_ENCRYPTION_INFO(_64) with a
// non-zero cryptid. Informational; present on App Store iOS binaries.
func Encrypted(f *dm.File) *checksec.Result {
	for _, cmd := range []uint32{lcEncryptionInfo64, lcEncryptionInfo} {
		l, ok := findLoad(f, cmd)
		if !ok || len(l.Data) < 20 {
			continue
		}
		if f.ByteOrder.Uint32(l.Data[16:20]) != 0 {
			return &checksec.Result{Value: "Encrypted", Status: checksec.StatusInfo}
		}
	}
	return &checksec.Result{Value: "Not encrypted", Status: checksec.StatusInfo}
}
