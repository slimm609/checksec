// pkg/macho/signature_property_test.go
package macho

import (
	"testing"

	"pgregory.net/rapid"
)

// The SuperBlob parser must never panic and never read outside its input,
// whatever bytes it is handed.
func TestParseSuperBlob_NeverPanics(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		b := rapid.SliceOfN(rapid.Byte(), 0, 512).Draw(rt, "blob")
		_, _ = parseSuperBlob(b)
		_ = parseEntitlementsXML(b)
		_ = parseEntitlementsDER(b)
	})
}

// Seed the generator with a structurally valid header so the parser's inner
// branches are exercised, then corrupt a few bytes.
func TestParseSuperBlob_CorruptedValidBlobNeverPanics(t *testing.T) {
	base := superBlob(map[uint32][]byte{
		csSlotCodeDirectory: codeDirectory(csFlagRuntime, "com.example", "TEAM123456"),
		csSlotEntitlements:  blob(csMagicEntitlements, []byte("<plist/>")),
		csSlotSignature:     blob(csMagicBlobWrapper, nil),
	})
	rapid.Check(t, func(rt *rapid.T) {
		b := append([]byte(nil), base...)
		n := rapid.IntRange(1, 8).Draw(rt, "n")
		for i := 0; i < n; i++ {
			idx := rapid.IntRange(0, len(b)-1).Draw(rt, "idx")
			b[idx] = rapid.Byte().Draw(rt, "val")
		}
		_, _ = parseSuperBlob(b)
	})
}
