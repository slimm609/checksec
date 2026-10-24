// pkg/macho/signature_test.go
package macho

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// blob builds a code-signing blob: magic, length, payload (all big-endian).
func blob(magic uint32, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(b[0:], magic)
	binary.BigEndian.PutUint32(b[4:], uint32(len(b)))
	copy(b[8:], payload)
	return b
}

// codeDirectory builds a minimal CodeDirectory with the given flags, ident and
// optional team id (version 0x20200 when team != "").
func codeDirectory(flags uint32, ident, team string) []byte {
	version := uint32(0x20100)
	hdrLen := 48 // through scatterOffset
	if team != "" {
		version = 0x20200
		hdrLen = 52
	}
	body := make([]byte, hdrLen-8)
	identOff := uint32(hdrLen)
	strs := append([]byte(ident), 0)
	teamOff := uint32(0)
	if team != "" {
		teamOff = identOff + uint32(len(strs))
		strs = append(strs, append([]byte(team), 0)...)
	}
	binary.BigEndian.PutUint32(body[0:], version)   // offset 8
	binary.BigEndian.PutUint32(body[4:], flags)     // offset 12
	binary.BigEndian.PutUint32(body[8:], 0)         // hashOffset
	binary.BigEndian.PutUint32(body[12:], identOff) // identOffset (20)
	if team != "" {
		binary.BigEndian.PutUint32(body[40:], teamOff) // teamOffset (48)
	}
	return blob(csMagicCodeDirectory, append(body, strs...))
}

// superBlob assembles slots into a SuperBlob.
func superBlob(slots map[uint32][]byte) []byte {
	count := len(slots)
	hdr := make([]byte, 12+8*count)
	binary.BigEndian.PutUint32(hdr[0:], csMagicEmbeddedSignature)
	binary.BigEndian.PutUint32(hdr[8:], uint32(count))
	var body []byte
	i := 0
	for typ, data := range slots {
		off := uint32(len(hdr) + len(body))
		binary.BigEndian.PutUint32(hdr[12+8*i:], typ)
		binary.BigEndian.PutUint32(hdr[16+8*i:], off)
		body = append(body, data...)
		i++
	}
	out := append(hdr, body...)
	binary.BigEndian.PutUint32(out[4:], uint32(len(out)))
	return out
}

func TestParseSuperBlob_SignedWithTeam(t *testing.T) {
	sb := superBlob(map[uint32][]byte{
		csSlotCodeDirectory: codeDirectory(0, "com.example.app", "ABCDE12345"),
		csSlotSignature:     blob(csMagicBlobWrapper, []byte{0x30, 0x82, 0x01, 0x00}),
	})
	info, err := parseSuperBlob(sb)
	if err != nil {
		t.Fatal(err)
	}
	if info.Ident != "com.example.app" || info.TeamID != "ABCDE12345" || !info.HasCMS || info.CMSEmpty {
		t.Errorf("got %+v", info)
	}
}

func TestParseSuperBlob_AdHocEmptyCMS(t *testing.T) {
	sb := superBlob(map[uint32][]byte{
		csSlotCodeDirectory: codeDirectory(csFlagAdhoc, "a.out", ""),
		csSlotSignature:     blob(csMagicBlobWrapper, nil),
	})
	info, err := parseSuperBlob(sb)
	if err != nil {
		t.Fatal(err)
	}
	if info.Flags&csFlagAdhoc == 0 || !info.CMSEmpty || info.TeamID != "" {
		t.Errorf("got %+v", info)
	}
}

func TestParseSuperBlob_EntitlementSlots(t *testing.T) {
	xml := []byte("<plist><dict><key>k</key><true/></dict></plist>")
	der := []byte{0x70, 0x00}
	sb := superBlob(map[uint32][]byte{
		csSlotCodeDirectory:   codeDirectory(0, "x", ""),
		csSlotEntitlements:    blob(csMagicEntitlements, xml),
		csSlotEntitlementsDER: blob(csMagicEntitlementsDER, der),
	})
	info, err := parseSuperBlob(sb)
	if err != nil {
		t.Fatal(err)
	}
	if string(info.EntitlementsXML) != string(xml) || string(info.EntitlementsDER) != string(der) {
		t.Errorf("entitlement slots not captured: %+v", info)
	}
}

// Review Focus 2: index offsets past the blob, lengths past the blob, and a
// CodeDirectory shorter than its fixed header all return an error, never panic.
func TestParseSuperBlob_Malformed(t *testing.T) {
	good := superBlob(map[uint32][]byte{csSlotCodeDirectory: codeDirectory(0, "x", "")})

	cases := map[string][]byte{
		"empty":        nil,
		"short header": good[:10],
		"wrong magic":  append([]byte{0, 0, 0, 0}, good[4:]...),
		"index past end": func() []byte {
			b := append([]byte(nil), good...)
			binary.BigEndian.PutUint32(b[16:], 0xfffffff0)
			return b
		}(),
		"count too large": func() []byte { b := append([]byte(nil), good...); binary.BigEndian.PutUint32(b[8:], 1<<20); return b }(),
		"cd truncated":    func() []byte { b := append([]byte(nil), good...); return b[:len(b)-20] }(),
		"ident past end": func() []byte {
			b := append([]byte(nil), good...)
			binary.BigEndian.PutUint32(b[20+20:], 0xffff)
			return b
		}(), // CodeDirectory starts at 20; identOffset is at CD+20
		"blob len past end": func() []byte {
			b := append([]byte(nil), good...)
			binary.BigEndian.PutUint32(b[20+4:], 0xffff)
			return b
		}(),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSuperBlob(b); err == nil {
				t.Errorf("want error for %s", name)
			}
		})
	}
}

func TestSignature_Fixtures(t *testing.T) {
	cases := []struct {
		fixture string
		want    string
		status  checksec.Status
	}{
		{"exec_arm64", "Linker-signed", checksec.StatusWarn},
		{"adhoc_arm64", "Ad-hoc", checksec.StatusWarn},
		{"hardened_arm64", "Ad-hoc", checksec.StatusWarn},
		{"unsigned_arm64", "Unsigned", checksec.StatusBad},
		{"obj.o", "Unsigned", checksec.StatusBad},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			r := Signature(loadFixture(t, tc.fixture))
			if r.Value != tc.want || r.Status != tc.status {
				t.Errorf("got %+v, want %q/%q", r, tc.want, tc.status)
			}
		})
	}
}

func TestClassifySignature(t *testing.T) {
	cases := []struct {
		info   CodeSignatureInfo
		want   string
		status checksec.Status
	}{
		{CodeSignatureInfo{}, "Unsigned", checksec.StatusBad},
		{CodeSignatureInfo{Present: true, Malformed: true}, "Malformed", checksec.StatusWarn},
		{CodeSignatureInfo{Present: true, Flags: csFlagLinkerSigned | csFlagAdhoc}, "Linker-signed", checksec.StatusWarn},
		{CodeSignatureInfo{Present: true, Flags: csFlagAdhoc, HasCMS: true, CMSEmpty: true}, "Ad-hoc", checksec.StatusWarn},
		{CodeSignatureInfo{Present: true, HasCMS: false}, "Ad-hoc", checksec.StatusWarn},
		{CodeSignatureInfo{Present: true, HasCMS: true}, "Signed", checksec.StatusGood},
		{CodeSignatureInfo{Present: true, HasCMS: true, TeamID: "ABCDE12345"}, "Signed [ABCDE12345]", checksec.StatusGood},
	}
	for _, tc := range cases {
		if v, s := classifySignature(tc.info); v != tc.want || s != tc.status {
			t.Errorf("classifySignature(%+v) = %q/%q, want %q/%q", tc.info, v, s, tc.want, tc.status)
		}
	}
}

func TestHardenedRuntime(t *testing.T) {
	if r := HardenedRuntime(loadFixture(t, "hardened_arm64")); r.Value != "Enabled" || r.Status != checksec.StatusGood {
		t.Errorf("hardened: %+v", r)
	}
	if r := HardenedRuntime(loadFixture(t, "adhoc_arm64")); r.Value != "Disabled" || r.Status != checksec.StatusBad {
		t.Errorf("adhoc: %+v", r)
	}
	if r := HardenedRuntime(loadFixture(t, "unsigned_arm64")); r.Value != "N/A" || r.Status != checksec.StatusNA {
		t.Errorf("unsigned: %+v", r)
	}
}

func TestSignature_MalformedLinkedit(t *testing.T) {
	// LC_CODE_SIGNATURE with no __LINKEDIT segment.
	f := syntheticMachO(t, 2, 0, lc(lcCodeSignature, make([]byte, 8)))
	if r := Signature(f); r.Value != "Malformed" || r.Status != checksec.StatusWarn {
		t.Errorf("got %+v", r)
	}
	if r := HardenedRuntime(f); r.Value != "N/A" {
		t.Errorf("hardened on malformed: %+v", r)
	}
	if r := Entitlements(f); !strings.HasPrefix(r.Value, "N/A") {
		t.Errorf("entitlements on malformed: %+v", r)
	}
}
